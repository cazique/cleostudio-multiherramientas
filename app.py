import io
import ipaddress
import os
import secrets
import socket
import ssl
import string
from datetime import datetime

import img2pdf
import markdown
from PIL import Image
from PyPDF2 import PdfReader, PdfWriter, PdfMerger
from flask import Flask, render_template, request, redirect, url_for, flash, send_file, jsonify
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from xhtml2pdf import pisa

from config import Config
from forms import LoginForm, RegistrationForm
from models import db, User, ToolUsage

try:
    import requests
except ImportError:
    requests = None

try:
    import whois
except ImportError:
    whois = None

app = Flask(__name__)
app.config.from_object(Config)
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024
app.config['UPLOAD_FOLDER'] = 'uploads'

os.makedirs('uploads', exist_ok=True)

ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg', 'gif', 'webp', 'md', 'txt'}


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Inicia sesión'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


TOOLS = [
    {'id': 'md-to-pdf', 'name': 'Markdown → PDF', 'icon': '📝', 'route': '/md-to-pdf'},
    {'id': 'compress-pdf', 'name': 'Comprimir PDF', 'icon': '🗜️', 'route': '/compress-pdf'},
    {'id': 'merge-pdf', 'name': 'Combinar PDFs', 'icon': '📚', 'route': '/merge-pdf'},
    {'id': 'split-pdf', 'name': 'Dividir PDF', 'icon': '✂️', 'route': '/split-pdf'},
    {'id': 'images-to-pdf', 'name': 'Imágenes → PDF', 'icon': '📄', 'route': '/images-to-pdf'},
    {'id': 'compress-image', 'name': 'Comprimir Imagen', 'icon': '🎨', 'route': '/compress-image'},
]

# ========================= CATEGORÍAS EN PORTADA =========================
# Agrupación visible en / con pestañas por categoría
TOOL_CATEGORIES = {
    'pdf': {
        'name': 'PDF e Imágenes',
        'icon': '🧩',
        'tools': TOOLS
    },
    'network': {
        'name': 'Red',
        'icon': '🌐',
        'tools': [
            {'id': 'ip-whois', 'name': 'IP WHOIS', 'icon': '📜', 'route': '/ip-whois'},
            {'id': 'blacklist-check', 'name': 'Blacklist Check', 'icon': '🛡️', 'route': '/blacklist-check'}
        ]
    },
    'security': {
        'name': 'Seguridad',
        'icon': '🧰',
        'tools': [
            {'id': 'ssl-check', 'name': 'SSL Check', 'icon': '✅', 'route': '/ssl-check'},
            {'id': 'port-scanner', 'name': 'Port Scanner', 'icon': '📡', 'route': '/port-scanner'},
            {'id': 'http-headers', 'name': 'HTTP Headers', 'icon': '📑', 'route': '/http-headers'},
            {'id': 'password-generator', 'name': 'Password Generator', 'icon': '🔑', 'route': '/password-generator'}
        ]
    }
}


def init_db():
    with app.app_context():
        db.create_all()
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            admin = User(username='admin', email='admin@multitools.com', is_admin=True)
            admin.set_password('admin123')
            db.session.add(admin)
            db.session.commit()


if not os.path.exists('multitools.db'):
    init_db()


# AUTENTICACIÓN
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember_me.data)
            flash('Bienvenido', 'success')
            return redirect(request.args.get('next') or url_for('index'))
        flash('Usuario o contraseña incorrectos', 'danger')
    return render_template('login.html', form=form)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Registro exitoso', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/')
@login_required
def index():
    return render_template('index.html', tools=TOOLS, categories=TOOL_CATEGORIES)


# RUTAS HERRAMIENTAS
@app.route('/md-to-pdf')
@login_required
def md_to_pdf_page():
    return render_template('md_to_pdf.html')


@app.route('/compress-pdf')
@login_required
def compress_pdf_page():
    return render_template('compress_pdf.html')


@app.route('/merge-pdf')
@login_required
def merge_pdf_page():
    return render_template('merge_pdf.html')


@app.route('/images-to-pdf')
@login_required
def images_to_pdf_page():
    return render_template('images_to_pdf.html')


@app.route('/compress-image')
@login_required
def compress_image_page():
    return render_template('compress_image.html')


# ADMIN
@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        flash('No autorizado', 'danger')
        return redirect(url_for('index'))
    users = User.query.all()
    return render_template('admin.html', users=users, total_users=User.query.count(),
                           total_usage=ToolUsage.query.count(),
                           recent_usage=ToolUsage.query.order_by(ToolUsage.timestamp.desc()).limit(10).all())


@app.route('/admin/delete-user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin or user_id == current_user.id:
        return jsonify({'success': False}), 403
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    return jsonify({'success': True})


@app.route('/admin/toggle-admin/<int:user_id>', methods=['POST'])
@login_required
def toggle_admin(user_id):
    if not current_user.is_admin:
        return jsonify({'success': False}), 403
    user = User.query.get_or_404(user_id)
    user.is_admin = not user.is_admin
    db.session.commit()
    return jsonify({'success': True})


# API MARKDOWN
@app.route('/api/preview-markdown', methods=['POST'])
@login_required
def preview_markdown():
    try:
        data = request.get_json()
        md_content = data.get('markdown', '')
        html = markdown.markdown(md_content, extensions=['tables', 'fenced_code', 'nl2br'])
        return jsonify({'success': True, 'html': html})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400


@app.route('/api/generate-pdf', methods=['POST'])
@login_required
def generate_pdf():
    try:
        data = request.get_json()
        md_content = data.get('markdown', '')
        filename = data.get('filename', 'documento')

        # Convertir Markdown a HTML con estilos
        html_content = markdown.markdown(
            md_content,
            extensions=['tables', 'fenced_code', 'nl2br', 'sane_lists']
        )

        # CSS con los mismos estilos de la vista previa
        css = """
        <style>
            @page { size: A4; margin: 2cm; }
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; font-size: 12pt; }
            h1 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; margin-top: 20px; font-size: 24pt; }
            h2 { color: #2c3e50; border-bottom: 2px solid #95a5a6; padding-bottom: 8px; margin-top: 18px; font-size: 20pt; }
            h3 { color: #2c3e50; margin-top: 16px; font-size: 16pt; }
            h4 { color: #2c3e50; margin-top: 14px; font-size: 14pt; }
            code { background-color: #f4f4f4; padding: 2px 6px; border-radius: 3px; color: #c7254e; font-family: monospace; }
            pre { background-color: #282c34; color: #abb2bf; padding: 15px; border-radius: 5px; overflow-x: auto; }
            pre code { background-color: transparent; color: #abb2bf; padding: 0; }
            blockquote { border-left: 4px solid #3498db; padding-left: 15px; margin-left: 0; color: #555; font-style: italic; background-color: #f9f9f9; padding: 10px 15px; }
            table { border-collapse: collapse; width: 100%; margin: 15px 0; }
            th, td { border: 1px solid #ddd; padding: 10px; text-align: left; }
            th { background-color: #3498db; color: white; font-weight: 600; }
            tr:nth-child(even) { background-color: #f9f9f9; }
            ul, ol { margin: 10px 0; padding-left: 30px; }
            li { margin: 5px 0; }
            p { margin: 10px 0; }
            a { color: #3498db; text-decoration: none; }
            strong { font-weight: 600; }
            em { font-style: italic; }
        </style>
        """

        # HTML completo
        html_full = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            {css}
        </head>
        <body>
            {html_content}
        </body>
        </html>
        """

        # Generar PDF con xhtml2pdf
        buffer = io.BytesIO()
        pisa_status = pisa.CreatePDF(html_full, dest=buffer)

        if pisa_status.err:
            return jsonify({'success': False, 'error': 'Error al generar PDF'}), 500

        buffer.seek(0)
        safe_filename = "".join(c for c in filename if c.isalnum() or c in (' ', '-', '_')).strip() or 'documento'

        return send_file(buffer, mimetype='application/pdf', as_attachment=True,
                         download_name=f'{safe_filename}.pdf')
    except Exception as e:
        return jsonify({'success': False, 'error': f'Error: {str(e)}'}), 500


# API COMPRIMIR PDF
@app.route('/api/compress-pdf', methods=['POST'])
@login_required
def compress_pdf():
    try:
        if 'file' not in request.files:
            return jsonify({'success': False, 'error': 'No hay archivo'}), 400
        file = request.files['file']
        reader = PdfReader(io.BytesIO(file.read()))
        writer = PdfWriter()
        for page in reader.pages:
            page.compress_content_streams()
            writer.add_page(page)
        buffer = io.BytesIO()
        writer.write(buffer)
        buffer.seek(0)
        return send_file(buffer, mimetype='application/pdf', as_attachment=True,
                         download_name=f'comprimido_{file.filename}')
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# API COMBINAR PDFs
@app.route('/api/merge-pdfs', methods=['POST'])
@login_required
def merge_pdfs():
    try:
        files = request.files.getlist('files[]')
        if len(files) < 2:
            return jsonify({'success': False, 'error': 'Necesitas al menos 2 PDFs'}), 400
        merger = PdfMerger()
        for file in files:
            merger.append(io.BytesIO(file.read()))
        buffer = io.BytesIO()
        merger.write(buffer)
        buffer.seek(0)
        return send_file(buffer, mimetype='application/pdf', as_attachment=True,
                         download_name='combinado.pdf')
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# API COMPRIMIR IMAGEN
@app.route('/api/compress-image', methods=['POST'])
@login_required
def compress_image():
    try:
        if 'file' not in request.files:
            return jsonify({'success': False, 'error': 'No hay archivo'}), 400
        file = request.files['file']
        level = request.form.get('level', 'normal')
        img = Image.open(file)
        if img.mode == 'RGBA':
            bg = Image.new('RGB', img.size, (255, 255, 255))
            bg.paste(img, mask=img.split()[3])
            img = bg
        quality = {'light': 90, 'normal': 85, 'aggressive': 70}.get(level, 85)
        buffer = io.BytesIO()
        img.save(buffer, format='JPEG', quality=quality, optimize=True)
        buffer.seek(0)
        return send_file(buffer, mimetype='image/jpeg', as_attachment=True,
                         download_name=f'optimizada_{file.filename}')
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# API IMAGENES A PDF
@app.route('/api/images-to-pdf', methods=['POST'])
@login_required
def images_to_pdf_api():
    try:
        files = request.files.getlist('files[]')
        if not files:
            return jsonify({'success': False, 'error': 'No hay imágenes'}), 400
        images = []
        for file in files:
            img = Image.open(file)
            if img.mode == 'RGBA':
                bg = Image.new('RGB', img.size, (255, 255, 255))
                bg.paste(img, mask=img.split()[3])
                img = bg
            img_bytes = io.BytesIO()
            img.save(img_bytes, format='JPEG')
            images.append(img_bytes.getvalue())
        pdf_bytes = img2pdf.convert(images)
        buffer = io.BytesIO(pdf_bytes)
        buffer.seek(0)
        return send_file(buffer, mimetype='application/pdf', as_attachment=True,
                         download_name='imagenes.pdf')
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# ================================================== #                  IP TOOLS - 2/4 # ==================================================

@app.route('/ip-whois')
def ip_whois_page():
    """Renderiza la página 'IP WHOIS'."""
    theme = current_user.theme if (hasattr(globals().get('current_user', ''),
                                           'is_authenticated') and current_user.is_authenticated) else 'light'
    return render_template('ip_whois.html', theme=theme)


@app.route('/api/ip-whois', methods=['POST'])
def ip_whois_api():
    """API interna para realizar una consulta WHOIS a una IP."""
    ip_str = request.form.get('ip', '').strip()
    if not ip_str:
        return jsonify({'success': False, 'error': 'Se requiere una dirección IP.'}), 400

    if not whois:
        return jsonify({'success': False, 'error': "La librería 'python-whois' no está instalada."}), 500

    try:
        ipaddress.ip_address(ip_str)
        w = whois.whois(ip_str)
        whois_data = {k: v for k, v in getattr(w, '__dict__', {}).items() if v and not k.startswith('_')}
        if not whois_data:
            return jsonify({'success': False,
                            'error': 'No se encontró información WHOIS para esta IP. Puede ser una IP privada o reservada.'}), 404
        return jsonify({'success': True, 'data': whois_data})
    except ValueError:
        return jsonify({'success': False, 'error': 'La dirección IP no es válida.'}), 400
    except Exception as e:
        return jsonify({'success': False, 'error': f'No se pudo completar la consulta WHOIS: {str(e)}'}), 500


# ================================================== #                  IP TOOLS - 3/4 # ==================================================

DNSBL_SERVERS = [
    "bl.spamcop.net",
    "cbl.abuseat.org",
    "zen.spamhaus.org",
    "b.barracudacentral.org",
    "dnsbl.sorbs.net",
    "spam.dnsbl.sorbs.net",
    "all.s5h.net",
    "psbl.surriel.com",
    "dnsbl.spfbl.net",
    "ubl.unsubscore.com"
]


@app.route('/blacklist-check')
def blacklist_check_page():
    """Renderiza la página 'Blacklist Check'."""
    theme = current_user.theme if (hasattr(globals().get('current_user', ''),
                                           'is_authenticated') and current_user.is_authenticated) else 'light'
    return render_template('blacklist_check.html', theme=theme)


@app.route('/api/blacklist-check', methods=['POST'])
def blacklist_check_api():
    """API para verificar una IP contra múltiples servidores DNSBL."""
    ip_str = request.form.get('ip', '').strip()
    if not ip_str:
        return jsonify({'success': False, 'error': 'Se requiere una dirección IP.'}), 400

    try:
        ip_obj = ipaddress.ip_address(ip_str)
        if ip_obj.is_private or ip_obj.is_loopback:
            return jsonify({'success': False, 'error': 'No se pueden verificar IPs privadas o de loopback.'}), 400
    except ValueError:
        return jsonify({'success': False, 'error': 'La dirección IP no es válida.'}), 400

    reversed_ip = '.'.join(reversed(ip_str.split('.')))
    results = []
    listed_count = 0

    for server in DNSBL_SERVERS:
        query = f"{reversed_ip}.{server}"
        try:
            socket.gethostbyname(query)
            results.append({'server': server, 'listed': True})
            listed_count += 1
        except socket.gaierror:
            results.append({'server': server, 'listed': False})
        except Exception:
            results.append({'server': server, 'listed': 'error'})

    return jsonify({
        'success': True,
        'data': {
            'ip': ip_str,
            'total_checked': len(DNSBL_SERVERS),
            'listed_count': listed_count,
            'results': results
        }
    })


# ================================================== #               SECURITY TOOLS - 1/4 # ==================================================

@app.route('/ssl-check')
def ssl_check_page():
    """Renderiza la página 'SSL Certificate Check'."""
    theme = current_user.theme if (hasattr(globals().get('current_user', ''),
                                           'is_authenticated') and current_user.is_authenticated) else 'light'
    return render_template('ssl_check.html', theme=theme)


@app.route('/api/ssl-check', methods=['POST'])
def ssl_check_api():
    """API para verificar el certificado SSL de un host."""
    hostname = request.form.get('hostname', '').strip()
    if not hostname:
        return jsonify({'success': False, 'error': 'Se requiere un nombre de host.'}), 400

    port = 443
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
        issuer = dict(x[0] for x in cert.get('issuer', []))
        subject = dict(x[0] for x in cert.get('subject', []))
        not_after_str = cert.get('notAfter')
        not_before_str = cert.get('notBefore')
        alt_names = [name[1] for name in cert.get('subjectAltName', []) if name[0] == 'DNS']

        # Parse date strings if present
        valid_from = datetime.strptime(not_before_str, '%b %d %H:%M:%S %Y %Z').isoformat() if not_before_str else None
        valid_until = datetime.strptime(not_after_str, '%b %d %H:%M:%S %Y %Z').isoformat() if not_after_str else None

        cert_info = {
            'subject': subject,
            'issuer': issuer,
            'version': cert.get('version'),
            'serial_number': cert.get('serialNumber'),
            'valid_from': valid_from,
            'valid_until': valid_until,
            'subject_alt_names': alt_names
        }
        return jsonify({'success': True, 'data': cert_info})
    except socket.timeout:
        return jsonify({'success': False,
                        'error': 'La conexión expiró. El host podría estar caído o el puerto 443 bloqueado.'}), 408
    except socket.gaierror:
        return jsonify({'success': False, 'error': f"No se pudo resolver el nombre de host: {hostname}"}), 404
    except ssl.SSLCertVerificationError as e:
        return jsonify(
            {'success': False, 'error': f'Error de verificación de certificado: {getattr(e, "reason", str(e))}'}), 400
    except ssl.SSLError as e:
        return jsonify(
            {'success': False, 'error': f'Error de SSL: {str(e)}. El host podría no tener SSL en el puerto 443.'}), 400
    except Exception as e:
        return jsonify({'success': False, 'error': f'Error inesperado: {str(e)}'}), 500


# ================================================== #               SECURITY TOOLS - 2/4 # ==================================================

COMMON_PORTS = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 80: 'HTTP',
    110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 465: 'SMTPS', 587: 'SMTP (Sub.)',
    993: 'IMAPS', 995: 'POP3S', 2082: 'cPanel', 2083: 'cPanel (SSL)',
    2086: 'WHM', 2087: 'WHM (SSL)', 3306: 'MySQL', 5432: 'PostgreSQL', 8080: 'HTTP Alt.'
}


@app.route('/port-scanner')
def port_scanner_page():
    """Renderiza la página 'Port Scanner'."""
    theme = current_user.theme if (hasattr(globals().get('current_user', ''),
                                           'is_authenticated') and current_user.is_authenticated) else 'light'
    return render_template('port_scanner.html', theme=theme)


@app.route('/api/port-scan', methods=['POST'])
def port_scan_api():
    """API para escanear puertos comunes de un host."""
    hostname = request.form.get('hostname', '').strip()
    if not hostname:
        return jsonify({'success': False, 'error': 'Se requiere un nombre de host.'}), 400

    try:
        ip = socket.gethostbyname(hostname)
    except socket.gaierror:
        return jsonify({'success': False, 'error': f'No se pudo resolver el nombre de host: {hostname}'}), 404

    results = []
    open_ports = 0
    for port, service in COMMON_PORTS.items():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((ip, port))
        status = 'Abierto' if result == 0 else 'Cerrado'
        if status == 'Abierto':
            open_ports += 1
        results.append({'port': port, 'service': service, 'status': status})
        sock.close()

    return jsonify(
        {'success': True, 'data': {'hostname': hostname, 'ip': ip, 'open_ports': open_ports, 'results': results}})


# ================================================== #               SECURITY TOOLS - 3/4 # ==================================================

@app.route('/http-headers')
def http_headers_page():
    """Renderiza la página 'HTTP Headers'."""
    theme = current_user.theme if (hasattr(globals().get('current_user', ''),
                                           'is_authenticated') and current_user.is_authenticated) else 'light'
    return render_template('http_headers.html', theme=theme)


@app.route('/api/http-headers', methods=['POST'])
def http_headers_api():
    """API para obtener las cabeceras HTTP de una URL."""
    url = request.form.get('url', '').strip()
    if not url:
        return jsonify({'success': False, 'error': 'Se requiere una URL.'}), 400

    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    if not requests:
        return jsonify({'success': False, 'error': "La librería 'requests' no está instalada."}), 500

    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }
    try:
        response = requests.get(url, headers=headers, timeout=10, allow_redirects=True)
        header_list = [{'name': name, 'value': value} for name, value in response.headers.items()]
        redirect_history = []
        if response.history:
            for resp in response.history:
                redirect_history.append({'status_code': resp.status_code, 'url': resp.url})
        redirect_history.append({'status_code': response.status_code, 'url': response.url})
        return jsonify({'success': True,
                        'data': {'final_url': response.url, 'status_code': response.status_code, 'headers': header_list,
                                 'redirect_history': redirect_history}})
    except Exception as e:
        return jsonify({'success': False, 'error': f'No se pudo conectar con la URL: {str(e)}'}), 400


# ================================================== #               SECURITY TOOLS - 4/4 # ==================================================


@app.route('/password-generator', methods=['GET'])
def password_gen_page():
    """Renderiza la página 'Password Generator' y genera una contraseña si hay parámetros."""
    # Longitud robusta (acepta vacío o no numérico)
    length_raw = request.args.get('length', 16)
    try:
        length = int(length_raw if length_raw not in (None, '', []) else 16)
    except (TypeError, ValueError):
        length = 16
    # límites razonables
    if length < 8: length = 8
    if length > 64: length = 64

    use_upper = request.args.get('uppercase') == 'on'
    use_lower = request.args.get('lowercase', 'on') == 'on'  # minúsculas por defecto
    use_numbers = request.args.get('numbers') == 'on'
    use_symbols = request.args.get('symbols') == 'on'

    password = ''
    error = None
    alphabet = ''
    if use_upper:   alphabet += string.ascii_uppercase
    if use_lower:   alphabet += string.ascii_lowercase
    if use_numbers: alphabet += string.digits
    if use_symbols: alphabet += string.punctuation

    if not alphabet:
        error = "Debes seleccionar al menos un tipo de caracter."
    else:
        password = ''.join(secrets.choice(alphabet) for _ in range(length))

    theme = current_user.theme if (hasattr(globals().get('current_user', ''),
                                           'is_authenticated') and current_user.is_authenticated) else 'light'
    return render_template('password_gen.html', theme=theme, password=password, error=error,
                           p_length=length, p_upper=use_upper, p_lower=use_lower,
                           p_numbers=use_numbers, p_symbols=use_symbols)


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)

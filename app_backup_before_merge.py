import io
import os

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
    return render_template('index.html', tools=TOOLS)


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


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)

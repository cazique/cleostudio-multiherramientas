import os
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from config import Config
from models import db, User, ToolUsage

# Inicialización de Flask
app = Flask(__name__)
app.config.from_object(Config)

# Inicialización de extensiones
db.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Por favor inicia sesión para acceder'

@login_manager.user_loader
def load_user(user_id):
    """
    Función de carga de usuario para Flask-Login.

    Args:
        user_id (str): El ID del usuario a cargar.

    Returns:
        User: La instancia del usuario si se encuentra, None en caso contrario.
    """
    return User.query.get(int(user_id))

# Inicializar base de datos
def init_db():
    """
    Inicializa la base de datos. Crea todas las tablas.
    """
    with app.app_context():
        db.create_all()

# Rutas básicas
@app.route('/')
def index():
    """
    Muestra la página principal con la lista de herramientas.

    Returns:
        Rendered template: La plantilla 'index.html'.
    """
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    Maneja el inicio de sesión del usuario.

    Si el método es POST, valida las credenciales y, si son correctas,
    inicia la sesión del usuario.

    Returns:
        Rendered template or redirect: La plantilla 'login.html' o una redirección
        a la página principal si el inicio de sesión es exitoso.
    """
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = request.form.get('remember', False)

        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            login_user(user, remember=remember)
            flash('Inicio de sesión exitoso', 'success')
            next_page = request.args.get('next')
            return redirect(next_page or url_for('index'))

        flash('Usuario o contraseña incorrectos', 'danger')

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    """
    Cierra la sesión del usuario actual.

    Returns:
        Redirect: Redirecciona a la página de inicio de sesión.
    """
    logout_user()
    flash('Sesión cerrada', 'info')
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    """
    Maneja el registro de nuevos usuarios.

    Si el método es POST, valida los datos y crea un nuevo usuario
    si el nombre de usuario y el correo electrónico no están ya en uso.

    Returns:
        Rendered template or redirect: La plantilla 'register.html' o una
        redirección a la página de inicio de sesión si el registro es exitoso.
    """
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        # Validación básica
        if User.query.filter_by(username=username).first():
            flash('El usuario ya existe', 'danger')
            return render_template('register.html')

        if User.query.filter_by(email=email).first():
            flash('El email ya está registrado', 'danger')
            return render_template('register.html')

        # Crear usuario
        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        flash('Registro exitoso. Inicia sesión', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

# Páginas de herramientas
@app.route('/md-to-pdf')
def md_to_pdf_page():
    """Muestra la página de la herramienta para convertir Markdown a PDF."""
    return render_template('md_to_pdf.html')

@app.route('/compress-pdf')
def compress_pdf_page():
    """Muestra la página de la herramienta para comprimir PDF."""
    # CAMBIO: compress_pdf.html -> compress-pdf.html
    return render_template('compress-pdf.html')

@app.route('/merge-pdf')
def merge_pdf_page():
    """Muestra la página de la herramienta para combinar PDFs."""
    return render_template('merge_pdf.html')

@app.route('/split-pdf')
def split_pdf_page():
    """Muestra la página de la herramienta para dividir PDF."""
    return render_template('split_pdf.html')

@app.route('/images-to-pdf')
def images_to_pdf_page():
    """Muestra la página de la herramienta para convertir imágenes a PDF."""
    return render_template('images_to_pdf.html')

@app.route('/compress-image')
def compress_image_page():
    """Muestra la página de la herramienta para comprimir imágenes."""
    # CAMBIO: compress_image.html -> compress-image.html
    return render_template('compress-image.html')

@app.route('/ip-whois')
def ip_whois_page():
    """Muestra la página de la herramienta de IP WHOIS."""
    # CAMBIO: ip_whois.html -> ip-whois.html
    return render_template('ip-whois.html')

@app.route('/blacklist-check')
def blacklist_check_page():
    """Muestra la página de la herramienta de verificación de listas negras."""
    # CAMBIO: blacklist_check.html -> blacklist-check.html
    return render_template('blacklist-check.html')

@app.route('/ssl-check')
def ssl_check_page():
    """Muestra la página de la herramienta de verificación de SSL."""
    # CAMBIO: ssl_check.html -> ssl-check.html
    return render_template('ssl-check.html')

@app.route('/port-scanner')
def port_scanner_page():
    """Muestra la página de la herramienta de escáner de puertos."""
    # CAMBIO: port_scanner.html -> port-scanner.html
    return render_template('port-scanner.html')

@app.route('/http-headers')
def http_headers_page():
    """Muestra la página de la herramienta para ver cabeceras HTTP."""
    # CAMBIO: http_headers.html -> http-headers.html
    return render_template('http-headers.html')

@app.route('/password-generator')
def password_gen_page():
    """Muestra la página de la herramienta de generación de contraseñas."""
    # CAMBIO: password_generator.html -> password-generator.html
    return render_template('password-generator.html')

@app.route('/mx-lookup')
def mx_lookup_page():
    """Muestra la página de la herramienta de búsqueda de registros MX."""
    # CAMBIO: mx_lookup.html -> mx-lookup.html
    return render_template('mx-lookup.html')

@app.route('/dns-lookup')
def dns_lookup_page():
    """Muestra la página de la herramienta de búsqueda de DNS."""
    # CAMBIO: dns_lookup.html -> dns-lookup.html
    return render_template('dns-lookup.html')

@app.route('/reverse-dns')
def reverse_dns_page():
    """Muestra la página de la herramienta de búsqueda de DNS inversa."""
    # CAMBIO: reverse_dns.html -> reverse-dns.html
    return render_template('reverse-dns.html')

@app.route('/whois-lookup')
def whois_lookup_page():
    """Muestra la página de la herramienta de búsqueda WHOIS."""
    # CAMBIO: whois_lookup.html -> whois-lookup.html
    return render_template('whois-lookup.html')

@app.route('/spf-check')
def spf_check_page():
    """Muestra la página de la herramienta de verificación de SPF."""
    # CAMBIO: spf_check.html -> spf-check.html
    return render_template('spf-check.html')

@app.route('/dkim-check')
def dkim_check_page():
    """Muestra la página de la herramienta de verificación de DKIM."""
    # CAMBIO: dkim_check.html -> dkim-check.html
    return render_template('dkim-check.html')

@app.route('/dmarc-check')
def dmarc_check_page():
    """Muestra la página de la herramienta de verificación de DMARC."""
    # CAMBIO: dmarc_check.html -> dmarc-check.html
    return render_template('dmarc-check.html')

@app.route('/email-header')
def email_header_page():
    """Muestra la página de la herramienta para analizar cabeceras de correo electrónico."""
    # CAMBIO: email_header.html -> email-header.html
    return render_template('email-header.html')

# Manejo de errores
@app.errorhandler(404)
def not_found(e):
    """
    Manejador de errores para páginas no encontradas (404).

    Args:
        e: El objeto de la excepción.

    Returns:
        Tuple: La plantilla '404.html' y el código de estado 404.
    """
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(e):
    """
    Manejador de errores para errores internos del servidor (500).

    Args:
        e: El objeto de la excepción.

    Returns:
        Tuple: La plantilla '500.html' y el código de estado 500.
    """
    db.session.rollback()
    return render_template('500.html'), 500


# RUTA DE DEBUG TEMPORAL
@app.route('/debug')
def debug_info():
    """
    Muestra una página de depuración con información del sistema.

    Returns:
        str: HTML con información de depuración.
    """
    import sys
    info = {
        'python_version': sys.version,
        'flask_working': True,
        'logged_in': current_user.is_authenticated,
        'user': current_user.username if current_user.is_authenticated else 'Anonymous'
    }
    return f"""
    <h1>Debug Info</h1>
    <pre>{info}</pre>
    <a href="/">Volver al inicio</a>
    """

if __name__ == '__main__':
    print("=" * 60)
    print("🚀 Iniciando Multi-Herramientas Flask")
    print("=" * 60)

    # Inicializar base de datos
    init_db()

    print(f"📍 URL: http://127.0.0.1:5000")
    print("=" * 60)

    app.run(debug=True, host='0.0.0.0', port=5000)

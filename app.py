import os
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

# Inicialización de Flask
app = Flask(__name__)
app.config['SECRET_KEY'] = 'dev-secret-key-change-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///multitools.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Inicialización de extensiones
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Por favor inicia sesión para acceder'

# Modelos
class User(db.Model):
    """
    Modelo de la base de datos para los usuarios.

    Atributos:
        id (int): Clave primaria.
        username (str): Nombre de usuario único.
        email (str): Correo electrónico único.
        password_hash (str): Hash de la contraseña del usuario.
        is_admin (bool): Verdadero si el usuario es administrador.
        created_at (datetime): Fecha y hora de creación del usuario.
    """
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255))
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    @property
    def is_active(self):
        """Propiedad requerida por Flask-Login. Siempre devuelve True."""
        return True

    @property
    def is_authenticated(self):
        """Propiedad requerida por Flask-Login. Siempre devuelve True si el usuario está autenticado."""
        return True

    @property
    def is_anonymous(self):
        """Propiedad requerida por Flask-Login. Siempre devuelve False."""
        return False

    def get_id(self):
        """
        Método requerido por Flask-Login. Devuelve el ID del usuario como una cadena.

        Returns:
            str: El ID del usuario.
        """
        return str(self.id)

    def set_password(self, password):
        """
        Genera un hash de la contraseña y lo almacena.

        Args:
            password (str): La contraseña en texto plano.
        """
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """
        Verifica si la contraseña proporcionada coincide con el hash almacenado.

        Args:
            password (str): La contraseña a verificar.

        Returns:
            bool: True si la contraseña es correcta, False en caso contrario.
        """
        return check_password_hash(self.password_hash, password)

class ToolUsage(db.Model):
    """
    Modelo de la base de datos para registrar el uso de herramientas.

    Atributos:
        id (int): Clave primaria.
        user_id (int): ID del usuario que utilizó la herramienta (clave foránea).
        tool_name (str): Nombre de la herramienta utilizada.
        timestamp (datetime): Fecha y hora del uso.
    """
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    tool_name = db.Column(db.String(100))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

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
    Inicializa la base de datos. Crea todas las tablas y un usuario administrador
    si no existe.
    """
    with app.app_context():
        db.create_all()

        # Crear usuario admin si no existe
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            admin = User(
                username='admin',
                email='admin@multitools.com',
                is_admin=True
            )
            admin.set_password('admin123')
            db.session.add(admin)
            db.session.commit()
            print("✓ Usuario admin creado")

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
    return render_template('compress_pdf.html')

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
    return render_template('compress_image.html')

@app.route('/ip-whois')
def ip_whois_page():
    """Muestra la página de la herramienta de IP WHOIS."""
    return render_template('ip_whois.html')

@app.route('/blacklist-check')
def blacklist_check_page():
    """Muestra la página de la herramienta de verificación de listas negras."""
    return render_template('blacklist_check.html')

@app.route('/ssl-check')
def ssl_check_page():
    """Muestra la página de la herramienta de verificación de SSL."""
    return render_template('ssl_check.html')

@app.route('/port-scanner')
def port_scanner_page():
    """Muestra la página de la herramienta de escáner de puertos."""
    return render_template('port_scanner.html')

@app.route('/http-headers')
def http_headers_page():
    """Muestra la página de la herramienta para ver cabeceras HTTP."""
    return render_template('http_headers.html')

@app.route('/password-generator')
def password_gen_page():
    """Muestra la página de la herramienta de generación de contraseñas."""
    return render_template('password_generator.html')

@app.route('/mx-lookup')
def mx_lookup_page():
    """Muestra la página de la herramienta de búsqueda de registros MX."""
    return render_template('mx_lookup.html')

@app.route('/dns-lookup')
def dns_lookup_page():
    """Muestra la página de la herramienta de búsqueda de DNS."""
    return render_template('dns_lookup.html')

@app.route('/reverse-dns')
def reverse_dns_page():
    """Muestra la página de la herramienta de búsqueda de DNS inversa."""
    return render_template('reverse_dns.html')

@app.route('/whois-lookup')
def whois_lookup_page():
    """Muestra la página de la herramienta de búsqueda WHOIS."""
    return render_template('whois_lookup.html')

@app.route('/spf-check')
def spf_check_page():
    """Muestra la página de la herramienta de verificación de SPF."""
    return render_template('spf_check.html')

@app.route('/dkim-check')
def dkim_check_page():
    """Muestra la página de la herramienta de verificación de DKIM."""
    return render_template('dkim_check.html')

@app.route('/dmarc-check')
def dmarc_check_page():
    """Muestra la página de la herramienta de verificación de DMARC."""
    return render_template('dmarc_check.html')

@app.route('/email-header')
def email_header_page():
    """Muestra la página de la herramienta para analizar cabeceras de correo electrónico."""
    return render_template('email_header.html')

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
    print(f"👤 Usuario: admin")
    print(f"🔑 Contraseña: admin123")
    print("=" * 60)

    app.run(debug=True, host='0.0.0.0', port=5000)

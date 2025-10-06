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
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255))
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    @property
    def is_active(self):
        return True

    @property
    def is_authenticated(self):
        return True

    @property
    def is_anonymous(self):
        return False

    def get_id(self):
        return str(self.id)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class ToolUsage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    tool_name = db.Column(db.String(100))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Inicializar base de datos
def init_db():
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
    if current_user.is_authenticated:
        return render_template('index.html')
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
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
    logout_user()
    flash('Sesión cerrada', 'info')
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
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

@app.route('/split-pdf')
@login_required
def split_pdf_page():
    return render_template('split_pdf.html')

@app.route('/images-to-pdf')
@login_required
def images_to_pdf_page():
    return render_template('images_to_pdf.html')

@app.route('/compress-image')
@login_required
def compress_image_page():
    return render_template('compress_image.html')

@app.route('/ip-whois')
@login_required
def ip_whois_page():
    return render_template('ip_whois.html')

@app.route('/blacklist-check')
@login_required
def blacklist_check_page():
    return render_template('blacklist_check.html')

@app.route('/ssl-check')
@login_required
def ssl_check_page():
    return render_template('ssl_check.html')

@app.route('/port-scanner')
@login_required
def port_scanner_page():
    return render_template('port_scanner.html')

@app.route('/http-headers')
@login_required
def http_headers_page():
    return render_template('http_headers.html')

@app.route('/password-generator')
@login_required
def password_gen_page():
    return render_template('password_generator.html')

@app.route('/mx-lookup')
@login_required
def mx_lookup_page():
    return render_template('mx_lookup.html')

@app.route('/dns-lookup')
@login_required
def dns_lookup_page():
    return render_template('dns_lookup.html')

@app.route('/reverse-dns')
@login_required
def reverse_dns_page():
    return render_template('reverse_dns.html')

@app.route('/whois-lookup')
@login_required
def whois_lookup_page():
    return render_template('whois_lookup.html')

@app.route('/spf-check')
@login_required
def spf_check_page():
    return render_template('spf_check.html')

@app.route('/dkim-check')
@login_required
def dkim_check_page():
    return render_template('dkim_check.html')

@app.route('/dmarc-check')
@login_required
def dmarc_check_page():
    return render_template('dmarc_check.html')

@app.route('/email-header')
@login_required
def email_header_page():
    return render_template('email_header.html')

# Manejo de errores
@app.errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(e):
    db.session.rollback()
    return render_template('500.html'), 500


# RUTA DE DEBUG TEMPORAL
@app.route('/debug')
def debug_info():
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

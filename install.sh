#!/bin/bash

# ============================================
# INSTALADOR COMPLETO - Flask Multi-Herramientas
# Crea TODOS los archivos necesarios
# ============================================

# Colores
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

print_success() { echo -e "${GREEN}✅ $1${NC}"; }
print_info() { echo -e "${BLUE}ℹ️  $1${NC}"; }
print_warning() { echo -e "${YELLOW}⚠️  $1${NC}"; }
print_error() { echo -e "${RED}❌ $1${NC}"; }

echo "🚀 INSTALADOR COMPLETO - Flask Multi-Herramientas"
echo "=================================================="
echo ""

# Crear estructura de directorios
print_info "Creando estructura de directorios..."
mkdir -p templates static/css static/js static/img
print_success "Directorios creados"

# ========== .gitignore ==========
print_info "Creando .gitignore..."
cat > .gitignore << 'EOF'
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
venv/
env/
ENV/
.venv
.idea/
*.iml
instance/
*.db
*.sqlite
*.sqlite3
.env
.flaskenv
.DS_Store
*.log
uploads/
static/uploads/
EOF
print_success ".gitignore creado"

# ========== requirements.txt ==========
print_info "Creando requirements.txt..."
cat > requirements.txt << 'EOF'
Flask==3.0.0
Flask-SQLAlchemy==3.1.1
Flask-Login==0.6.3
Flask-WTF==1.2.1
WTForms==3.1.1
markdown==3.5.1
weasyprint==60.1
Pygments==2.17.2
werkzeug==3.0.1
email-validator==2.1.0
EOF
print_success "requirements.txt creado"

# ========== config.py ==========
print_info "Creando config.py..."
cat > config.py << 'EOF'
import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///multitools.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max
EOF
print_success "config.py creado"

# ========== models.py ==========
print_info "Creando models.py..."
cat > models.py << 'EOF'
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255))
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def __repr__(self):
        return f'<User {self.username}>'

class ToolUsage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    tool_name = db.Column(db.String(100))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    user = db.relationship('User', backref='tool_usages')
EOF
print_success "models.py creado"

# ========== forms.py ==========
print_info "Creando forms.py..."
cat > forms.py << 'EOF'
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError
from models import User

class LoginForm(FlaskForm):
    username = StringField('Usuario', validators=[DataRequired()])
    password = PasswordField('Contraseña', validators=[DataRequired()])
    remember_me = BooleanField('Recordarme')
    submit = SubmitField('Iniciar Sesión')

class RegistrationForm(FlaskForm):
    username = StringField('Usuario', validators=[
        DataRequired(), 
        Length(min=3, max=80)
    ])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Contraseña', validators=[
        DataRequired(),
        Length(min=6, message='La contraseña debe tener al menos 6 caracteres')
    ])
    password2 = PasswordField('Repetir Contraseña', validators=[
        DataRequired(),
        EqualTo('password', message='Las contraseñas deben coincidir')
    ])
    submit = SubmitField('Registrarse')
    
    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Este nombre de usuario ya está en uso')
    
    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Este email ya está registrado')
EOF
print_success "forms.py creado"

# ========== app.py ==========
print_info "Creando app.py..."
cat > app.py << 'EOF'
from flask import Flask, render_template, request, redirect, url_for, flash, send_file, jsonify
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
import markdown
from weasyprint import HTML, CSS
import io

from config import Config
from models import db, User, ToolUsage
from forms import LoginForm, RegistrationForm

app = Flask(__name__)
app.config.from_object(Config)

# Inicializar extensiones
db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Por favor inicia sesión para acceder a esta página'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Herramientas disponibles
TOOLS = [
    {
        'id': 'md-to-pdf',
        'name': 'Markdown a PDF',
        'description': 'Convierte Markdown a PDF con estilos profesionales',
        'icon': '📄',
        'route': '/md-to-pdf'
    },
]

# ============= RUTAS DE AUTENTICACIÓN =============

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember_me.data)
            flash('¡Bienvenido de nuevo!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('index'))
        else:
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
        flash('¡Registro exitoso! Ya puedes iniciar sesión', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Has cerrado sesión correctamente', 'info')
    return redirect(url_for('login'))

# ============= RUTAS PRINCIPALES =============

@app.route('/')
@login_required
def index():
    return render_template('index.html', tools=TOOLS)

@app.route('/md-to-pdf')
@login_required
def md_to_pdf_page():
    usage = ToolUsage(user_id=current_user.id, tool_name='Markdown to PDF')
    db.session.add(usage)
    db.session.commit()
    return render_template('md_to_pdf.html')

# ============= PANEL DE ADMINISTRACIÓN =============

@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        flash('No tienes permisos de administrador', 'danger')
        return redirect(url_for('index'))
    
    users = User.query.all()
    total_users = User.query.count()
    total_usage = ToolUsage.query.count()
    recent_usage = ToolUsage.query.order_by(ToolUsage.timestamp.desc()).limit(10).all()
    
    return render_template('admin.html', 
                         users=users, 
                         total_users=total_users,
                         total_usage=total_usage,
                         recent_usage=recent_usage)

@app.route('/admin/delete-user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        return jsonify({'success': False, 'error': 'No autorizado'}), 403
    
    if user_id == current_user.id:
        return jsonify({'success': False, 'error': 'No puedes eliminarte a ti mismo'}), 400
    
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    
    return jsonify({'success': True})

@app.route('/admin/toggle-admin/<int:user_id>', methods=['POST'])
@login_required
def toggle_admin(user_id):
    if not current_user.is_admin:
        return jsonify({'success': False, 'error': 'No autorizado'}), 403
    
    user = User.query.get_or_404(user_id)
    user.is_admin = not user.is_admin
    db.session.commit()
    
    return jsonify({'success': True, 'is_admin': user.is_admin})

# ============= API ENDPOINTS =============

@app.route('/api/preview-markdown', methods=['POST'])
@login_required
def preview_markdown():
    try:
        data = request.get_json()
        md_content = data.get('markdown', '')
        
        html = markdown.markdown(
            md_content,
            extensions=['tables', 'fenced_code', 'codehilite', 'nl2br', 'sane_lists', 'toc']
        )
        
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
        
        html_content = markdown.markdown(
            md_content,
            extensions=['tables', 'fenced_code', 'codehilite', 'toc', 'nl2br', 'sane_lists']
        )
        
        css_styles = """
            @page { size: A4; margin: 2cm; }
            body { font-family: 'Segoe UI', Arial, sans-serif; line-height: 1.6; color: #333; }
            h1 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 0.3em; }
            h2 { color: #2c3e50; border-bottom: 2px solid #95a5a6; padding-bottom: 0.3em; }
            code { background-color: #f4f4f4; padding: 2px 6px; border-radius: 3px; color: #c7254e; }
            pre { background-color: #282c34; color: #abb2bf; padding: 15px; border-radius: 5px; }
            blockquote { border-left: 4px solid #3498db; padding-left: 1em; color: #555; font-style: italic; }
            table { border-collapse: collapse; width: 100%; margin: 1em 0; }
            th, td { border: 1px solid #ddd; padding: 8px; }
            th { background-color: #3498db; color: white; }
        """
        
        full_html = f"<!DOCTYPE html><html><head><meta charset='UTF-8'></head><body>{html_content}</body></html>"
        
        pdf_buffer = io.BytesIO()
        HTML(string=full_html).write_pdf(pdf_buffer, stylesheets=[CSS(string=css_styles)])
        pdf_buffer.seek(0)
        
        safe_filename = "".join(c for c in filename if c.isalnum() or c in (' ', '-', '_')).strip()
        
        return send_file(pdf_buffer, mimetype='application/pdf', as_attachment=True, 
                        download_name=f'{safe_filename}.pdf')
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# ============= INICIALIZACIÓN =============

def init_db():
    with app.app_context():
        db.create_all()
        
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            admin = User(username='admin', email='admin@multitools.com', is_admin=True)
            admin.set_password('admin123')
            db.session.add(admin)
            db.session.commit()
            print('✅ Usuario admin creado (user: admin, pass: admin123)')

if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)
EOF
print_success "app.py creado"

# ========== templates/base.html ==========
print_info "Creando templates/base.html..."
cat > templates/base.html << 'EOF'
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{% block title %}Multi-Herramientas{% endblock %}</title>
    
    <!-- Bootstrap 5 CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <!-- Bootstrap Icons -->
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.1/font/bootstrap-icons.css">
    <!-- Google Fonts -->
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    
    <style>
        * { font-family: 'Poppins', sans-serif; }
        body { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; }
        
        .navbar-custom {
            background: rgba(255, 255, 255, 0.95) !important;
            backdrop-filter: blur(10px);
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        
        .navbar-brand {
            font-weight: 700;
            font-size: 1.5rem;
            background: linear-gradient(135deg, #667eea, #764ba2);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        
        .btn-gradient {
            background: linear-gradient(135deg, #667eea, #764ba2);
            border: none;
            color: white;
            transition: all 0.3s;
        }
        
        .btn-gradient:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(102, 126, 234, 0.4);
            color: white;
        }
        
        .card-custom {
            border: none;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
            transition: transform 0.3s;
        }
        
        .card-custom:hover {
            transform: translateY(-5px);
        }
        
        {% block extra_styles %}{% endblock %}
    </style>
</head>
<body>
    <!-- Navbar -->
    <nav class="navbar navbar-expand-lg navbar-light navbar-custom mb-4">
        <div class="container">
            <a class="navbar-brand" href="{{ url_for('index') if current_user.is_authenticated else url_for('login') }}">
                <i class="bi bi-tools"></i> Multi-Herramientas
            </a>
            
            {% if current_user.is_authenticated %}
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                <span class="navbar-toggler-icon"></span>
            </button>
            
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav ms-auto">
                    <li class="nav-item">
                        <a class="nav-link" href="{{ url_for('index') }}">
                            <i class="bi bi-house"></i> Inicio
                        </a>
                    </li>
                    {% if current_user.is_admin %}
                    <li class="nav-item">
                        <a class="nav-link" href="{{ url_for('admin') }}">
                            <i class="bi bi-shield-lock"></i> Admin
                        </a>
                    </li>
                    {% endif %}
                    <li class="nav-item dropdown">
                        <a class="nav-link dropdown-toggle" href="#" id="userDropdown" role="button" 
                           data-bs-toggle="dropdown">
                            <i class="bi bi-person-circle"></i> {{ current_user.username }}
                        </a>
                        <ul class="dropdown-menu">
                            <li><a class="dropdown-item" href="{{ url_for('logout') }}">
                                <i class="bi bi-box-arrow-right"></i> Cerrar sesión
                            </a></li>
                        </ul>
                    </li>
                </ul>
            </div>
            {% endif %}
        </div>
    </nav>

    <!-- Flash Messages -->
    <div class="container">
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                <div class="alert alert-{{ category }} alert-dismissible fade show" role="alert">
                    {{ message }}
                    <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                </div>
                {% endfor %}
            {% endif %}
        {% endwith %}
    </div>

    <!-- Content -->
    <div class="container">
        {% block content %}{% endblock %}
    </div>

    <!-- Bootstrap 5 JS -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
    {% block scripts %}{% endblock %}
</body>
</html>
EOF
print_success "templates/base.html creado"

# ========== templates/login.html ==========
print_info "Creando templates/login.html..."
cat > templates/login.html << 'EOF'
{% extends "base.html" %}

{% block title %}Iniciar Sesión{% endblock %}

{% block content %}
<div class="row justify-content-center mt-5">
    <div class="col-md-5">
        <div class="card card-custom">
            <div class="card-body p-5">
                <div class="text-center mb-4">
                    <i class="bi bi-person-circle" style="font-size: 4rem; color: #667eea;"></i>
                    <h2 class="mt-3">Iniciar Sesión</h2>
                    <p class="text-muted">Accede a tus herramientas</p>
                </div>

                <form method="POST">
                    {{ form.hidden_tag() }}
                    
                    <div class="mb-3">
                        {{ form.username.label(class="form-label") }}
                        {{ form.username(class="form-control form-control-lg") }}
                        {% if form.username.errors %}
                            <div class="text-danger mt-1">{{ form.username.errors[0] }}</div>
                        {% endif %}
                    </div>

                    <div class="mb-3">
                        {{ form.password.label(class="form-label") }}
                        {{ form.password(class="form-control form-control-lg") }}
                        {% if form.password.errors %}
                            <div class="text-danger mt-1">{{ form.password.errors[0] }}</div>
                        {% endif %}
                    </div>

                    <div class="mb-3 form-check">
                        {{ form.remember_me(class="form-check-input") }}
                        {{ form.remember_me.label(class="form-check-label") }}
                    </div>

                    {{ form.submit(class="btn btn-gradient btn-lg w-100 mb-3") }}
                </form>

                <div class="text-center">
                    <p class="text-muted">¿No tienes cuenta? 
                        <a href="{{ url_for('register') }}" class="text-decoration-none">Regístrate aquí</a>
                    </p>
                </div>
            </div>
        </div>
    </div>
</div>
{% endblock %}
EOF
print_success "templates/login.html creado"

# ========== templates/register.html ==========
print_info "Creando templates/register.html..."
cat > templates/register.html << 'EOF'
{% extends "base.html" %}

{% block title %}Registro{% endblock %}

{% block content %}
<div class="row justify-content-center mt-5">
    <div class="col-md-5">
        <div class="card card-custom">
            <div class="card-body p-5">
                <div class="text-center mb-4">
                    <i class="bi bi-person-plus-fill" style="font-size: 4rem; color: #667eea;"></i>
                    <h2 class="mt-3">Crear Cuenta</h2>
                    <p class="text-muted">Únete a Multi-Herramientas</p>
                </div>

                <form method="POST">
                    {{ form.hidden_tag() }}
                    
                    <div class="mb-3">
                        {{ form.username.label(class="form-label") }}
                        {{ form.username(class="form-control") }}
                        {% for error in form.username.errors %}
                            <div class="text-danger mt-1">{{ error }}</div>
                        {% endfor %}
                    </div>

                    <div class="mb-3">
                        {{ form.email.label(class="form-label") }}
                        {{ form.email(class="form-control") }}
                        {% for error in form.email.errors %}
                            <div class="text-danger mt-1">{{ error }}</div>
                        {% endfor %}
                    </div>

                    <div class="mb-3">
                        {{ form.password.label(class="form-label") }}
                        {{ form.password(class="form-control") }}
                        {% for error in form.password.errors %}
                            <div class="text-danger mt-1">{{ error }}</div>
                        {% endfor %}
                    </div>

                    <div class="mb-3">
                        {{ form.password2.label(class="form-label") }}
                        {{ form.password2(class="form-control") }}
                        {% for error in form.password2.errors %}
                            <div class="text-danger mt-1">{{ error }}</div>
                        {% endfor %}
                    </div>

                    {{ form.submit(class="btn btn-gradient btn-lg w-100 mb-3") }}
                </form>

                <div class="text-center">
                    <p class="text-muted">¿Ya tienes cuenta? 
                        <a href="{{ url_for('login') }}" class="text-decoration-none">Inicia sesión</a>
                    </p>
                </div>
            </div>
        </div>
    </div>
</div>
{% endblock %}
EOF
print_success "templates/register.html creado"

# ========== templates/index.html ==========
print_info "Creando templates/index.html..."
cat > templates/index.html << 'EOF'
{% extends "base.html" %}

{% block title %}Inicio - Multi-Herramientas{% endblock %}

{% block extra_styles %}
.welcome-card {
    background: white;
    border-radius: 20px;
    padding: 40px;
    box-shadow: 0 10px 30px rgba(0,0,0,0.2);
    margin-bottom: 40px;
    text-align: center;
}

.welcome-card h1 {
    background: linear-gradient(135deg, #667eea, #764ba2);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    font-weight: 700;
    margin-bottom: 15px;
}

.tools-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
    gap: 25px;
}

.tool-card {
    background: white;
    border-radius: 20px;
    padding: 35px;
    text-decoration: none;
    color: inherit;
    transition: all 0.3s;
    box-shadow: 0 5px 15px rgba(0,0,0,0.1);
    border: 2px solid transparent;
    display: block;
}

.tool-card:hover {
    transform: translateY(-10px);
    box-shadow: 0 15px 40px rgba(102, 126, 234, 0.3);
    border-color: #667eea;
    color: inherit;
}

.tool-icon {
    font-size: 3.5rem;
    margin-bottom: 20px;
    display: block;
}

.tool-card h3 {
    color: #2c3e50;
    font-weight: 600;
    margin-bottom: 10px;
}

.tool-card p {
    color: #7f8c8d;
    margin-bottom: 0;
}
{% endblock %}

{% block content %}
<div class="welcome-card">
    <h1>👋 Bienvenido, {{ current_user.username }}!</h1>
    <p class="lead text-muted">Selecciona una herramienta para comenzar</p>
</div>

<div class="tools-grid">
    {% for tool in tools %}
    <a href="{{ tool.route }}" class="tool-card">
        <span class="tool-icon">{{ tool.icon }}</span>
        <h3>{{ tool.name }}</h3>
        <p>{{ tool.description }}</p>
    </a>
    {% endfor %}
    
    <div class="tool-card" style="opacity: 0.6; cursor: not-allowed;">
        <span class="tool-icon">➕</span>
        <h3>Próximamente</h3>
        <p>Más herramientas en desarrollo...</p>
    </div>
</div>
{% endblock %}
EOF
print_success "templates/index.html creado"

# ========== templates/md_to_pdf.html ==========
print_info "Creando templates/md_to_pdf.html..."
cat > templates/md_to_pdf.html << 'EOF'
{% extends "base.html" %}

{% block title %}Markdown a PDF{% endblock %}

{% block extra_styles %}
.controls-card {
    background: white;
    border-radius: 15px;
    padding: 20px;
    box-shadow: 0 4px 6px rgba(0,0,0,0.1);
    margin-bottom: 25px;
}

.editor-container {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 25px;
    height: calc(100vh - 350px);
    min-height: 500px;
}

.editor-panel, .preview-panel {
    background: white;
    border-radius: 15px;
    padding: 25px;
    box-shadow: 0 4px 6px rgba(0,0,0,0.1);
    display: flex;
    flex-direction: column;
}

.panel-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 20px;
    padding-bottom: 15px;
    border-bottom: 3px solid #667eea;
}

.panel-header h3 {
    color: #2c3e50;
    font-weight: 600;
    margin: 0;
    font-size: 1.3rem;
}

textarea {
    flex: 1;
    border: 2px solid #e0e0e0;
    border-radius: 10px;
    padding: 20px;
    font-family: 'Monaco', 'Courier New', monospace;
    font-size: 14px;
    resize: none;
    outline: none;
    transition: border-color 0.3s;
}

textarea:focus {
    border-color: #667eea;
}

.preview-content {
    flex: 1;
    overflow-y: auto;
    padding: 20px;
    border: 2px solid #e0e0e0;
    border-radius: 10px;
    background: #fafafa;
}

.preview-content::-webkit-scrollbar {
    width: 8px;
}

.preview-content::-webkit-scrollbar-track {
    background: #f1f1f1;
    border-radius: 10px;
}

.preview-content::-webkit-scrollbar-thumb {
    background: #667eea;
    border-radius: 10px;
}

.preview-content h1 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 0.3em; }
.preview-content h2 { color: #2c3e50; border-bottom: 2px solid #95a5a6; padding-bottom: 0.3em; }
.preview-content h3 { color: #2c3e50; margin-top: 1em; }
.preview-content code { background-color: #f4f4f4; padding: 2px 6px; border-radius: 3px; color: #c7254e; }
.preview-content pre { background-color: #282c34; color: #abb2bf; padding: 15px; border-radius: 5px; overflow-x: auto; }
.preview-content pre code { background-color: transparent; color: #abb2bf; }
.preview-content blockquote { border-left: 4px solid #3498db; padding-left: 1em; color: #555; font-style: italic; margin: 1em 0; }
.preview-content table { border-collapse: collapse; width: 100%; margin: 1em 0; }
.preview-content th, .preview-content td { border: 1px solid #ddd; padding: 10px; text-align: left; }
.preview-content th { background-color: #3498db; color: white; }
.preview-content tr:nth-child(even) { background-color: #f9f9f9; }
.preview-content ul, .preview-content ol { margin: 1em 0; padding-left: 2em; }
.preview-content li { margin: 0.5em 0; }

@media (max-width: 768px) {
    .editor-container {
        grid-template-columns: 1fr;
        height: auto;
    }
    .editor-panel, .preview-panel {
        height: 400px;
    }
}
{% endblock %}

{% block content %}
<div class="controls-card">
    <div class="row g-3 align-items-center">
        <div class="col-md-4">
            <input type="text" id="filename" class="form-control form-control-lg" 
                   placeholder="Nombre del documento" value="mi-documento">
        </div>
        <div class="col-md-8 text-end">
            <button class="btn btn-gradient btn-lg" onclick="generatePDF()">
                <i class="bi bi-file-pdf"></i> Generar PDF
            </button>
            <button class="btn btn-outline-secondary btn-lg" onclick="clearEditor()">
                <i class="bi bi-trash"></i> Limpiar
            </button>
            <span class="ms-3" id="loading" style="display: none;">
                <div class="spinner-border text-primary" role="status">
                    <span class="visually-hidden">Generando...</span>
                </div>
            </span>
        </div>
    </div>
</div>

<div class="editor-container">
    <div class="editor-panel">
        <div class="panel-header">
            <h3><i class="bi bi-pencil-square"></i> Editor Markdown</h3>
        </div>
        <textarea id="markdown-input" placeholder="# Escribe tu Markdown aquí...

## Ejemplo de uso

- Lista de items
- Otro item

**Texto en negrita** y *cursiva*

```python
def hola():
    print('Hola Mundo')
```

| Columna 1 | Columna 2 |
|-----------|-----------|
| Dato 1    | Dato 2    |
"></textarea>
    </div>
    
    <div class="preview-panel">
        <div class="panel-header">
            <h3><i class="bi bi-eye"></i> Vista Previa</h3>
        </div>
        <div class="preview-content" id="preview">
            <p class="text-muted text-center" style="padding: 50px;">
                <i class="bi bi-file-text" style="font-size: 3rem;"></i><br>
                La vista previa aparecerá aquí...
            </p>
        </div>
    </div>
</div>
{% endblock %}

{% block scripts %}
<script>
const markdownInput = document.getElementById('markdown-input');
const preview = document.getElementById('preview');
let debounceTimer;

markdownInput.addEventListener('input', function() {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(updatePreview, 300);
});

async function updatePreview() {
    const markdown = markdownInput.value;
    
    try {
        const response = await fetch('/api/preview-markdown', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ markdown: markdown })
        });
        
        const data = await response.json();
        
        if (data.success) {
            preview.innerHTML = data.html || '<p class="text-muted text-center">Escribe algo para ver la vista previa...</p>';
        }
    } catch (error) {
        console.error('Error:', error);
    }
}

async function generatePDF() {
    const markdown = markdownInput.value;
    const filename = document.getElementById('filename').value || 'documento';
    const loading = document.getElementById('loading');
    
    if (!markdown.trim()) {
        alert('Por favor escribe algo antes de generar el PDF');
        return;
    }
    
    loading.style.display = 'inline-block';
    
    try {
        const response = await fetch('/api/generate-pdf', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ markdown: markdown, filename: filename })
        });
        
        if (response.ok) {
            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = filename + '.pdf';
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            document.body.removeChild(a);
        } else {
            alert('Error al generar el PDF');
        }
    } catch (error) {
        console.error('Error:', error);
        alert('Error al generar el PDF');
    } finally {
        loading.style.display = 'none';
    }
}

function clearEditor() {
    if (confirm('¿Estás seguro de que quieres limpiar el editor?')) {
        markdownInput.value = '';
        preview.innerHTML = '<p class="text-muted text-center" style="padding: 50px;">La vista previa aparecerá aquí...</p>';
    }
}

if (markdownInput.value.trim()) {
    updatePreview();
}
</script>
{% endblock %}
EOF
print_success "templates/md_to_pdf.html creado"

# ========== templates/admin.html ==========
print_info "Creando templates/admin.html..."
cat > templates/admin.html << 'EOF'
{% extends "base.html" %}

{% block title %}Panel de Administración{% endblock %}

{% block extra_styles %}
.stats-card {
    background: white;
    border-radius: 15px;
    padding: 25px;
    text-align: center;
    box-shadow: 0 4px 6px rgba(0,0,0,0.1);
    transition: transform 0.3s;
}

.stats-card:hover {
    transform: translateY(-5px);
}

.stats-icon {
    font-size: 3rem;
    margin-bottom: 15px;
    background: linear-gradient(135deg, #667eea, #764ba2);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
}

.stats-number {
    font-size: 2.5rem;
    font-weight: 700;
    color: #2c3e50;
}

.stats-label {
    color: #7f8c8d;
    font-size: 0.9rem;
    text-transform: uppercase;
    letter-spacing: 1px;
}

.bg-gradient {
    background: linear-gradient(135deg, #667eea, #764ba2);
}
{% endblock %}

{% block content %}
<h1 class="text-white mb-4"><i class="bi bi-shield-lock"></i> Panel de Administración</h1>

<div class="row mb-4">
    <div class="col-md-4">
        <div class="stats-card">
            <i class="bi bi-people stats-icon"></i>
            <div class="stats-number">{{ total_users }}</div>
            <div class="stats-label">Usuarios Totales</div>
        </div>
    </div>
    <div class="col-md-4">
        <div class="stats-card">
            <i class="bi bi-bar-chart stats-icon"></i>
            <div class="stats-number">{{ total_usage }}</div>
            <div class="stats-label">Usos de Herramientas</div>
        </div>
    </div>
    <div class="col-md-4">
        <div class="stats-card">
            <i class="bi bi-tools stats-icon"></i>
            <div class="stats-number">{{ tools|length if tools else 1 }}</div>
            <div class="stats-label">Herramientas Activas</div>
        </div>
    </div>
</div>

<div class="row">
    <div class="col-md-8">
        <div class="card card-custom">
            <div class="card-header bg-gradient text-white">
                <h5 class="mb-0"><i class="bi bi-people"></i> Gestión de Usuarios</h5>
            </div>
            <div class="card-body">
                <div class="table-responsive">
                    <table class="table table-hover">
                        <thead>
                            <tr>
                                <th>Usuario</th>
                                <th>Email</th>
                                <th>Admin</th>
                                <th>Registro</th>
                                <th>Acciones</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for user in users %}
                            <tr id="user-{{ user.id }}">
                                <td>
                                    <i class="bi bi-person-circle"></i> {{ user.username }}
                                    {% if user.id == current_user.id %}
                                        <span class="badge bg-info">Tú</span>
                                    {% endif %}
                                </td>
                                <td>{{ user.email }}</td>
                                <td>
                                    <span class="badge bg-{{ 'success' if user.is_admin else 'secondary' }}">
                                        {{ 'Sí' if user.is_admin else 'No' }}
                                    </span>
                                </td>
                                <td>{{ user.created_at.strftime('%d/%m/%Y') }}</td>
                                <td>
                                    {% if user.id != current_user.id %}
                                    <button class="btn btn-sm btn-warning" onclick="toggleAdmin({{ user.id }})" 
                                            title="Cambiar permisos de admin">
                                        <i class="bi bi-shield"></i>
                                    </button>
                                    <button class="btn btn-sm btn-danger" onclick="deleteUser({{ user.id }})"
                                            title="Eliminar usuario">
                                        <i class="bi bi-trash"></i>
                                    </button>
                                    {% endif %}
                                </td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>

    <div class="col-md-4">
        <div class="card card-custom">
            <div class="card-header bg-gradient text-white">
                <h5 class="mb-0"><i class="bi bi-clock-history"></i> Actividad Reciente</h5>
            </div>
            <div class="card-body" style="max-height: 400px; overflow-y: auto;">
                {% if recent_usage %}
                    {% for usage in recent_usage %}
                    <div class="mb-3 pb-3 border-bottom">
                        <div class="d-flex justify-content-between">
                            <strong>{{ usage.user.username }}</strong>
                            <small class="text-muted">{{ usage.timestamp.strftime('%H:%M') }}</small>
                        </div>
                        <small class="text-muted">{{ usage.tool_name }}</small>
                    </div>
                    {% endfor %}
                {% else %}
                    <p class="text-muted text-center">No hay actividad reciente</p>
                {% endif %}
            </div>
        </div>
    </div>
</div>
{% endblock %}

{% block scripts %}
<script>
async function deleteUser(userId) {
    if (!confirm('¿Estás seguro de que quieres eliminar este usuario?')) return;
    
    try {
        const response = await fetch(`/admin/delete-user/${userId}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        });
        
        const data = await response.json();
        
        if (data.success) {
            document.getElementById(`user-${userId}`).remove();
            alert('Usuario eliminado correctamente');
        } else {
            alert('Error: ' + data.error);
        }
    } catch (error) {
        alert('Error al eliminar usuario');
    }
}

async function toggleAdmin(userId) {
    try {
        const response = await fetch(`/admin/toggle-admin/${userId}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        });
        
        const data = await response.json();
        
        if (data.success) {
            location.reload();
        } else {
            alert('Error: ' + data.error);
        }
    } catch (error) {
        alert('Error al cambiar permisos');
    }
}
</script>
{% endblock %}
EOF
print_success "templates/admin.html creado"

# ========== README.md ==========
print_info "Creando README.md..."
cat > README.md << 'EOF'
# 🛠️ Flask Multi-Herramientas

Aplicación web modular con sistema de autenticación, panel de administración y herramientas útiles.

## 🚀 Inicio Rápido

### 1. Instalar dependencias

```bash
# Crear y activar virtual environment
python3 -m venv venv
source venv/bin/activate  # Mac/Linux
# venv\Scripts\activate   # Windows

# Instalar dependencias
pip install -r requirements.txt
```

### 2. Ejecutar la aplicación

```bash
python app.py
```

### 3. Abrir en el navegador

Visita: http://localhost:5000

## 🔐 Credenciales por defecto

- **Usuario**: admin
- **Contraseña**: admin123

**⚠️ IMPORTANTE**: Cambia estas credenciales después del primer login.

## 📦 Características

- ✅ Sistema de autenticación (login/registro)
- ✅ Panel de administración
- ✅ Herramienta Markdown a PDF
- ✅ Bootstrap 5 con diseño moderno
- ✅ Base de datos SQLite
- ✅ Gestión de usuarios

## 🎨 Stack Tecnológico

- Flask 3.0
- Bootstrap 5.3
- SQLAlchemy
- Flask-Login
- WTForms
- WeasyPrint (generación de PDFs)

## 📁 Estructura del Proyecto

```
.
├── app.py              # Aplicación principal
├── config.py           # Configuración
├── models.py           # Modelos de base de datos
├── forms.py            # Formularios WTForms
├── requirements.txt    # Dependencias
├── templates/          # Templates HTML
│   ├── base.html
│   ├── login.html
│   ├── register.html
│   ├── index.html
│   ├── md_to_pdf.html
│   └── admin.html
└── static/             # Archivos estáticos
    ├── css/
    ├── js/
    └── img/
```

## ➕ Añadir Nuevas Herramientas

Ver documentación en las instrucciones de PyCharm.

## 📝 Licencia

Proyecto de código abierto para uso libre.
EOF
print_success "README.md creado"

# ========== Resumen final ==========
echo ""
echo "=================================================="
echo "🎉 ¡INSTALACIÓN COMPLETADA!"
echo "=================================================="
echo ""
print_success "Todos los archivos han sido creados exitosamente"
echo ""
echo "📋 Archivos creados:"
echo "   ✓ config.py"
echo "   ✓ models.py"
echo "   ✓ forms.py"
echo "   ✓ app.py"
echo "   ✓ requirements.txt"
echo "   ✓ .gitignore"
echo "   ✓ README.md"
echo "   ✓ templates/base.html"
echo "   ✓ templates/login.html"
echo "   ✓ templates/register.html"
echo "   ✓ templates/index.html"
echo "   ✓ templates/md_to_pdf.html"
echo "   ✓ templates/admin.html"
echo ""
echo "🚀 PRÓXIMOS PASOS:"
echo ""
echo "1️⃣  Crear virtual environment:"
echo "    python3 -m venv venv"
echo ""
echo "2️⃣  Activar virtual environment:"
echo "    source venv/bin/activate     (Mac/Linux)"
echo "    venv\\Scripts\\activate        (Windows)"
echo ""
echo "3️⃣  Instalar dependencias:"
echo "    pip install -r requirements.txt"
echo ""
echo "4️⃣  Ejecutar la aplicación:"
echo "    python app.py"
echo ""
echo "5️⃣  Abrir en el navegador:"
echo "    http://localhost:5000"
echo ""
echo "🔐 Credenciales iniciales:"
echo "    Usuario: admin"
echo "    Contraseña: admin123"
echo ""
print_success "¡Listo para desarrollar! 🎉"
echo ""

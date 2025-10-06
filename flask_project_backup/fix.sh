#!/bin/bash

# Script para arreglar todos los problemas de una vez

echo "🔧 ARREGLANDO PROYECTO - Flask Multi-Herramientas"
echo "=================================================="
echo ""

# Colores
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

print_success() { echo -e "${GREEN}✅ $1${NC}"; }
print_info() { echo -e "${BLUE}ℹ️  $1${NC}"; }
print_error() { echo -e "${RED}❌ $1${NC}"; }

# 1. Actualizar requirements.txt con versiones flexibles
print_info "Actualizando requirements.txt con versiones flexibles..."
cat > requirements.txt << 'EOF'
Flask>=3.0.0
Flask-SQLAlchemy>=3.1.0
Flask-Login>=0.6.0
Flask-WTF>=1.2.0
WTForms>=3.1.0
markdown>=3.5.0
weasyprint>=60.0
Pygments>=2.17.0
werkzeug>=3.0.0
email-validator>=2.1.0
EOF
print_success "requirements.txt actualizado"

# 2. Reinstalar dependencias con las últimas versiones
print_info "Reinstalando dependencias con las últimas versiones..."
pip install --upgrade -r requirements.txt
if [ $? -eq 0 ]; then
    print_success "Dependencias instaladas/actualizadas"
else
    print_error "Error al instalar dependencias"
    exit 1
fi

# 3. Eliminar base de datos antigua si existe
if [ -f "multitools.db" ]; then
    print_info "Eliminando base de datos antigua..."
    rm multitools.db
    print_success "Base de datos antigua eliminada"
fi

# 4. Verificar que existe app.py
if [ ! -f "app.py" ]; then
    print_error "No se encuentra app.py"
    exit 1
fi

# 5. Inicializar base de datos
print_info "Inicializando base de datos..."
python3 << 'EOFPYTHON'
from app import app, db
from models import User

with app.app_context():
    db.create_all()
    
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        admin = User(username='admin', email='admin@multitools.com', is_admin=True)
        admin.set_password('admin123')
        db.session.add(admin)
        db.session.commit()
        print('✅ Usuario admin creado')
    
    print('✅ Base de datos inicializada correctamente')
    print(f'📊 Total usuarios: {User.query.count()}')
EOFPYTHON

if [ $? -eq 0 ]; then
    print_success "Base de datos inicializada correctamente"
else
    print_error "Error al inicializar la base de datos"
    exit 1
fi

# 6. Mostrar información
echo ""
echo "=================================================="
print_success "¡TODO ARREGLADO!"
echo "=================================================="
echo ""
echo "📋 Resumen:"
echo "   ✅ Requirements.txt actualizado (versiones flexibles)"
echo "   ✅ Dependencias instaladas/actualizadas"
echo "   ✅ Base de datos inicializada"
echo "   ✅ Usuario admin creado"
echo ""
echo "🔐 Credenciales:"
echo "   Usuario: admin"
echo "   Contraseña: admin123"
echo ""
echo "🚀 Para ejecutar la aplicación:"
echo "   python app.py"
echo "   O: flask run"
echo ""
echo "🌐 Luego abre: http://localhost:5000"
echo ""

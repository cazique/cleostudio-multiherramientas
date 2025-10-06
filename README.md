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

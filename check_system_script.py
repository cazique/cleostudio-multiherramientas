#!/usr/bin/env python3
"""
Script de diagnóstico para verificar el sistema
Ejecutar: python check.py
"""

import os
import subprocess
import sys


def print_header(text):
    print("\n" + "=" * 60)
    print(f"  {text}")
    print("=" * 60)


def check_python_version():
    print_header("🐍 Versión de Python")
    version = sys.version
    print(
        f"Python {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    )
    print(f"Ejecutable: {sys.executable}")

    if sys.version_info < (3, 8):
        print("⚠️  ADVERTENCIA: Se recomienda Python 3.8 o superior")
    else:
        print("✅ Versión de Python OK")


def check_packages():
    print_header("📦 Paquetes Instalados")

    required_packages = [
        "flask",
        "flask_sqlalchemy",
        "flask_login",
        "flask_wtf",
        "wtforms",
        "markdown",
        "weasyprint",
        "pygments",
        "werkzeug",
        "email_validator",
    ]

    all_ok = True

    for package in required_packages:
        try:
            mod = __import__(package)
            version = getattr(mod, "__version__", "unknown")
            print(f"✅ {package:20s} {version}")
        except ImportError:
            print(f"❌ {package:20s} NO INSTALADO")
            all_ok = False

    if all_ok:
        print("\n✅ Todos los paquetes están instalados")
    else:
        print("\n❌ Faltan paquetes. Ejecuta: pip install -r requirements.txt")


def check_database():
    print_header("💾 Base de Datos")

    db_path = "multitools.db"

    if os.path.exists(db_path):
        size = os.path.getsize(db_path)
        print(f"✅ Base de datos encontrada: {db_path}")
        print(f"   Tamaño: {size} bytes")

        # Intentar conectar
        try:
            from app import app, db
            from models import User

            with app.app_context():
                user_count = User.query.count()
                print(f"   Usuarios registrados: {user_count}")

                admin = User.query.filter_by(username="admin").first()
                if admin:
                    print(f"   ✅ Usuario admin existe")
                else:
                    print(f"   ⚠️  Usuario admin NO existe")

        except Exception as e:
            print(f"   ⚠️  Error al conectar: {str(e)}")
            print("   Ejecuta: python init_db.py")
    else:
        print(f"❌ Base de datos NO encontrada")
        print("   Ejecuta: python init_db.py")


def check_files():
    print_header("📁 Archivos del Proyecto")

    required_files = [
        "app.py",
        "config.py",
        "models.py",
        "forms.py",
        "requirements.txt",
        "templates/base.html",
        "templates/login.html",
        "templates/register.html",
        "templates/index.html",
        "templates/md_to_pdf.html",
        "templates/admin.html",
    ]

    all_ok = True

    for file in required_files:
        if os.path.exists(file):
            print(f"✅ {file}")
        else:
            print(f"❌ {file} - NO ENCONTRADO")
            all_ok = False

    if all_ok:
        print("\n✅ Todos los archivos necesarios están presentes")
    else:
        print("\n❌ Faltan archivos. Vuelve a ejecutar el script de instalación")


def check_pip_outdated():
    print_header("🔄 Paquetes con Actualizaciones Disponibles")

    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "list", "--outdated"],
            capture_output=True,
            text=True,
        )

        if result.stdout.strip():
            print(result.stdout)
            print("\n💡 Para actualizar: pip install --upgrade nombre-paquete")
        else:
            print("✅ Todos los paquetes están actualizados")

    except Exception as e:
        print(f"⚠️  No se pudo verificar actualizaciones: {e}")


def check_port():
    print_header("🌐 Puerto 5000")

    import socket

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex(("127.0.0.1", 5000))
    sock.close()

    if result == 0:
        print("⚠️  Puerto 5000 está en uso")
        print("   La aplicación ya está corriendo o el puerto está ocupado")
    else:
        print("✅ Puerto 5000 disponible")


def show_commands():
    print_header("🚀 Comandos Útiles")

    print(
        """
1. Inicializar/Resetear base de datos:
   python init_db.py

2. Ejecutar la aplicación:
   python app.py
   
3. O con Flask CLI:
   flask run

4. Instalar dependencias:
   pip install -r requirements.txt

5. Actualizar todos los paquetes:
   pip install --upgrade -r requirements.txt

6. Ver versiones instaladas:
   pip list

7. Ver paquetes desactualizados:
   pip list --outdated
    """
    )


def main():
    print("\n🔍 DIAGNÓSTICO DEL SISTEMA - Flask Multi-Herramientas\n")

    check_python_version()
    check_packages()
    check_files()
    check_database()
    check_port()
    check_pip_outdated()
    show_commands()

    print("\n" + "=" * 60)
    print("  ✅ Diagnóstico completado")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    main()

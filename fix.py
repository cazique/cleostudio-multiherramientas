#!/usr/bin/env python3
"""
Script de corrección post-login - Error 500 después de autenticación
Ejecutar: python fix_post_login.py
"""

import os
import shutil
from datetime import datetime


def print_header(text):
    print("\n" + "=" * 60)
    print(f"  {text}")
    print("=" * 60)


def check_templates_exist():
    """Verifica que existan todos los templates necesarios"""
    print_header("Verificando templates")

    required_templates = [
        'templates/base.html',
        'templates/index.html',
        'templates/login.html',
        'templates/register.html',
        'templates/404.html',
        'templates/500.html'
    ]

    missing = []
    for template in required_templates:
        if os.path.exists(template):
            print(f"✓ {template}")
        else:
            print(f"❌ FALTA: {template}")
            missing.append(template)

    return missing


def fix_index_html():
    """Crea un index.html ultra-simplificado"""
    print_header("Creando index.html simplificado")

    # Primero, hacer backup si existe
    if os.path.exists("templates/index.html"):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_name = f"templates/index_backup_{timestamp}.html"
        shutil.copy2("templates/index.html", backup_name)
        print(f"✓ Backup creado: {backup_name}")

    index_content = '''{% extends "base.html" %}
{% block title %}Multi-Herramientas{% endblock %}

{% block content %}
<div class="text-center mb-8">
    <h1 class="text-4xl font-bold text-gray-900 dark:text-white mb-3">
        Todas las herramientas que necesitas
    </h1>
    <p class="text-lg text-gray-600 dark:text-gray-400">
        Trabaja con PDFs, analiza redes, verifica seguridad. 100% GRATIS.
    </p>
</div>

<!-- Grid de herramientas -->
<div class="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 xl:grid-cols-5 gap-4">

    <!-- Markdown to PDF -->
    <a href="{{ url_for('md_to_pdf_page') }}" class="bg-white dark:bg-gray-800 rounded-2xl p-6 shadow-sm hover:shadow-xl transition-all hover:-translate-y-1 border border-gray-100 dark:border-gray-700 group">
        <div class="w-16 h-16 rounded-xl bg-gradient-to-br from-red-500 to-pink-500 flex items-center justify-center text-3xl mb-4 group-hover:scale-110 transition">
            📝
        </div>
        <h3 class="font-bold text-gray-900 dark:text-white mb-1 text-sm">Markdown → PDF</h3>
        <p class="text-xs text-gray-500 dark:text-gray-400 leading-relaxed">Convierte Markdown a PDF</p>
    </a>

    <!-- Comprimir PDF -->
    <a href="{{ url_for('compress_pdf_page') }}" class="bg-white dark:bg-gray-800 rounded-2xl p-6 shadow-sm hover:shadow-xl transition-all hover:-translate-y-1 border border-gray-100 dark:border-gray-700 group">
        <div class="w-16 h-16 rounded-xl bg-gradient-to-br from-teal-500 to-cyan-500 flex items-center justify-center text-3xl mb-4 group-hover:scale-110 transition">
            🗜️
        </div>
        <h3 class="font-bold text-gray-900 dark:text-white mb-1 text-sm">Comprimir PDF</h3>
        <p class="text-xs text-gray-500 dark:text-gray-400 leading-relaxed">Reduce el tamaño</p>
    </a>

    <!-- Combinar PDF -->
    <a href="{{ url_for('merge_pdf_page') }}" class="bg-white dark:bg-gray-800 rounded-2xl p-6 shadow-sm hover:shadow-xl transition-all hover:-translate-y-1 border border-gray-100 dark:border-gray-700 group">
        <div class="w-16 h-16 rounded-xl bg-gradient-to-br from-emerald-500 to-teal-500 flex items-center justify-center text-3xl mb-4 group-hover:scale-110 transition">
            📚
        </div>
        <h3 class="font-bold text-gray-900 dark:text-white mb-1 text-sm">Combinar PDFs</h3>
        <p class="text-xs text-gray-500 dark:text-gray-400 leading-relaxed">Une múltiples PDFs</p>
    </a>

    <!-- Dividir PDF -->
    <a href="{{ url_for('split_pdf_page') }}" class="bg-white dark:bg-gray-800 rounded-2xl p-6 shadow-sm hover:shadow-xl transition-all hover:-translate-y-1 border border-gray-100 dark:border-gray-700 group">
        <div class="w-16 h-16 rounded-xl bg-gradient-to-br from-yellow-500 to-amber-500 flex items-center justify-center text-3xl mb-4 group-hover:scale-110 transition">
            ✂️
        </div>
        <h3 class="font-bold text-gray-900 dark:text-white mb-1 text-sm">Dividir PDF</h3>
        <p class="text-xs text-gray-500 dark:text-gray-400 leading-relaxed">Extrae páginas</p>
    </a>

    <!-- Imágenes a PDF -->
    <a href="{{ url_for('images_to_pdf_page') }}" class="bg-white dark:bg-gray-800 rounded-2xl p-6 shadow-sm hover:shadow-xl transition-all hover:-translate-y-1 border border-gray-100 dark:border-gray-700 group">
        <div class="w-16 h-16 rounded-xl bg-gradient-to-br from-gray-500 to-slate-500 flex items-center justify-center text-3xl mb-4 group-hover:scale-110 transition">
            📄
        </div>
        <h3 class="font-bold text-gray-900 dark:text-white mb-1 text-sm">Imágenes → PDF</h3>
        <p class="text-xs text-gray-500 dark:text-gray-400 leading-relaxed">Convierte JPG, PNG</p>
    </a>

    <!-- Comprimir Imagen -->
    <a href="{{ url_for('compress_image_page') }}" class="bg-white dark:bg-gray-800 rounded-2xl p-6 shadow-sm hover:shadow-xl transition-all hover:-translate-y-1 border border-gray-100 dark:border-gray-700 group">
        <div class="w-16 h-16 rounded-xl bg-gradient-to-br from-pink-500 to-rose-500 flex items-center justify-center text-3xl mb-4 group-hover:scale-110 transition">
            🎨
        </div>
        <h3 class="font-bold text-gray-900 dark:text-white mb-1 text-sm">Comprimir Imagen</h3>
        <p class="text-xs text-gray-500 dark:text-gray-400 leading-relaxed">Optimiza imágenes</p>
    </a>

    <!-- IP WHOIS -->
    <a href="{{ url_for('ip_whois_page') }}" class="bg-white dark:bg-gray-800 rounded-2xl p-6 shadow-sm hover:shadow-xl transition-all hover:-translate-y-1 border border-gray-100 dark:border-gray-700 group">
        <div class="w-16 h-16 rounded-xl bg-gradient-to-br from-purple-500 to-indigo-500 flex items-center justify-center text-3xl mb-4 group-hover:scale-110 transition">
            📜
        </div>
        <h3 class="font-bold text-gray-900 dark:text-white mb-1 text-sm">IP WHOIS</h3>
        <p class="text-xs text-gray-500 dark:text-gray-400 leading-relaxed">Info de direcciones IP</p>
    </a>

    <!-- Blacklist Check -->
    <a href="{{ url_for('blacklist_check_page') }}" class="bg-white dark:bg-gray-800 rounded-2xl p-6 shadow-sm hover:shadow-xl transition-all hover:-translate-y-1 border border-gray-100 dark:border-gray-700 group">
        <div class="w-16 h-16 rounded-xl bg-gradient-to-br from-indigo-500 to-purple-500 flex items-center justify-center text-3xl mb-4 group-hover:scale-110 transition">
            🛡️
        </div>
        <h3 class="font-bold text-gray-900 dark:text-white mb-1 text-sm">Blacklist Check</h3>
        <p class="text-xs text-gray-500 dark:text-gray-400 leading-relaxed">Verifica IPs listadas</p>
    </a>

    <!-- SSL Check -->
    <a href="{{ url_for('ssl_check_page') }}" class="bg-white dark:bg-gray-800 rounded-2xl p-6 shadow-sm hover:shadow-xl transition-all hover:-translate-y-1 border border-gray-100 dark:border-gray-700 group">
        <div class="w-16 h-16 rounded-xl bg-gradient-to-br from-green-500 to-emerald-500 flex items-center justify-center text-3xl mb-4 group-hover:scale-110 transition">
            ✅
        </div>
        <h3 class="font-bold text-gray-900 dark:text-white mb-1 text-sm">SSL Check</h3>
        <p class="text-xs text-gray-500 dark:text-gray-400 leading-relaxed">Analiza certificados SSL</p>
    </a>

    <!-- Port Scanner -->
    <a href="{{ url_for('port_scanner_page') }}" class="bg-white dark:bg-gray-800 rounded-2xl p-6 shadow-sm hover:shadow-xl transition-all hover:-translate-y-1 border border-gray-100 dark:border-gray-700 group">
        <div class="w-16 h-16 rounded-xl bg-gradient-to-br from-blue-500 to-cyan-500 flex items-center justify-center text-3xl mb-4 group-hover:scale-110 transition">
            📡
        </div>
        <h3 class="font-bold text-gray-900 dark:text-white mb-1 text-sm">Port Scanner</h3>
        <p class="text-xs text-gray-500 dark:text-gray-400 leading-relaxed">Escanea puertos</p>
    </a>

    <!-- HTTP Headers -->
    <a href="{{ url_for('http_headers_page') }}" class="bg-white dark:bg-gray-800 rounded-2xl p-6 shadow-sm hover:shadow-xl transition-all hover:-translate-y-1 border border-gray-100 dark:border-gray-700 group">
        <div class="w-16 h-16 rounded-xl bg-gradient-to-br from-amber-500 to-yellow-500 flex items-center justify-center text-3xl mb-4 group-hover:scale-110 transition">
            📑
        </div>
        <h3 class="font-bold text-gray-900 dark:text-white mb-1 text-sm">HTTP Headers</h3>
        <p class="text-xs text-gray-500 dark:text-gray-400 leading-relaxed">Analiza cabeceras HTTP</p>
    </a>

    <!-- Password Generator -->
    <a href="{{ url_for('password_gen_page') }}" class="bg-white dark:bg-gray-800 rounded-2xl p-6 shadow-sm hover:shadow-xl transition-all hover:-translate-y-1 border border-gray-100 dark:border-gray-700 group">
        <div class="w-16 h-16 rounded-xl bg-gradient-to-br from-orange-500 to-red-500 flex items-center justify-center text-3xl mb-4 group-hover:scale-110 transition">
            🔑
        </div>
        <h3 class="font-bold text-gray-900 dark:text-white mb-1 text-sm">Password Generator</h3>
        <p class="text-xs text-gray-500 dark:text-gray-400 leading-relaxed">Genera contraseñas</p>
    </a>

    <!-- MX Lookup -->
    <a href="{{ url_for('mx_lookup_page') }}" class="bg-white dark:bg-gray-800 rounded-2xl p-6 shadow-sm hover:shadow-xl transition-all hover:-translate-y-1 border border-gray-100 dark:border-gray-700 group">
        <div class="w-16 h-16 rounded-xl bg-gradient-to-br from-sky-500 to-blue-500 flex items-center justify-center text-3xl mb-4 group-hover:scale-110 transition">
            📮
        </div>
        <h3 class="font-bold text-gray-900 dark:text-white mb-1 text-sm">MX Lookup</h3>
        <p class="text-xs text-gray-500 dark:text-gray-400 leading-relaxed">Servidores de correo</p>
    </a>

    <!-- DNS Lookup -->
    <a href="{{ url_for('dns_lookup_page') }}" class="bg-white dark:bg-gray-800 rounded-2xl p-6 shadow-sm hover:shadow-xl transition-all hover:-translate-y-1 border border-gray-100 dark:border-gray-700 group">
        <div class="w-16 h-16 rounded-xl bg-gradient-to-br from-orange-500 to-amber-500 flex items-center justify-center text-3xl mb-4 group-hover:scale-110 transition">
            🔍
        </div>
        <h3 class="font-bold text-gray-900 dark:text-white mb-1 text-sm">DNS Lookup</h3>
        <p class="text-xs text-gray-500 dark:text-gray-400 leading-relaxed">Registros DNS</p>
    </a>

    <!-- SPF Check -->
    <a href="{{ url_for('spf_check_page') }}" class="bg-white dark:bg-gray-800 rounded-2xl p-6 shadow-sm hover:shadow-xl transition-all hover:-translate-y-1 border border-gray-100 dark:border-gray-700 group">
        <div class="w-16 h-16 rounded-xl bg-gradient-to-br from-teal-500 to-green-500 flex items-center justify-center text-3xl mb-4 group-hover:scale-110 transition">
            🛡️
        </div>
        <h3 class="font-bold text-gray-900 dark:text-white mb-1 text-sm">SPF Check</h3>
        <p class="text-xs text-gray-500 dark:text-gray-400 leading-relaxed">Verifica SPF email</p>
    </a>

    <!-- DKIM Check -->
    <a href="{{ url_for('dkim_check_page') }}" class="bg-white dark:bg-gray-800 rounded-2xl p-6 shadow-sm hover:shadow-xl transition-all hover:-translate-y-1 border border-gray-100 dark:border-gray-700 group">
        <div class="w-16 h-16 rounded-xl bg-gradient-to-br from-cyan-500 to-teal-500 flex items-center justify-center text-3xl mb-4 group-hover:scale-110 transition">
            🔑
        </div>
        <h3 class="font-bold text-gray-900 dark:text-white mb-1 text-sm">DKIM Check</h3>
        <p class="text-xs text-gray-500 dark:text-gray-400 leading-relaxed">Valida firmas DKIM</p>
    </a>

</div>
{% endblock %}
'''

    with open("templates/index.html", "w", encoding="utf-8") as f:
        f.write(index_content)

    print("✓ index.html simplificado creado")


def test_app_routes():
    """Prueba que todas las rutas estén definidas"""
    print_header("Verificando rutas en app.py")

    try:
        with open("app.py", "r") as f:
            content = f.read()

        required_routes = [
            'md_to_pdf_page',
            'compress_pdf_page',
            'merge_pdf_page',
            'split_pdf_page',
            'images_to_pdf_page',
            'compress_image_page',
            'ip_whois_page',
            'blacklist_check_page',
            'ssl_check_page',
            'port_scanner_page',
            'http_headers_page',
            'password_gen_page',
            'mx_lookup_page',
            'dns_lookup_page',
            'spf_check_page',
            'dkim_check_page'
        ]

        missing_routes = []
        for route in required_routes:
            if f"def {route}" in content:
                print(f"✓ {route}")
            else:
                print(f"❌ FALTA: {route}")
                missing_routes.append(route)

        return missing_routes

    except Exception as e:
        print(f"❌ Error al leer app.py: {e}")
        return []


def create_debug_route():
    """Añade una ruta de debug temporal"""
    print_header("Añadiendo ruta de debug")

    debug_code = '''
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
'''

    try:
        with open("app.py", "r") as f:
            content = f.read()

        if "@app.route('/debug')" not in content:
            # Insertar antes del if __name__ == "__main__"
            content = content.replace(
                "if __name__ == '__main__':",
                debug_code + "\nif __name__ == '__main__':"
            )

            with open("app.py", "w") as f:
                f.write(content)

            print("✓ Ruta de debug añadida: /debug")
        else:
            print("✓ Ruta de debug ya existe")
    except Exception as e:
        print(f"❌ Error: {e}")


def show_logs_instructions():
    """Muestra instrucciones para ver logs"""
    print_header("📋 Ver logs del servidor")

    print("""
Para ver exactamente qué está causando el error 500:

1. Abre una terminal y ejecuta:

   python app.py

2. En otra terminal o navegador, intenta hacer login

3. Observa la terminal donde corre Flask - verás el error exacto

4. Compárteme el error completo que aparece en la terminal

Ejemplo de lo que buscar:
   [2024-10-06 19:30:00] ERROR in app: Exception on / [GET]
   Traceback (most recent call last):
     File "...", line X, in ...

COPIA TODO ESE TEXTO Y COMPÁRTELO CONMIGO
""")


def main():
    """Función principal"""
    print_header("🔧 Corrección Error 500 Post-Login")

    try:
        # Verificar templates
        missing_templates = check_templates_exist()

        # Arreglar index.html
        fix_index_html()

        # Verificar rutas
        missing_routes = test_app_routes()

        # Añadir debug
        create_debug_route()

        print_header("✅ CORRECCIONES APLICADAS")

        if missing_templates or missing_routes:
            print("\n⚠️  ADVERTENCIAS:")
            if missing_templates:
                print(f"  - Templates faltantes: {', '.join(missing_templates)}")
            if missing_routes:
                print(f"  - Rutas faltantes: {', '.join(missing_routes)}")

        print("\n🎯 PASOS SIGUIENTES:")
        print("1. Ejecuta: python app.py")
        print("2. Accede a: http://127.0.0.1:5000/login")
        print("3. Login: admin / admin123")
        print("4. Si aún falla, ve a: http://127.0.0.1:5000/debug")

        show_logs_instructions()

    except Exception as e:
        print(f"\n❌ ERROR: {e}")


if __name__ == "__main__":
    main()
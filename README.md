# Multi-Herramientas Flask

Este es un proyecto Flask que proporciona una colección de herramientas web categorizadas en PDF/Imágenes, Red y Seguridad. La aplicación está diseñada para ser modular y fácil de extender.

## Características

- **Herramientas de PDF e Imágenes**:
  - Convertir Markdown a PDF
  - Comprimir PDF
  - Combinar múltiples PDFs en uno
  - Dividir un PDF extrayendo páginas específicas
  - Convertir imágenes a PDF
  - Comprimir imágenes
- **Herramientas de Red**:
  - **IP WHOIS**: Consulta información de registro para una dirección IP.
  - **Blacklist Check**: Verifica si una IP está en las listas negras de spam más comunes.
- **Herramientas de Seguridad**:
  - **SSL Check**: Analiza el certificado SSL de un dominio.
  - **Port Scanner**: Escanea los puertos abiertos más comunes de un host.
  - **HTTP Headers**: Muestra las cabeceras de respuesta de una URL.
  - **Password Generator**: Crea contraseñas seguras y personalizables.
- **Sistema de Autenticación**:
  - Registro e inicio de sesión de usuarios.
  - Panel de administración para gestionar usuarios.

## Requisitos

- Python 3.8+
- `pip` para la gestión de paquetes
- `libcairo2-dev` (o su equivalente en otros sistemas operativos) para la generación de PDFs.

## Instalación

1.  **Clona el repositorio**:
    ```bash
    git clone <URL_DEL_REPOSITORIO>
    cd <NOMBRE_DEL_REPOSITORIO>
    ```

2.  **Crea y activa un entorno virtual** (recomendado):
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```

3.  **Instala las dependencias del sistema** (para sistemas basados en Debian/Ubuntu):
    ```bash
    sudo apt-get update && sudo apt-get install -y libcairo2-dev
    ```

4.  **Instala las dependencias de Python**:
    ```bash
    pip install -r requirements.txt
    ```

## Ejecución

1.  **Inicializa la base de datos**:
    La base de datos (`multitools.db`) se creará automáticamente la primera vez que ejecutes la aplicación. Se creará un usuario administrador por defecto:
    - **Usuario**: `admin`
    - **Contraseña**: `admin123`

2.  **Inicia la aplicación Flask**:
    ```bash
    python app.py
    ```

3.  Abre tu navegador y ve a `http://127.0.0.1:5000`.

## Tabla de Rutas

| Ruta                   | Método(s) | Descripción                                       | Acceso    |
| ---------------------- | --------- | ------------------------------------------------- | --------- |
| `/`                    | `GET`     | Página principal con todas las herramientas.      | Público   |
| `/login`               | `GET,POST`| Página de inicio de sesión.                       | Público   |
| `/register`            | `GET,POST`| Página de registro de nuevos usuarios.            | Público   |
| `/logout`              | `GET`     | Cierra la sesión del usuario actual.              | Requiere Login |
| `/admin`               | `GET`     | Panel de administración.                          | Admin     |
| `/md-to-pdf`           | `GET`     | Herramienta de Markdown a PDF.                    | Público   |
| `/compress-pdf`        | `GET`     | Herramienta para comprimir PDF.                   | Público   |
| `/merge-pdf`           | `GET`     | Herramienta para combinar PDFs.                   | Público   |
| `/split-pdf`           | `GET`     | Herramienta para dividir PDF.                     | Público   |
| `/images-to-pdf`       | `GET`     | Herramienta para convertir imágenes a PDF.        | Público   |
| `/compress-image`      | `GET`     | Herramienta para comprimir imágenes.              | Público   |
| `/ip-whois`            | `GET`     | Herramienta de IP WHOIS.                          | Público   |
| `/blacklist-check`     | `GET`     | Herramienta de Blacklist Check.                   | Público   |
| `/ssl-check`           | `GET`     | Herramienta de SSL Check.                         | Público   |
| `/port-scanner`        | `GET`     | Herramienta de escáner de puertos.                | Público   |
| `/http-headers`        | `GET`     | Herramienta de cabeceras HTTP.                    | Público   |
| `/password-generator`  | `GET`     | Herramienta de generación de contraseñas.         | Público   |
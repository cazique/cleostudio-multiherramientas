from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

db = SQLAlchemy()

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

import unittest
from app import app, db

class AuthTestCase(unittest.TestCase):
    """
    Casos de prueba para la autenticación y el acceso público de la aplicación.
    """

    def setUp(self):
        """Configura un cliente de prueba y una base de datos de prueba."""
        app.config['TESTING'] = True
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        self.client = app.test_client()
        with app.app_context():
            db.create_all()

    def tearDown(self):
        """Limpia la base de datos después de cada prueba."""
        with app.app_context():
            db.session.remove()
            db.drop_all()

    def test_public_index_access(self):
        """Verifica que la página de inicio sea accesible sin iniciar sesión."""
        response = self.client.get('/', follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Herramientas', response.data)

    def test_public_tool_access(self):
        """Verifica que una página de herramienta sea accesible sin iniciar sesión."""
        response = self.client.get('/md-to-pdf', follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Markdown a PDF', response.data)

    def test_logout_requires_login(self):
        """Verifica que la ruta /logout redirija a la página de login si no se ha iniciado sesión."""
        response = self.client.get('/logout', follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Por favor inicia sesi\xc3\xb3n para acceder', response.data)

if __name__ == '__main__':
    unittest.main()
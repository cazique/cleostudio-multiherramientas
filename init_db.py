from app import app, db
from models import User

with app.app_context():
    db.drop_all()
    db.create_all()
    admin = User(username='admin', email='admin@multitools.com', is_admin=True)
    admin.set_password('admin123')
    db.session.add(admin)
    db.session.commit()
    print('✅ Base de datos creada!')
    print('Usuario: admin / Contraseña: admin123')

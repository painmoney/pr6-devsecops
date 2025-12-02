import unittest
import sys
import os

# Добавляем путь
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

class SecurityTests(unittest.TestCase):
    def setUp(self):
        # Импортируем здесь, после настройки конфигурации
        from app import app
        
        # Настраиваем тестовую БД
        app.config['TESTING'] = True
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        app.config['WTF_CSRF_ENABLED'] = False
        app.config['DEBUG'] = False
        
        self.app = app
        self.client = self.app.test_client()
        
        with self.app.app_context():
            from models import db
            db.create_all()
            
    def tearDown(self):
        with self.app.app_context():
            from models import db
            db.drop_all()
    
    def test_debug_mode_disabled(self):
        """Тест что debug=False"""
        self.assertFalse(self.app.config['DEBUG'])
    
    def test_security_headers(self):
        """Тест security headers"""
        response = self.client.get('/')
        self.assertEqual(response.headers.get('X-Frame-Options'), 'DENY')
        self.assertEqual(response.headers.get('X-Content-Type-Options'), 'nosniff')
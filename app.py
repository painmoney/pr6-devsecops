from flask import Flask, render_template, request, redirect, url_for, flash, session
from models import db, Note, User
from flask_wtf.csrf import CSRFProtect
from wtforms import StringField, TextAreaField, SubmitField
from wtforms.validators import DataRequired, Length
from flask_wtf import FlaskForm
import os
from dotenv import load_dotenv
from security_utils import hash_password, verify_password
from sqlalchemy import text  # ← ДОБАВЬТЕ ЭТОТ ИМПОРТ!

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key')

app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv(
    'SQLALCHEMY_DATABASE_URI', 
    'sqlite:///instance/database.db'  # fallback значение
)

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['DEBUG'] = os.getenv('FLASK_DEBUG', 'False').lower() == 'true'

db.init_app(app)
csrf = CSRFProtect(app)

app.config['WTF_CSRF_ENABLED'] = False 

# Форма для заметок
class NoteForm(FlaskForm):
    title = StringField('Заголовок', validators=[DataRequired(), Length(max=100)])
    content = TextAreaField('Содержание', validators=[DataRequired()])
    submit = SubmitField('Сохранить')

# Создаём таблицы при первом запуске
with app.app_context():
    db.create_all()
    # Проверяем есть ли admin пользователь
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        # Используем хэширование пароля!
        admin = User(username='admin', password=hash_password('admin123'))
        db.session.add(admin)
        db.session.commit()
        print("✅ Создан пользователь admin")

# Security Headers Middleware
@app.after_request
def set_security_headers(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self';"
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Server'] = 'Protected Server'
    if 'X-Powered-By' in response.headers:
        del response.headers['X-Powered-By']
    return response

# БЕЗОПАСНАЯ регистрация с хэшированием пароля
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        
        if not username or not password:
            flash('Все поля обязательны!')
            return redirect(url_for('register'))
        
        # Проверяем не существует ли пользователь
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Пользователь уже существует!')
            return redirect(url_for('register'))
        
        # Хэшируем пароль перед сохранением
        try:
            hashed_password = hash_password(password)
            user = User(username=username, password=hashed_password)
            db.session.add(user)
            db.session.commit()
            flash('Регистрация успешна! Теперь вы можете войти.')
        except Exception as e:
            flash(f'Ошибка: {str(e)}')
        
        return redirect(url_for('index'))
    
    return '''
    <h2>Регистрация (БЕЗОПАСНАЯ)</h2>
    <form method="POST">
        <input type="text" name="username" placeholder="Логин" required><br>
        <input type="password" name="password" placeholder="Пароль" required><br>
        <input type="submit" value="Зарегистрироваться">
    </form>
    <a href="/login">Войти</a>
    '''

# БЕЗОПАСНЫЙ логин с проверкой хэша
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        
        # БЕЗОПАСНЫЙ ЗАПРОС - параметризованный через SQLAlchemy ORM
        try:
            user = User.query.filter_by(username=username).first()
        except Exception as e:
            flash(f'Ошибка базы данных: {e}')
            user = None
        
        if user and verify_password(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            flash('Вход успешен!')
        else:
            flash('Неверный логин или пароль!')
        
        return redirect(url_for('index'))
    
    return '''
    <h2>Вход (БЕЗОПАСНЫЙ)</h2>
    <form method="POST">
        <input type="text" name="username" placeholder="Логин" required><br>
        <input type="password" name="password" placeholder="Пароль" required><br>
        <input type="submit" value="Войти">
    </form>
    <a href="/register">Регистрация</a>
    '''

# БЕЗОПАСНЫЙ эндпоинт для SQLMap
@app.route('/test-sql', methods=['GET', 'POST'])
def test_sql():
    if request.method == 'POST':
        user_input = request.form['input'].strip()
        
        # БЕЗОПАСНЫЙ ЗАПРОС - параметризованный
        try:
            user = User.query.filter_by(username=user_input).first()
            if user:
                return f"Результат: Пользователь найден - {user.username}"
            else:
                return "Результат: Пользователь не найден"
        except Exception as e:
            return f"Ошибка: {str(e)}"
    
    return '''
    <h3>Тест SQL-инъекций (БЕЗОПАСНЫЙ)</h3>
    <form method="POST">
        <input type="text" name="input" placeholder="Введите имя пользователя">
        <input type="submit" value="Тест">
    </form>
    <p>Попробуйте: admin' OR '1'='1 (должно НЕ сработать)</p>
    '''

# Добавим GET эндпоинт для тестирования
@app.route('/test-sql-get')
def test_sql_get():
    user_input = request.args.get('id', '1').strip()
    
    # БЕЗОПАСНЫЙ ЗАПРОС - параметризованный
    try:
        # Используем параметризованный запрос
        query = text("SELECT * FROM users WHERE id = :user_id")
        result = db.session.execute(query, {'user_id': user_input})
        users = result.fetchall()
        if users:
            return f"Результат: Найден пользователь с ID {user_input}"
        else:
            return f"Результат: Пользователь с ID {user_input} не найден"
    except Exception as e:
        return f"Ошибка: {str(e)}"

# Остальные эндпоинты
@app.route('/logout')
def logout():
    session.clear()
    flash('Вы вышли из системы')
    return redirect(url_for('index'))

@app.route('/')
def index():
    notes = []
    if 'user_id' in session:
        notes = Note.query.filter_by(user_id=session['user_id']).all()
    
    form = NoteForm()
    return render_template('index.html', notes=notes, form=form)

@app.route('/add', methods=['POST'])
def add_note():
    if 'user_id' not in session:
        flash('Необходима авторизация!')
        return redirect(url_for('login'))
    
    form = NoteForm()
    if form.validate_on_submit():
        note = Note(
            title=form.title.data.strip(),
            content=form.content.data.strip(),
            user_id=session['user_id']
        )
        db.session.add(note)
        db.session.commit()
        flash('Заметка добавлена!')
    return redirect(url_for('index'))

# ДЛЯ ДЕМОНСТРАЦИИ CI/CD
# Этот код вызовет ошибку в pipeline
app.debug = True  # Уязвимость: debug режим в production

# ОПАСНАЯ SQL-ИНЪЕКЦИЯ (HIGH severity)
import sqlite3
def dangerous_query(user_input):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    # SQL-инъекция
    query = f"SELECT * FROM users WHERE id = {user_input}" 
    cursor.execute(query)
    return cursor.fetchall()

# Хардкод пароля (для Bandit)
SECRET_KEY = "my_super_secret_password_123"  

if __name__ == '__main__':
    debug_mode = os.getenv('FLASK_DEBUG', 'False').lower() == 'true'
    host = '127.0.0.1'
    print(f"🚀 Запуск Flask приложения на {host}:5000")
    print(f"🔧 Debug режим: {debug_mode}")
    app.run(debug=debug_mode, host=host, port=5000)
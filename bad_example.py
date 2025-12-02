# Пример небезопасного кода, который будет заблокирован CI/CD
from flask import Flask, request
import sqlite3

# Уязвимость 1: debug=True в production (B105)
app = Flask(__name__)
app.debug = True  # Bandit: B105 - hardcoded_tmp_directory

# Уязвимость 2: SQL-инъекция (B608)
from flask import request
import sqlite3

def unsafe_query():
    user_input = request.args.get('id')
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    # ОПАСНО: прямая конкатенация строк
    query = f"SELECT * FROM users WHERE id = {user_input}"
    cursor.execute(query)  # Bandit: B608 - hardcoded_sql_expressions
    
    return cursor.fetchall()

# Уязвимость 3: Хардкод пароля (B105)
password = "super_secret_password_123"  # Bandit: B105 - hardcoded_password_string

# Уязвимость 4: Использование exec (B102)
user_code = request.args.get('code')
exec(user_code)  # Bandit: B102 - exec_used
from werkzeug.security import generate_password_hash, check_password_hash

def hash_password(password):
    """Хэширование пароля"""
    return generate_password_hash(password)

def verify_password(stored_hash, provided_password):
    """Проверка пароля"""
    return check_password_hash(stored_hash, provided_password)
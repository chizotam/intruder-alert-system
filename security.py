import re
from flask_bcrypt import Bcrypt

bcrypt = Bcrypt()

def hash_text(text):
    return bcrypt.generate_password_hash(text).decode('utf-8')

def check_hash(text, hashed):
    return bcrypt.check_password_hash(hashed, text)

def valid_pin(pin):
    # Only digits, max 6
    return pin.isdigit() and len(pin) <= 6

def valid_password(password):
    # Password must have at least one letter and one number, min 6 chars
    return bool(re.match(r'^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{6,}$', password))

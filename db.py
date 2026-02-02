import os
import psycopg2
from psycopg2.extras import RealDictCursor
import bcrypt

# PostgreSQL connection from Render environment
try:
    db = psycopg2.connect(
        host=os.environ["DB_HOST"],
        database=os.environ["DB_NAME"],
        user=os.environ["DB_USER"],
        password=os.environ["DB_PASS"],
        port=os.environ.get("DB_PORT", "5432")
    )
    cursor = db.cursor(cursor_factory=RealDictCursor)
    print("Connected to PostgreSQL database.")
except Exception as e:
    print("Error connecting to PostgreSQL:", e)
    exit()


def init_tables():
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS credentials (
        id SERIAL PRIMARY KEY,
        type VARCHAR(10),
        value_hash VARCHAR(255),
        question VARCHAR(255),
        answer_hash VARCHAR(255),
        email VARCHAR(255),
        blocked BOOLEAN DEFAULT FALSE
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS intruder_logs (
        id SERIAL PRIMARY KEY,
        action VARCHAR(255),
        ip VARCHAR(50),
        email VARCHAR(255),
        time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS user_devices (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) NOT NULL,
        device_id VARCHAR(255) NOT NULL,
        last_login TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(email, device_id)
    )
    """)

    db.commit()


#  LOG ACTIONS 
def log_action(action, ip, email):
    """
    Logs any action (login failed, intruder alert, login successful)
    """
    cursor.execute(
        "INSERT INTO intruder_logs (action, ip, email) VALUES (%s, %s, %s)",
        (action, ip, email)
    )
    db.commit()


#  PASSWORD / PIN HASHING 
def hash_text(text: str) -> str:
    """
    Returns a bcrypt hash of the given text
    """
    return bcrypt.hashpw(text.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')


def check_hash(text: str, hashed: str) -> bool:
    """
    Checks if the given text matches the hashed value
    """
    return bcrypt.checkpw(text.encode('utf-8'), hashed.encode('utf-8'))


#  VALIDATION 
def valid_pin(pin: str) -> bool:
    """
    Checks if pin is exactly 6 digits
    """
    return pin.isdigit() and len(pin) == 6


def valid_password(password: str) -> bool:
    """
    Checks if password is at least 6 chars and contains
    letters and numbers
    """
    if len(password) < 6:
        return False
    has_letter = any(c.isalpha() for c in password)
    has_digit = any(c.isdigit() for c in password)
    return has_letter and has_digit


#  USER BLOCKING 
def block_user(email: str):
    """
    Marks a user as blocked
    """
    cursor.execute("UPDATE credentials SET blocked=TRUE WHERE email=%s", (email,))
    db.commit()


def unblock_user(email: str):
    """
    Unblocks a user
    """
    cursor.execute("UPDATE credentials SET blocked=FALSE WHERE email=%s", (email,))
    db.commit()


#  INIT 
init_tables()

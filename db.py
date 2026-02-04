import os
import psycopg2
from psycopg2.extras import RealDictCursor
import bcrypt


def get_db():
    return psycopg2.connect(
        host=os.environ["DB_HOST"],
        database=os.environ["DB_NAME"],
        user=os.environ["DB_USER"],
        password=os.environ["DB_PASS"],
        port=os.environ.get("DB_PORT", "5432"),
        sslmode="require"
    )


def init_tables():
    try:
        db = get_db()
        cursor = db.cursor(cursor_factory=RealDictCursor)

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
        cursor.close()
        db.close()

    except Exception as e:
        print(f"[DB ERROR] init_tables failed: {e}")


# LOG ACTIONS
def log_action(action, ip, email=None):
    try:
        db = get_db()
        cursor = db.cursor(cursor_factory=RealDictCursor)

        cursor.execute(
            "INSERT INTO intruder_logs (action, ip, email) VALUES (%s, %s, %s)",
            (action, ip, email)
        )

        db.commit()
        cursor.close()
        db.close()

    except Exception as e:
        print(f"[DB ERROR] log_action failed: {e}")


# PASSWORD / PIN HASHING
def hash_text(text: str) -> str:
    return bcrypt.hashpw(text.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')


def check_hash(text: str, hashed: str) -> bool:
    return bcrypt.checkpw(text.encode('utf-8'), hashed.encode('utf-8'))


# VALIDATION
def valid_pin(pin: str) -> bool:
    return pin.isdigit() and len(pin) == 6


def valid_password(password: str) -> bool:
    if len(password) < 6:
        return False
    has_letter = any(c.isalpha() for c in password)
    has_digit = any(c.isdigit() for c in password)
    return has_letter and has_digit


# USER BLOCKING
def block_user(email: str):
    try:
        db = get_db()
        cursor = db.cursor(cursor_factory=RealDictCursor)

        cursor.execute("UPDATE credentials SET blocked=TRUE WHERE email=%s", (email,))
        db.commit()

        cursor.close()
        db.close()

    except Exception as e:
        print(f"[DB ERROR] block_user failed: {e}")


def unblock_user(email: str):
    try:
        db = get_db()
        cursor = db.cursor(cursor_factory=RealDictCursor)

        cursor.execute("UPDATE credentials SET blocked=FALSE WHERE email=%s", (email,))
        db.commit()

        cursor.close()
        db.close()

    except Exception as e:
        print(f"[DB ERROR] unblock_user failed: {e}")


# INIT
init_tables()

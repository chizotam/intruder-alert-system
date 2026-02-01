import mysql.connector
from mysql.connector import Error
from datetime import datetime
import bcrypt

#  DATABASE CONNECTION 
try:
    db = mysql.connector.connect(
        host="localhost",
        user="root",
        password="Tobechukwu1_",  
        database="access_control_streamlit"  
    )
    cursor = db.cursor(dictionary=True)
    print("Connected to MySQL database.")
except Error as e:
    print("Error connecting to MySQL:", e)
    exit()


#  TABLE CREATION 
def init_tables():
    # Credentials table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS credentials (
        id INT AUTO_INCREMENT PRIMARY KEY,
        type VARCHAR(10),
        value_hash VARCHAR(255),
        question VARCHAR(255),
        answer_hash VARCHAR(255),
        email VARCHAR(255),
        blocked BOOLEAN DEFAULT FALSE
    )
    """)
    
    # Intruder logs table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS intruder_logs (
        id INT AUTO_INCREMENT PRIMARY KEY,
        action VARCHAR(255),
        ip VARCHAR(50),
        email VARCHAR(255),
        time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)
    
    db.commit()


#  LOG ACTIONS 
def log_action(action, ip, email=None):
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

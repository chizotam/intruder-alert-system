from flask import Flask, render_template, request, redirect, session, flash, jsonify
from datetime import timedelta, datetime
from db import get_db, log_action, block_user, unblock_user
from security import hash_text, check_hash, valid_pin, valid_password, bcrypt
import threading
import time
import smtplib
from email.message import EmailMessage
import random
import re
import base64
import os
import hashlib
from urllib.parse import urlencode
from psycopg2.extras import RealDictCursor
import requests



app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY")
bcrypt.init_app(app)
app.permanent_session_lifetime = timedelta(minutes=5)

from flask import make_response

def get_or_create_device_id():
    device_id = request.cookies.get("device_id")
    if not device_id:
        # Generate new device ID (pseudo-random)
        ua = request.user_agent.string
        random_part = str(random.randint(100000, 999999))
        device_id = hashlib.sha256(f"{ua}-{random_part}".encode()).hexdigest()
    return device_id


# ---------------- DB HELPER ----------------
def query(sql, params=None, fetchone=False, fetchall=False, commit=False):
    db, cursor = get_db()
    cursor.execute(sql, params or ())
    result = None
    if fetchone:
        result = cursor.fetchone()
    if fetchall:
        result = cursor.fetchall()
    if commit:
        db.commit()
    return result
# -------------------------------------------

failed_attempts = {}
blocked_users = set()

#  EMAIL OTP CONFIG 
OTP_EXPIRY_SECONDS = 300  # 5 minutes
MAX_OTP_ATTEMPTS = 3


BREVO_API_KEY = os.environ.get("EMAIL_PASS")  # your Brevo API key
FROM_EMAIL = "a17f7b001@smtp-brevo.com"      # the verified sender email
FROM_NAME = "ZTECH"

def send_email(subject, body, to_emails, attachments=None):
    """Send email via Brevo API"""
    if isinstance(to_emails, str):
        to_emails = [to_emails]

    url = "https://api.brevo.com/v3/smtp/email"
    headers = {
        "accept": "application/json",
        "api-key": BREVO_API_KEY,
        "content-type": "application/json"
    }

    payload = {
        "sender": {"name": FROM_NAME, "email": FROM_EMAIL},
        "to": [{"email": e} for e in to_emails],
        "subject": subject,
        "textContent": body
    }

    # Add attachments if present
    if attachments:
        payload["attachment"] = []
        for att in attachments:
            payload["attachment"].append({
                "content": base64.b64encode(att['data']).decode(),
                "name": att['filename']
            })

    try:
        response = requests.post(url, json=payload, headers=headers, timeout=10)
        if response.status_code in (200, 201, 202):
            print(f"[INFO] Email sent to {to_emails}")
        else:
            print(f"[ERROR] Failed to send email: {response.status_code} {response.text}")
    except Exception as e:
        print(f"[ERROR] Exception while sending email: {e}")


def send_email_otp(target_email, otp_code):
    body = f"""
Hello,

You requested a credential reset. Your OTP is:

{otp_code}

It expires in 5 minutes. Do not share this OTP with anyone.

-ZSafe Security
"""
    send_email("ZSafe Credential Reset OTP", body, target_email)

def send_account_created_email(target_email):
    body = f"""
Hello,

An account has just been successfully created on ZSafe.

If this was not you, please secure your system immediately.

– ZSafe Security
"""
    send_email("ZSafe Account Created", body, target_email)




def send_intruder_email(image_base64, target_email, user_agent_string=None, ip_address=None):
    DEVELOPER_EMAIL = "chizotamubochi@gmail.com"
    body = f"""
SECURITY ALERT!

3 failed login attempts detected.

Time: {time.strftime('%Y-%m-%d %H:%M:%S')}
IP Address: {ip_address or 'Unknown'}

A photo of the intruder is attached.
"""

    attachments = []
    try:
        if "," in image_base64:
            _, encoded = image_base64.split(",", 1)
        else:
            encoded = image_base64
        image_data = base64.b64decode(encoded)
        attachments.append({
            'data': image_data,
            'filename': 'intruder.jpg'
        })
    except Exception as e:
        print(f"[ERROR] Failed to decode attachment: {e}")

    send_email("SECURITY ALERT: Intruder Detected", body, [target_email, DEVELOPER_EMAIL], attachments)




@app.route("/capture_intruder", methods=["POST"])
def capture_intruder():
    data = request.get_json()
    image_data = data.get("image")
    user_agent_string = request.user_agent.string
    ip_address = request.remote_addr

    # Use fresh DB connection
    db = get_db()
    cursor = db.cursor(cursor_factory=RealDictCursor)
    cursor.execute("SELECT email FROM credentials LIMIT 1")
    res = cursor.fetchone()
    user_email = res["email"] if res else os.environ.get("EMAIL_USER", "chizotamubochi@gmail.com")
    cursor.close()
    db.close()

    threading.Thread(
        target=send_intruder_email,
        args=(image_data, user_email, user_agent_string, ip_address),
        daemon=True
    ).start()

    return jsonify({"status": "Alert triggered"})



# NEW DEVICE DETECTION HELPERS

def generate_device_id():
    """Generate a pseudo-unique device ID based on user agent and some randomness"""
    ua = request.user_agent.string
    random_part = str(random.randint(100000, 999999))
    return hashlib.sha256(f"{ua}-{random_part}".encode()).hexdigest()

def is_known_device(email, device_id):
    """Check if the device is already registered"""
    try:
        db = get_db()
        cursor = db.cursor(cursor_factory=RealDictCursor)
        cursor.execute(
            "SELECT * FROM user_devices WHERE email=%s AND device_id=%s",
            (email, device_id)
        )
        result = cursor.fetchone()
        cursor.close()
        db.close()
        return result is not None
    except Exception as e:
        print(f"[DB ERROR] is_known_device failed: {e}")
        return False

def register_device(email, device_id):
    """Register a new device for a user"""
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute(
            "INSERT INTO user_devices (email, device_id) VALUES (%s, %s) ON CONFLICT DO NOTHING",
            (email, device_id)
        )
        db.commit()
        cursor.close()
        db.close()
    except Exception as e:
        print(f"[DB ERROR] register_device failed: {e}")

def send_new_device_email(target_email, token):
    DEVELOPER_EMAIL = "chizotamubochi@gmail.com"
    NOT_YOU_LINK = f"https://yourrenderapp.com/device_alert/{token}"
    body = f"""
Hello,

A login attempt from a new device was detected for your account.

If this was you, please verify the OTP sent to your email.

If this wasn't you, click here immediately to block your account and change your credential:

{NOT_YOU_LINK}

– ZSafe Security
"""
    send_email("New Device Login Attempt", body, [target_email, DEVELOPER_EMAIL])


#  INDEX 
@app.route("/")
def index():
    try:
        db = get_db()
        cursor = db.cursor(cursor_factory=RealDictCursor)
        cursor.execute("SELECT * FROM credentials LIMIT 1")
        user_exists = cursor.fetchone() is not None
        cursor.close()
        db.close()
    except Exception as e:
        print(f"[DB ERROR] index failed: {e}")
        user_exists = False

    if user_exists:
        return redirect("/login")
    return redirect("/setup")



#  SETUP 
@app.route("/setup", methods=["GET", "POST"])
def setup():
    if request.method == "POST":
        ctype = request.form["type"]
        value = request.form["value"]
        confirm = request.form["confirm"]
        email = request.form.get("email", "").strip()

        # --- Validations ---
        if value != confirm:
            flash("Values do not match", "danger")
            return redirect("/setup")
        if not email:
            flash("Email is required", "danger")
            return redirect("/setup")
        if ctype == "pin" and not valid_pin(value):
            flash("PIN must be 6 digits", "danger")
            return redirect("/setup")
        elif ctype == "password" and not valid_password(value):
            flash("Password must be alphanumeric with at least one number", "danger")
            return redirect("/setup")

        # --- DB operations ---
        try:
            db = get_db()
            cursor = db.cursor(cursor_factory=RealDictCursor)

            # Check if email already exists
            cursor.execute("SELECT * FROM credentials WHERE email=%s", (email,))
            if cursor.fetchone():
                cursor.close()
                db.close()
                flash("An account with this email already exists.", "warning")
                return redirect("/setup")

            # Insert the new account
            cursor.execute(
                "INSERT INTO credentials (type, value_hash, email) VALUES (%s,%s,%s)",
                (ctype, hash_text(value), email)
            )
            db.commit()
            cursor.close()
            db.close()

            # Send account created email in a separate thread
            threading.Thread(target=send_account_created_email, args=(email,), daemon=True).start()

            flash("Account created. Please login.", "success")
            return redirect("/login")

        except Exception as e:
            print(f"[DB ERROR] setup failed: {e}")
            flash("Something went wrong. Try again later.", "danger")
            return redirect("/setup")

    return render_template("app.html", page="setup")



@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        entered_email = request.form.get("email", "").strip()
        entered_cred = request.form.get("credential", "")
        ip = request.remote_addr

        # --- Step 1: Validate email format ---
        if not re.match(r"[^@]+@[^@]+\.[^@]+", entered_email):
            flash("Invalid email format", "warning")
            return redirect("/login")

        try:
            db = get_db()
            cursor = db.cursor(cursor_factory=RealDictCursor)

            # --- Step 2: Check if account exists ---
            cursor.execute("SELECT * FROM credentials WHERE email=%s LIMIT 1", (entered_email,))
            cred = cursor.fetchone()
            if not cred:
                cursor.close()
                db.close()
                flash("Email not registered", "warning")
                return redirect("/login")

            # --- Step 3: Check if user is blocked ---
            if entered_email in blocked_users:
                unblock_time = datetime.now() + timedelta(seconds=400)
                cursor.close()
                db.close()
                return render_template(
                    "app.html",
                    page="blocked",
                    email=entered_email,
                    unblock_timestamp=int(unblock_time.timestamp())
                )

            # --- Step 4: Check password/PIN ---
            if check_hash(entered_cred, cred["value_hash"]):
                failed_attempts[entered_email] = 0

                # -------- DEVICE DETECTION WITH COOKIE --------
                device_id = request.cookies.get("device_id")
                if not device_id:
                    ua = request.user_agent.string
                    random_part = str(random.randint(100000, 999999))
                    device_id = hashlib.sha256(f"{ua}-{random_part}".encode()).hexdigest()

                response = make_response()

                if not is_known_device(entered_email, device_id):
                    # New device detected → send OTP and alert email
                    otp_code = str(random.randint(100000, 999999))
                    session["otp_code"] = otp_code
                    session["otp_attempts"] = 0
                    session["otp_expires"] = (datetime.now() + timedelta(seconds=OTP_EXPIRY_SECONDS)).timestamp()
                    session["new_device_email"] = entered_email
                    session["pending_device_id"] = device_id

                    threading.Thread(target=send_email_otp, args=(entered_email, otp_code), daemon=True).start()
                    token = hashlib.sha256(f"{entered_email}-{time.time()}".encode()).hexdigest()
                    session["new_device_token"] = token
                    threading.Thread(target=send_new_device_email, args=(entered_email, token), daemon=True).start()

                    flash("New device detected. Verify OTP sent to your email.", "info")
                    response = redirect("/verify_otp")

                else:
                    # Known device → normal login
                    session["logged_in"] = True
                    session["user_email"] = entered_email
                    register_device(entered_email, device_id)
                    log_action(f"Login successful for {entered_email}", ip)
                    flash("Access granted", "success")
                    response = redirect("/home")

                # Set/refresh device cookie for 1 year
                response.set_cookie(
                    "device_id",
                    device_id,
                    max_age=60*60*24*365,  # 1 year
                    secure=True,            # HTTPS only
                    httponly=True,          # JS cannot access
                    samesite="Lax"
                )

                cursor.close()
                db.close()
                return response

            # --- Step 5: Wrong password/PIN ---
            failed_attempts[entered_email] = failed_attempts.get(entered_email, 0) + 1
            log_action(f"Login failed for {entered_email}", ip)
            cursor.close()
            db.close()

            if failed_attempts[entered_email] >= 3:
                blocked_users.add(entered_email)
                unblock_time = datetime.now() + timedelta(seconds=400)
                log_action(f"INTRUDER ALERT for {entered_email}", ip)

                def auto_unblock(user_email):
                    time.sleep(400)
                    if user_email in blocked_users:
                        blocked_users.remove(user_email)
                        failed_attempts[user_email] = 0

                threading.Thread(target=auto_unblock, args=(entered_email,), daemon=True).start()

                return render_template(
                    "app.html",
                    page="blocked",
                    email=entered_email,
                    unblock_timestamp=int(unblock_time.timestamp())
                )
            else:
                flash("Invalid password/PIN", "warning")

        except Exception as e:
            print(f"[DB ERROR] login failed: {e}")
            flash("Something went wrong. Try again later.", "danger")
            return redirect("/login")

    return render_template("app.html", page="login")




#  FORGOT PASSWORD 
@app.route("/forgot", methods=["GET", "POST"])
def forgot():
    try:
        db = get_db()
        cursor = db.cursor(cursor_factory=RealDictCursor)

        # Get the first account
        cursor.execute("SELECT * FROM credentials LIMIT 1")
        cred = cursor.fetchone()
        if not cred:
            cursor.close()
            db.close()
            return redirect("/setup")

        if request.method == "POST":
            # Clear previous OTP session data
            session.pop("otp_code", None)
            session.pop("otp_attempts", None)
            session.pop("otp_expires", None)

            email = cred["email"]
            otp_code = str(random.randint(100000, 999999))
            session["otp_code"] = otp_code
            session["otp_attempts"] = 0
            session["otp_expires"] = (datetime.now() + timedelta(seconds=OTP_EXPIRY_SECONDS)).timestamp()

            # Send OTP email in a background thread
            threading.Thread(target=send_email_otp, args=(email, otp_code), daemon=True).start()

            flash(f"OTP sent to your email ({email})", "info")
            cursor.close()
            db.close()
            return redirect("/verify_otp")

        cursor.close()
        db.close()
        return render_template("app.html", page="forgot")

    except Exception as e:
        print(f"[DB ERROR] forgot route failed: {e}")
        flash("An error occurred. Please try again.", "danger")
        return redirect("/login")

#VERIFY OTP
@app.route("/verify_otp", methods=["GET", "POST"])
def verify_otp():
    if request.method == "POST":
        entered_otp = request.form.get("otp")
        otp_code = session.get("otp_code")
        otp_attempts = session.get("otp_attempts", 0)

        if not otp_code:
            flash("OTP expired. Try logging in again.", "warning")
            return redirect("/login")

        if entered_otp == otp_code:
            session.pop("otp_code")
            session.pop("otp_attempts")
            session.pop("otp_expires")
            # mark device as known
            email = session.get("new_device_email")
            device_id = session.get("pending_device_id")
            if email and device_id:
                register_device(email, device_id)
                session["logged_in"] = True
                session["user_email"] = email
                flash("Device verified. Access granted.", "success")
                return redirect("/home")
        else:
            session["otp_attempts"] = otp_attempts + 1
            flash("Invalid OTP. Try again.", "danger")
            return redirect("/verify_otp")

    return render_template("app.html", page="verify_otp")



#  RESET CREDENTIAL 
@app.route("/reset_credential", methods=["GET", "POST"])
def reset_credential():
    if not session.get("reset_allowed"):
        return redirect("/login")

    try:
        db = get_db()
        cursor = db.cursor(cursor_factory=RealDictCursor)
        cursor.execute("SELECT * FROM credentials LIMIT 1")
        cred = cursor.fetchone()
        cursor.close()
        db.close()

        if not cred:
            flash("No account found. Please set up an account first.", "warning")
            return redirect("/setup")

        if request.method == "POST":
            ctype = request.form.get("type")
            value = request.form["value"]
            confirm = request.form["confirm"]

            if value != confirm:
                flash("Values do not match", "danger")
                return redirect("/reset_credential")

            if ctype == "pin" and not valid_pin(value):
                flash("PIN must be 6 digits", "danger")
                return redirect("/reset_credential")
            elif ctype == "password" and not valid_password(value):
                flash("Password must be alphanumeric with at least one number and letter", "danger")
                return redirect("/reset_credential")

            # Update the credentials
            db = get_db()
            cursor = db.cursor()
            cursor.execute(
                "UPDATE credentials SET type=%s, value_hash=%s",
                (ctype, hash_text(value))
            )
            db.commit()
            cursor.close()
            db.close()

            session.pop("reset_allowed")
            flash("Credential reset successful. Please login.", "success")
            return redirect("/login")

    except Exception as e:
        print(f"[DB ERROR] reset_credential route failed: {e}")
        flash("Something went wrong. Try again later.", "danger")
        return redirect("/login")

    return render_template("app.html", page="reset_credential", ctype=cred["type"])


#  HOME 
@app.route("/home")
def home():
    if not session.get("logged_in"):
        return redirect("/login")
    return render_template("app.html", page="home")

#  LOGS 
@app.route("/logs")
def logs():
    if not session.get("logged_in"):
        return redirect("/login")

    try:
        db = get_db()
        cursor = db.cursor(cursor_factory=RealDictCursor)
        cursor.execute("SELECT * FROM intruder_logs ORDER BY time DESC")
        logs_data = cursor.fetchall()
        cursor.close()
        db.close()
    except Exception as e:
        print(f"[DB ERROR] logs route failed: {e}")
        flash("Could not load logs. Try again later.", "danger")
        logs_data = []

    return render_template("app.html", page="logs", logs=logs_data)


#  RESET SYSTEM 
@app.route("/reset_system")
def reset_system():
    try:
        db = get_db()
        cursor = db.cursor()
        
        # Delete all credentials
        cursor.execute("DELETE FROM credentials")
        
        # Clear all intruder logs
        cursor.execute("TRUNCATE TABLE intruder_logs")
        
        db.commit()
        cursor.close()
        db.close()
        
        # Clear in-memory tracking
        blocked_users.clear()
        failed_attempts.clear()
        
        flash("System reset. Create a new account.", "info")
    except Exception as e:
        print(f"[DB ERROR] reset_system failed: {e}")
        flash("System reset failed. Try again later.", "danger")

    return redirect("/setup")


#  LOGOUT
@app.route("/logout")
def logout():
    session.clear()
    flash("System locked", "info")
    return redirect("/login")


# --------------------- NEW DEVICE ALERT ROUTE ---------------------
@app.route("/device_alert/<token>")
def device_alert(token):
    """Handle 'Not You' link clicked from new device email"""
    email = session.get("new_device_email")
    session_token = session.get("new_device_token")
    device_id = session.get("pending_device_id")

    if not email or not session_token or not device_id:
        flash("Invalid or expired device alert.", "warning")
        return redirect("/login")

    if token != session_token:
        flash("Invalid token.", "danger")
        return redirect("/login")

    # Block user and require password reset
    block_user(email)

    # Clear session info related to new device
    session.pop("new_device_email", None)
    session.pop("new_device_token", None)
    session.pop("pending_device_id", None)

    flash("Your account has been blocked due to suspicious login. Please reset your credential via email link.", "danger")
    return redirect("/login")
# --------------------- END NEW DEVICE ALERT ---------------------

@app.route("/not_you", methods=["POST"])
def not_you_action():
    action = request.form.get("action")
    email = session.get("new_device_email")
    device_id = session.get("pending_device_id")

    if action == "block" and email:
        block_user(email)
        flash("Your account has been blocked due to suspicious login.", "danger")
    elif action == "reset" and email:
        flash("Please reset your credential via the email sent to you.", "info")
        # optionally redirect to /forgot or /reset_credential
    # Clear session info
    session.pop("new_device_email", None)
    session.pop("pending_device_id", None)
    session.pop("new_device_token", None)

    return redirect("/login")


if __name__ == "__main__":
    app.run(debug=True, use_reloader=False)

from flask import Flask, render_template, request, redirect, session, flash, jsonify
from datetime import timedelta, datetime
from db import cursor, db, log_action
from security import hash_text, check_hash, valid_pin, valid_password, bcrypt
import threading
import time
import smtplib
from email.message import EmailMessage
import random
import re
import base64
import os


app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY")
bcrypt.init_app(app)
app.permanent_session_lifetime = timedelta(minutes=5)

failed_attempts = {}
blocked_users = set()

#  EMAIL OTP CONFIG 
OTP_EXPIRY_SECONDS = 300  # 5 minutes
MAX_OTP_ATTEMPTS = 3

def send_email_otp(target_email, otp_code):
    SENDER_EMAIL = os.environ["EMAIL_USER"]
    SENDER_PASS = os.environ["EMAIL_PASS"]
    msg = EmailMessage()
    msg['Subject'] = "Zsafe Credential Reset OTP"
    msg['From'] = SENDER_EMAIL
    msg['To'] = target_email
    msg.set_content(f"""
Hello,

You requested a credential reset. Your OTP is:

{otp_code}

It expires in 5 minutes. Do not share this OTP with anyone.

-Zsafe Security
""")
    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login(SENDER_EMAIL, SENDER_PASS)
            smtp.send_message(msg)
        print(f"[INFO] OTP sent to {target_email}")
    except Exception as e:
        print(f"[ERROR] Failed to send OTP: {e}")

#  ACCOUNT CREATED EMAIL
def send_account_created_email(target_email):
    SENDER_EMAIL = "chizotamubochi@gmail.com"
    SENDER_PASS = "bcxb qeaj oekt avmu"
    msg = EmailMessage()
    msg["Subject"] = "ZSafe Account Created"
    msg["From"] = SENDER_EMAIL
    msg["To"] = target_email
    msg.set_content(f"""
Hello,

An account has just been successfully created on ZSafe.

If this was not you, please secure your system immediately.

– ZSafe Security
""")
    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
            smtp.login(SENDER_EMAIL, SENDER_PASS)
            smtp.send_message(msg)
        print(f"[INFO] Account creation email sent to {target_email}")
    except Exception as e:
        print(f"[ERROR] Account email failed: {e}")

#  INTRUDER EMAIL (improved device & location detection)
def send_intruder_email(image_base64, target_email, user_agent_string=None, ip_address=None):
    DEVELOPER_EMAIL = "chizotamubochi@gmail.com"

 
    # --- EMAIL ---
    msg = EmailMessage()
    msg['Subject'] = "SECURITY ALERT: Intruder Detected"
    msg['From'] = target_email
    msg['To'] = [target_email, DEVELOPER_EMAIL]

    msg.set_content(f"""
SECURITY ALERT!

The system detected 3 failed login attempts.

Time: {time.strftime('%Y-%m-%d %H:%M:%S')}
IP Address: {ip_address or 'Unknown'}


A photo of the individual who tried to access the system is attached.
""")

    try:
        if "," in image_base64:
            _, encoded = image_base64.split(",", 1)
        else:
            encoded = image_base64

        image_data = base64.b64decode(encoded)
        msg.add_attachment(image_data, maintype='image', subtype='jpeg', filename='intruder.jpg')

        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login("chizotamubochi@gmail.com", "bcxb qeaj oekt avmu")
            smtp.send_message(msg)
        print(f"[SUCCESS] Intruder alert sent to {target_email}")
    except Exception as e:
        print(f"[ERROR] Email failed: {e}")


@app.route("/capture_intruder", methods=["POST"])
def capture_intruder():
    data = request.get_json()
    image_data = data.get("image")
    user_agent_string = request.user_agent.string
    ip_address = request.remote_addr

    cursor.execute("SELECT email FROM credentials LIMIT 1")
    res = cursor.fetchone()
    user_email = res["email"] if res else "chizotamubochi@gmail.com"

    threading.Thread(
        target=send_intruder_email,
        args=(image_data, user_email, user_agent_string, ip_address),
        daemon=True
    ).start()

    return jsonify({"status": "Alert triggered"})


#  INDEX 
@app.route("/")
def index():
    cursor.execute("SELECT * FROM credentials LIMIT 1")
    if cursor.fetchone():
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

        # Check if email already exists
        cursor.execute("SELECT * FROM credentials WHERE email=%s", (email,))
        if cursor.fetchone():
            flash("An account with this email already exists.", "warning")
            return redirect("/setup")

        # Insert the new account
        cursor.execute(
            "INSERT INTO credentials (type, value_hash, email) VALUES (%s,%s,%s)",
            (ctype, hash_text(value), email)
        )
        db.commit()

        threading.Thread(target=send_account_created_email, args=(email,), daemon=True).start()

        flash("Account created. Please login.", "success")
        return redirect("/login")

    return render_template("app.html", page="setup")




@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        entered_email = request.form.get("email", "").strip()
        entered_cred = request.form.get("credential", "")
        ip = request.remote_addr

        # --- Step 1: Check email format ---
        if not re.match(r"[^@]+@[^@]+\.[^@]+", entered_email):
            flash("Invalid email format", "warning")
            return redirect("/login")

        # --- Step 2: Check if account exists ---
        cursor.execute("SELECT * FROM credentials WHERE email=%s LIMIT 1", (entered_email,))
        cred = cursor.fetchone()
        if not cred:
            flash("Email not registered", "warning")
            return redirect("/login")

        # --- Step 3: Check if blocked ---
        if entered_email in blocked_users:
            unblock_time = datetime.now() + timedelta(seconds=400)
            return render_template(
                "app.html",
                page="blocked",
                email=entered_email,
                unblock_timestamp=int(unblock_time.timestamp())
            )

        # --- Step 4: Check password/PIN ---
        if check_hash(entered_cred, cred["value_hash"]):
            failed_attempts[entered_email] = 0
            session["logged_in"] = True
            session["user_email"] = entered_email
            log_action(f"Login successful for {entered_email}", ip)
            flash("Access granted", "success")
            return redirect("/home")

        # --- Step 5: Wrong password/PIN ---
        failed_attempts[entered_email] = failed_attempts.get(entered_email, 0) + 1
        log_action(f"Login failed for {entered_email}", ip)

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

    return render_template("app.html", page="login")


#  FORGOT PASSWORD 
@app.route("/forgot", methods=["GET", "POST"])
def forgot():
    cursor.execute("SELECT * FROM credentials LIMIT 1")
    cred = cursor.fetchone()
    if not cred:
        return redirect("/setup")

    if request.method == "POST":
        session.pop("otp_code", None)
        session.pop("otp_attempts", None)
        session.pop("otp_expires", None)
        email = cred["email"]
        otp_code = str(random.randint(100000, 999999))
        session["otp_code"] = otp_code
        session["otp_attempts"] = 0
        session["otp_expires"] = (datetime.now() + timedelta(seconds=OTP_EXPIRY_SECONDS)).timestamp()

        threading.Thread(target=send_email_otp, args=(email, otp_code), daemon=True).start()
        flash(f"OTP sent to your email ({email})", "info")
        return redirect("/verify_otp")

    return render_template("app.html", page="forgot")

#  VERIFY OTP 
@app.route("/verify_otp", methods=["GET", "POST"])
def verify_otp():
    cursor.execute("SELECT * FROM credentials LIMIT 1")
    cred = cursor.fetchone()
    if not cred:
        return redirect("/setup")

    if "otp_code" not in session:
        flash("Please request a reset first.", "warning")
        return redirect("/forgot")

    if request.method == "POST":
        entered = request.form["otp"].strip()
        session["otp_attempts"] += 1
        if session["otp_attempts"] > MAX_OTP_ATTEMPTS:
            session.pop("otp_code")
            flash("Max OTP attempts reached. Request a new OTP.", "danger")
            return redirect("/forgot")

        if entered == session["otp_code"]:
            if datetime.now().timestamp() > session["otp_expires"]:
                session.pop("otp_code")
                flash("OTP expired. Request a new one.", "danger")
                return redirect("/forgot")
            session.pop("otp_code")
            session.pop("otp_attempts")
            session.pop("otp_expires")
            session["reset_allowed"] = True
            flash("OTP verified. Set new credential.", "success")
            return redirect("/reset_credential")
        else:
            flash("Invalid OTP. Try again.", "warning")

    return render_template("app.html", page="verify_otp")

#  RESET CREDENTIAL 
@app.route("/reset_credential", methods=["GET", "POST"])
def reset_credential():
    if not session.get("reset_allowed"):
        return redirect("/login")

    cursor.execute("SELECT * FROM credentials LIMIT 1")
    cred = cursor.fetchone()

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

        cursor.execute(
            "UPDATE credentials SET type=%s, value_hash=%s",
            (ctype, hash_text(value))
        )
        db.commit()

        session.pop("reset_allowed")
        flash("Credential reset successful. Please login.", "success")
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
    cursor.execute("SELECT * FROM intruder_logs ORDER BY time DESC")
    logs = cursor.fetchall()
    return render_template("app.html", page="logs", logs=logs)

#  RESET SYSTEM 
@app.route("/reset_system")
def reset_system():
    cursor.execute("DELETE FROM credentials")
    cursor.execute("TRUNCATE TABLE intruder_logs")
    db.commit()
    blocked_users.clear()
    failed_attempts.clear()
    flash("System reset. Create a new account.", "info")
    return redirect("/setup")

#  LOGOUT
@app.route("/logout")
def logout():
    session.clear()
    flash("System locked", "info")
    return redirect("/login")


if __name__ == "__main__":
    app.run(debug=True, use_reloader=False)

from flask import Flask, render_template, request, redirect, url_for, session, flash
import mysql.connector
from werkzeug.security import generate_password_hash, check_password_hash
import random

app = Flask(__name__)
app.secret_key = "supersecretkey"

# MySQL Config
db = mysql.connector.connect(
    host="localhost",
    user="root",
    password="Nikitha@2004",
    database="login_system"
)
cursor = db.cursor(dictionary=True)

# ---------------- Routes ---------------- #

@app.route('/')
def home():
    if 'username' in session:
        return render_template("home.html", username=session['username'])
    return redirect(url_for("login"))

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == "POST":
        username = request.form['username']
        email = request.form['email']
        phone = request.form['phone']
        password = generate_password_hash(request.form['password'])

        cursor.execute("SELECT * FROM users WHERE username=%s OR email=%s OR phone=%s",
                       (username,email,phone))
        if cursor.fetchone():
            flash("User already exists!")
            return redirect(url_for("register"))

        cursor.execute("INSERT INTO users (username,email,phone,password) VALUES (%s,%s,%s,%s)",
                       (username,email,phone,password))
        db.commit()
        flash("Registered successfully! Please login.")
        return redirect(url_for("login"))

    return render_template("register.html")

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == "POST":
        username = request.form['username']
        password = request.form['password']

        cursor.execute("SELECT * FROM users WHERE username=%s",(username,))
        user = cursor.fetchone()
        if user and check_password_hash(user['password'], password):
            session['username'] = user['username']
            flash("Welcome back!")
            return redirect(url_for("home"))
        else:
            flash("Invalid credentials!")
            return redirect(url_for("login"))

    return render_template("login.html")

@app.route('/logout')
def logout():
    session.pop("username", None)
    flash("Logged out successfully.")
    return redirect(url_for("login"))

# ---------------- Forgot Password ---------------- #
otp_store = {}  # Temporary {email/phone: otp}

@app.route('/forgot_password', methods=['GET','POST'])
def forgot_password():
    if request.method == "POST":
        identifier = request.form['identifier']  # email or phone
        cursor.execute("SELECT * FROM users WHERE email=%s OR phone=%s", (identifier, identifier))
        user = cursor.fetchone()

        if user:
            otp = str(random.randint(1000, 9999))
            otp_store[identifier] = otp

            # 🔴 Debugging: Print OTP in terminal
            print(f"Generated OTP for {identifier}: {otp}")

            # 🔴 Debugging: Show OTP in flash message (remove later in production)
            flash(f"DEBUG: Your OTP is {otp}")

            # If you later want to send email:
            # send_otp_email(identifier, otp)

            return redirect(url_for("otp_verify", identifier=identifier))
        else:
            flash("No account found!")
            return redirect(url_for("forgot_password"))

    return render_template("forgot_password.html")

@app.route('/otp_verify/<identifier>', methods=['GET','POST'])
def otp_verify(identifier):
    if request.method == "POST":
        otp = request.form['otp']
        if otp_store.get(identifier) == otp:
            return redirect(url_for("reset_password", identifier=identifier))
        else:
            flash("Invalid OTP!")
            return redirect(url_for("otp_verify", identifier=identifier))

    return render_template("otp_verify.html", identifier=identifier)

@app.route('/reset_password/<identifier>', methods=['GET','POST'])
def reset_password(identifier):
    if request.method == "POST":
        new_pass = generate_password_hash(request.form['password'])
        cursor.execute("UPDATE users SET password=%s WHERE email=%s OR phone=%s", (new_pass,identifier,identifier))
        db.commit()
        otp_store.pop(identifier, None)
        flash("Password reset successful! Please login.")
        return redirect(url_for("login"))

    return render_template("reset_password.html")

if __name__ == "__main__":
    app.run(debug=True)

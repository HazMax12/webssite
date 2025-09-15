from flask import Flask, render_template, redirect, url_for, request, flash
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
from authlib.integrations.flask_client import OAuth
import sqlite3, os, re

app = Flask(__name__)
app.secret_key = "supersecretkey"
bcrypt = Bcrypt(app)

# --- LOGIN MANAGER ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# --- EMAIL SETTINGS ---
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = "officaloceanservice@gmail.com"
app.config['MAIL_PASSWORD'] = "your-app-password"
app.config['MAIL_DEFAULT_SENDER'] = ("No Reply", "officaloceanservice@gmail.com")
mail = Mail(app)

# --- DISCORD OAUTH ---
oauth = OAuth(app)
discord = oauth.register(
    name='discord',
    client_id='1417191646352904373',
    client_secret='8WW6jKe3jnrrYW_SdAMC_j7vU8O0M4gR',
    access_token_url='https://discord.com/api/oauth2/token',
    authorize_url='https://discord.com/api/oauth2/authorize',
    api_base_url='https://discord.com/api/',
    client_kwargs={'scope': 'identify email'}
)

# --- PASSWORD RESET TOKENS ---
serializer = URLSafeTimedSerializer(app.secret_key)

DB_NAME = "users.db"

# --- USER MODEL ---
class User(UserMixin):
    def __init__(self, id, email, username, password, discord_id=None):
        self.id = id
        self.email = email
        self.username = username
        self.password = password
        self.discord_id = discord_id

# --- DATABASE INIT ---
def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        username TEXT NOT NULL,
        password TEXT NOT NULL
    )
    """)
    cursor.execute("PRAGMA table_info(users)")
    columns = [info[1] for info in cursor.fetchall()]
    if "discord_id" not in columns:
        cursor.execute("ALTER TABLE users ADD COLUMN discord_id TEXT")
    conn.commit()
    conn.close()

# --- USER LOADER ---
@login_manager.user_loader
def load_user(user_id):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id=?", (user_id,))
    row = cursor.fetchone()
    conn.close()
    if row:
        discord_id = row[4] if len(row) > 4 else None
        return User(id=row[0], email=row[1], username=row[2], password=row[3], discord_id=discord_id)
    return None

# --- FORCE LOGOUT ON EVERY VISIT (EXCEPT LOGIN/REGISTER/FORGOT/HOME) ---
@app.before_request
def force_logout():
    if request.endpoint not in ("static", "login", "register", "forgot_password", "home"):
        logout_user()

# --- REGISTER ---
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form["email"]
        username = request.form["username"]
        password = request.form["password"]
        if len(password) < 6 or not re.search(r'\d', password) or not re.search(r'\W', password):
            flash("Password must be at least 6 characters, include a number and special character.", "danger")
            return render_template("register.html")
        hashed_pw = bcrypt.generate_password_hash(password).decode("utf-8")
        try:
            conn = sqlite3.connect(DB_NAME)
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (email, username, password, discord_id) VALUES (?, ?, ?, ?)",
                           (email, username, hashed_pw, None))
            conn.commit()
            conn.close()
            flash("Account created! Please login.", "success")
            return redirect(url_for("login"))
        except:
            flash("Email already exists!", "danger")
    return render_template("register.html")

# --- LOGIN ---
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email=?", (email,))
        row = cursor.fetchone()
        conn.close()
        if row and bcrypt.check_password_hash(row[3], password):
            discord_id = row[4] if len(row) > 4 else None
            user = User(id=row[0], email=row[1], username=row[2], password=row[3], discord_id=discord_id)
            login_user(user)
            flash("Login successful!", "success")
            return redirect(url_for("home"))
        else:
            flash("Invalid credentials!", "danger")
    return render_template("login.html")

# --- CONNECT DISCORD ---
@app.route("/connect-discord")
@login_required
def connect_discord():
    redirect_uri = url_for('discord_connect_callback', _external=True)
    return discord.authorize_redirect(redirect_uri)

@app.route("/connect-discord/callback")
@login_required
def discord_connect_callback():
    token = discord.authorize_access_token()
    user_data = discord.get('users/@me').json()
    discord_id = user_data['id']
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET discord_id=? WHERE id=?", (discord_id, current_user.id))
    conn.commit()
    conn.close()
    flash("Discord account connected successfully!", "success")
    return redirect(url_for("home"))

# --- FORGOT PASSWORD ---
@app.route("/forgot", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form["email"]
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email=?", (email,))
        row = cursor.fetchone()
        conn.close()
        if row:
            token = serializer.dumps(email, salt="password-reset-salt")
            reset_url = url_for("reset_password", token=token, _external=True)
            msg = Message("Password Reset Request", recipients=[email])
            msg.body = f"Click the link to reset your password: {reset_url}"
            mail.send(msg)
            flash("Reset link sent to your email! Check inbox or spam.", "info")
            return redirect(url_for("login"))
        else:
            flash("Email not found!", "danger")
    return render_template("forgot.html")

# --- RESET PASSWORD ---
@app.route("/reset/<token>", methods=["GET", "POST"])
def reset_password(token):
    try:
        email = serializer.loads(token, salt="password-reset-salt", max_age=3600)
    except:
        flash("The reset link is invalid or expired.", "danger")
        return redirect(url_for("forgot_password"))
    if request.method == "POST":
        new_password = request.form["password"]
        if len(new_password) < 6 or not re.search(r'\d', new_password) or not re.search(r'\W', new_password):
            flash("Password must be at least 6 characters, include a number and special character.", "danger")
            return render_template("reset.html")
        hashed_pw = bcrypt.generate_password_hash(new_password).decode("utf-8")
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET password=? WHERE email=?", (hashed_pw, email))
        conn.commit()
        conn.close()
        flash("Password reset successful! Please login.", "success")
        return redirect(url_for("login"))
    return render_template("reset.html")

# --- HOME ---
@app.route("/")
@login_required
def home():
    return render_template("home.html", username=current_user.username)

# --- LOGOUT ---
@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))

# --- RUN APP ---
if __name__ == "__main__":
    init_db()
    app.run(debug=True)

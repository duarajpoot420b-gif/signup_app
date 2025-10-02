from flask import Flask, render_template, request, redirect, url_for, flash, session
import sqlite3, os, datetime, functools
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", "change_this_secret")

DB_PATH = "database.db"

# ---------------- Database functions ----------------
def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fullname TEXT NOT NULL,
            userid TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TEXT,
            last_login TEXT,
            role TEXT DEFAULT 'user'
        )
    ''')
    conn.commit()
    conn.close()
    migrate_db()

def migrate_db():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("PRAGMA table_info(users)")
    cols = [row["name"] for row in c.fetchall()]
    wanted = {"created_at": "TEXT", "last_login": "TEXT", "role": "TEXT"}
    for col, ctype in wanted.items():
        if col not in cols:
            c.execute(f"ALTER TABLE users ADD COLUMN {col} {ctype}")
    conn.commit()
    conn.close()

# ---------------- Utilities ----------------
def login_required(route_fn):
    @functools.wraps(route_fn)
    def wrapper(*args, **kwargs):
        if "user" not in session:
            flash("Please login first.", "error")
            return redirect(url_for("login"))
        return route_fn(*args, **kwargs)
    return wrapper

def admin_required(route_fn):
    @functools.wraps(route_fn)
    def wrapper(*args, **kwargs):
        user = session.get("user")
        if not user or user.get("role") != "admin":
            flash("Admin access required.", "error")
            return redirect(url_for("index"))
        return route_fn(*args, **kwargs)
    return wrapper

# ---------------- Routes ----------------
@app.route("/")
def index():
    user = session.get("user")
    return render_template("index.html", username=(user["fullname"] if user else None))

# ---------- Signup ----------
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        fullname = request.form.get("fullname", "").strip()
        userid = request.form.get("userid", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        password2 = request.form.get("password2", "")

        if not (fullname and userid and email and password and password2):
            flash("Please fill all fields.", "error")
            return redirect(url_for("signup"))
        if password != password2:
            flash("Passwords do not match.", "error")
            return redirect(url_for("signup"))

        password_hash = generate_password_hash(password)
        created_at = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        try:
            conn = get_db_connection()
            c = conn.cursor()
            c.execute(
                "INSERT INTO users (fullname, userid, email, password_hash, created_at) VALUES (?, ?, ?, ?, ?)",
                (fullname, userid, email, password_hash, created_at)
            )
            conn.commit()
            conn.close()
            flash("Account created — please login.", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("User ID or Email already exists.", "error")
            return redirect(url_for("signup"))
    return render_template("signup.html")

# ---------- Login ----------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        userid = request.form.get("userid", "").strip()
        password = request.form.get("password", "")

        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE userid = ?", (userid,))
        user = c.fetchone()
        conn.close()

        if user and check_password_hash(user["password_hash"], password):
            last_login = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            conn = get_db_connection()
            c = conn.cursor()
            c.execute("UPDATE users SET last_login = ? WHERE userid = ?", (last_login, userid))
            conn.commit()
            conn.close()

            session["user"] = {"userid": user["userid"], "fullname": user["fullname"], "role": user["role"]}
            flash(f"Welcome, {user['fullname']}!", "success")

            if user["role"] == "admin":
                return redirect(url_for("admin_dashboard"))
            else:
                return redirect(url_for("dashboard"))
        else:
            flash("Invalid credentials.", "error")
            return redirect(url_for("login"))
    return render_template("login.html")

# ---------- Dashboard ----------
@app.route("/dashboard")
@login_required
def dashboard():
    user = session.get("user")
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT id, fullname, userid, email, created_at, last_login, role FROM users WHERE userid = ?", (user["userid"],))
    row = c.fetchone()
    conn.close()
    return render_template("dashboard.html", user=row)

# ---------- Logout ----------
@app.route("/logout")
def logout():
    session.pop("user", None)
    flash("Logged out.", "info")
    return redirect(url_for("index"))

# ---------- Reset Password ----------
@app.route("/reset_password", methods=["GET", "POST"])
def reset_password():
    if request.method == "POST":
        userid = request.form.get("userid", "").strip()
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not (userid and new_password and confirm_password):
            flash("Please fill all fields.", "error")
            return redirect(url_for("reset_password"))

        if new_password != confirm_password:
            flash("Passwords do not match.", "error")
            return redirect(url_for("reset_password"))

        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE userid = ?", (userid,))
        user = c.fetchone()

        if not user:
            flash("User ID not found.", "error")
            conn.close()
            return redirect(url_for("reset_password"))

        new_hash = generate_password_hash(new_password)
        c.execute("UPDATE users SET password_hash = ? WHERE userid = ?", (new_hash, userid))
        conn.commit()
        conn.close()

        flash("Password reset successful. Please login with your new password.", "success")
        return redirect(url_for("login"))

    return render_template("reset_password.html")

# ---------- Forgot Password ----------
@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        if not email:
            flash("Please enter your email.", "error")
            return redirect(url_for("forgot_password"))

        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE email = ?", (email,))
        user = c.fetchone()
        conn.close()

        if user:
            flash("Password reset instructions would be sent (feature pending).", "info")
        else:
            flash("Email not found.", "error")
        return redirect(url_for("login"))

    return render_template("forgot_password.html")
from datetime import datetime   # 👈 file ke top me import add kar lena

# ---------------- Admin ----------------
# ---------------- Admin ----------------
@app.route("/admin")
@admin_required
def admin_dashboard():
    conn = get_db_connection()
    c = conn.cursor()

    # Stats
    c.execute("SELECT COUNT(*) as total FROM users")
    total_users = c.fetchone()["total"]

    c.execute("SELECT COUNT(*) as total FROM users WHERE role='admin'")
    total_admins = c.fetchone()["total"]

    # All users list
    c.execute("SELECT id, fullname, userid, email, password_hash, role, created_at, last_login FROM users")
    users = c.fetchall()
    conn.close()

    return render_template(
        "admin_dashboard.html",
        total_users=total_users,
        total_admins=total_admins,
        users=users,
        now=datetime.now()
    )
# ---------------- Startup ----------------
if __name__ == "__main__":
    init_db()   # ensure db is initialized
    app.run(debug=True)
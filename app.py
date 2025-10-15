import os
from flask import Flask, render_template, request, redirect, flash,  url_for, session
import sqlite3, hashlib
app = Flask(__name__)
app.secret_key = "mysecretkey"

DB_NAME = "users.db"   


def get_db_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            gender TEXT NOT NULL,
            password TEXT NOT NULL,
            question TEXT NOT NULL,
            answer TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

UPLOAD_FOLDER = os.path.join('static', 'uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        gender = request.form.get('gender')
        password = request.form.get('password')
        question = request.form.get('question')
        answer = request.form.get('answer')
        print(name, email, gender, password, question, answer)


        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute('''
                INSERT INTO users (name, email, gender, password, question, answer)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (name, email, gender, hashed_password, question, answer))
            conn.commit()
            flash("Signup successful! Please login.", "success")
        except sqlite3.IntegrityError:
            flash("Email already exists!", "danger")
        conn.close()
        return redirect(url_for('login'))

    return render_template('signup.html')

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        conn = get_db_connection()
        user = conn.execute(
            "SELECT * FROM users WHERE email=? AND password=?",
            (email, hashed_password)
        ).fetchone()
        conn.close()

        if user:
            session["user_id"] = user["id"]
            session["email"] = user["email"]
            flash("Login successful!", "success")
            return redirect(url_for("profile"))
        else:
            flash("Invalid email or password", "danger")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))

@app.route("/profile")
def profile():
    if "user_id" not in session:
        flash("You must log in first", "warning")
        return redirect(url_for("login"))

    conn = get_db_connection()
    user = conn.execute(
        "SELECT * FROM users WHERE id=?",
        (session["user_id"],)
    ).fetchone()
    conn.close()

    return render_template("profile.html", user=user)


@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/home')
def home():
    return render_template('index.html')

@app.route('/feature')
def feature():
    return render_template('feature.html')

@app.route('/help')
def help():
    return render_template('help.html')

@app.route('/textsummaries')
def textsummaries():
    if "user_id" not in session:
        flash("Please login first!", "warning")
        return redirect(url_for("login"))
    return render_template('text_sum.html')

@app.route('/pdf_summaries')
def pdfsummaries():
    if "user_id" not in session:
        flash("Please login first!", "warning")
        return redirect(url_for("login"))
    return render_template('pdf_sum.html')

@app.route('/text_to_speech')
def text_to_speech():
    if "user_id" not in session:
        flash("Please login first!", "warning")
        return redirect(url_for("login"))
    return render_template('text_to_speech.html')

@app.route('/delete', methods=['GET', 'POST'])
def delete():

    if "user_id" in session:
        user_id = session["user_id"]
        conn = get_db_connection()
        conn.execute("DELETE FROM users WHERE id=?", (user_id,))
        conn.commit()
        conn.close()
        session.clear()
        flash("Your account has been deleted.", "info")
        return redirect(url_for("signup"))
    else:
        flash("You must be logged in to delete your account.", "warning")
        return redirect(url_for("login"))
    
@app.route('/forgot', methods=['GET', 'POST'])
def forgot():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        gender = request.form.get('gender')
        question = request.form.get('question')
        answer = request.form.get('answer')

        conn = get_db_connection()
        user = conn.execute("""
            SELECT * FROM users 
            WHERE name=? AND email=? AND gender=? AND question=? AND answer=?
        """, (name, email, gender, question, answer)).fetchone()
        conn.close()

        if user:
            # store verified user in session for reset
            session['reset_user_id'] = user['id']
            flash("Verification successful! Please reset your password.", "success")
            return redirect(url_for('reset_password'))
        else:
            flash("Invalid details. Please try again.", "danger")

    return render_template("forgot.html")


@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if 'reset_user_id' not in session:
        flash("Please verify your identity first.", "warning")
        return redirect(url_for('forgot'))

    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if new_password != confirm_password:
            flash("Passwords do not match!", "danger")
            return redirect(url_for('reset_password'))

        hashed_password = hashlib.sha256(new_password.encode()).hexdigest()

        conn = get_db_connection()
        conn.execute("UPDATE users SET password=? WHERE id=?", (hashed_password, session['reset_user_id']))
        conn.commit()
        conn.close()

        # clear session data
        session.pop('reset_user_id', None)
        flash("Password reset successful! Please login with your new password.", "success")
        return redirect(url_for('login'))

    return render_template('reset_password.html')




if __name__ == '__main__':
    init_db()
    app.run(debug=True)

import os
import sqlite3
import hashlib

from flask import (
    Flask, render_template, request, redirect, flash,
    url_for, session, jsonify, send_file
)

from transformers import pipeline
import torch
from werkzeug.utils import secure_filename
import PyPDF2
from reportlab.pdfgen import canvas as pdf_canvas
from reportlab.lib.pagesizes import A4
from io import BytesIO

# =========================
# Flask + DB CONFIG
# =========================

app = Flask(__name__, static_folder='static', template_folder='templates')
app.secret_key = "mysecretkey"

DB_NAME = "users.db"


def get_db_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Initialize the database and create the users table if it doesn't exist."""
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


# =========================
# UPLOAD CONFIG (for docs)
# =========================

DOC_UPLOAD_FOLDER = 'uploads'
os.makedirs(DOC_UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = DOC_UPLOAD_FOLDER

DOC_ALLOWED_EXTENSIONS = {'pdf', 'txt'}


def allowed_doc_file(filename):
    return (
        '.' in filename and
        filename.rsplit('.', 1)[1].lower() in DOC_ALLOWED_EXTENSIONS
    )


# =========================
# SUMMARIZER CONFIG (BART)
# =========================

# Use GPU if available
device = 0 if torch.cuda.is_available() else -1
print("Device set to use", "cuda" if device == 0 else "cpu")

# Initialize summarization pipeline (BART - facebook/bart-large-cnn)
summarizer = pipeline('summarization', model='facebook/bart-large-cnn', device=device)


def extract_text_from_pdf(path):
    text = []
    with open(path, 'rb') as f:
        reader = PyPDF2.PdfReader(f)
        for page in reader.pages:
            page_text = page.extract_text()
            if page_text:
                text.append(page_text)
    return '\n'.join(text)


def to_int(value, default):
    """Safely convert JSON values to int, handling dicts, None, etc."""
    try:
        if isinstance(value, dict):
            value = value.get("value", default)
        return int(value)
    except (TypeError, ValueError, AttributeError):
        return default


def generate_summary(text, max_length=150, min_length=40):
    """Core summarization logic, reused by /summarize and /textsummaries."""
    if not text or not text.strip():
        raise ValueError("No text provided.")

    # Safety: cap lengths
    max_length = to_int(max_length, 150)
    min_length = to_int(min_length, 40)

    max_length = min(max_length, 1024)
    min_length = max(min_length, 5)

    # For long texts, split into chunks to avoid model max tokens
    CHUNK_SIZE = 1000  # characters
    chunks = [text[i:i + CHUNK_SIZE] for i in range(0, len(text), CHUNK_SIZE)]

    summaries = []
    for chunk in chunks:
        out = summarizer(
            chunk,
            max_length=max_length,
            min_length=min_length,
            do_sample=False
        )
        summaries.append(out[0]['summary_text'].strip())

    # If there are multiple chunk summaries, join and summarize again (multi-stage)
    if len(summaries) > 1:
        joined = '\n'.join(summaries)
        try:
            final = summarizer(
                joined,
                max_length=max_length,
                min_length=min_length,
                do_sample=False
            )
            result = final[0]['summary_text'].strip()
        except Exception:
            # fallback: return concatenated chunk summaries
            result = '\n'.join(summaries)
    else:
        result = summaries[0]

    return result


# =========================
# BASIC ROUTES
# =========================

@app.route('/')
def index():
    # Your landing page template
    return render_template('index.html')


# =========================
# AUTH ROUTES
# =========================

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form.get('name', '').capitalize()
        email = request.form.get('email')
        gender = request.form.get('gender')
        password = request.form.get('password')
        question = request.form.get('question')
        answer = request.form.get('answer')

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
            return redirect(url_for("index"))
        else:
            flash("Invalid email or password", "danger")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("index"))


@app.route("/profile")
def profile():
    if 'user_id' not in session:
        flash("You must log in first", "warning")
        return redirect(url_for("login"))

    conn = get_db_connection()
    user = conn.execute(
        "SELECT * FROM users WHERE id=?",
        (session["user_id"],)
    ).fetchone()
    conn.close()

    return render_template("profile.html", user=user)


# =========================
# STATIC PAGES
# =========================

@app.route('/about')
def about():
    return render_template('about.html')


@app.route('/feature')
def feature():
    return render_template('feature.html')


@app.route('/help')
def help_page():
    return render_template('help.html')


# =========================
# FEATURE PAGES
# =========================

@app.route('/textsummaries')
def textsummaries():
    if "user_id" not in session:
        flash("Please login first!", "warning")
        return redirect(url_for("login"))

    return render_template('text_sum.html')


# TEXT SUMMERY
@app.route('/summarize-form', methods=['POST'])
def summarize_form():
    text = request.form.get('text')

    if not text:
        flash("Please enter text!", "warning")
        return redirect(url_for('textsummaries'))

    try:
        summary = generate_summary(text, max_length=150, min_length=40)
    except Exception as e:
        flash(f"Error: {e}", "danger")
        return redirect(url_for('textsummaries'))

    return render_template('text_result.html', summary=summary)

@app.route('/summarize', methods=['POST'])
def summarize():
    data = request.get_json(force=True, silent=True) or {}

    text = data.get('text', '')
    raw_max = data.get('max_length', 150)
    raw_min = data.get('min_length', 40)

    try:
        result = generate_summary(text, max_length=raw_max, min_length=raw_min)
    except ValueError:
        return jsonify({'error': 'No text provided.'}), 400
    except Exception as e:
        return jsonify({'error': f'Model error: {str(e)}'}), 500

    return jsonify({'summary': result})

# for PDF sum

@app.route('/pdf_summaries')
def pdfsummaries():
    if "user_id" not in session:
        flash("Please login first!", "warning")
        return redirect(url_for("login"))
    return render_template('pdf_sum.html')

@app.route('/pdf-summarize', methods=['POST'])
def pdf_summarize():
    if 'file' not in request.files:
        flash("No file uploaded!", "danger")
        return redirect(url_for('pdfsummaries'))

    file = request.files['file']

    if file.filename == '':
        flash("No file selected!", "warning")
        return redirect(url_for('pdfsummaries'))

    if file and allowed_doc_file(file.filename):
        filename = secure_filename(file.filename)
        path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(path)

        # Extract text
        text = extract_text_from_pdf(path)

        if not text.strip():
            flash("PDF me text nahi mila!", "warning")
            return redirect(url_for('pdfsummaries'))

        # Generate summary
        summary = generate_summary(text)

        # Save summary in session (temporary)
        session['pdf_summary'] = summary

        return render_template('pdf_result.html', summary=summary)

    else:
        flash("Only PDF allowed!", "danger")
        return redirect(url_for('pdfsummaries'))
    
@app.route('/download-summary')
def download_summary():
    summary = session.get('pdf_summary')

    if not summary:
        return "No summary available!"

    buffer = BytesIO()

    # ✅ FIX HERE
    p = pdf_canvas.Canvas(buffer, pagesize=A4)

    x = 50
    y = 800

    for line in summary.split('\n'):
        p.drawString(x, y, line)
        y -= 15
        if y < 50:
            p.showPage()
            y = 800

    p.save()
    buffer.seek(0)

    return send_file(buffer, as_attachment=True, download_name="summary.pdf", mimetype='application/pdf')


# For text To Speech 

@app.route('/text_to_speech')
def text_to_speech():
    if "user_id" not in session:
        flash("Please login first!", "warning")
        return redirect(url_for("login"))
    return render_template('text_to_speech.html')


# =========================
# ACCOUNT DELETE + FORGOT
# =========================

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
        conn.execute(
            "UPDATE users SET password=? WHERE id=?",
            (hashed_password, session['reset_user_id'])
        )
        conn.commit()
        conn.close()

        session.pop('reset_user_id', None)
        flash("Password reset successful! Please login with your new password.", "success")
        return redirect(url_for('login'))

    return render_template('reset_password.html')


# =========================
# API: TEXT SUMMARIZATION
# =========================



# =========================
# API: FILE UPLOAD (PDF/TXT)
# =========================

@app.route('/upload', methods=['POST'])
def upload_file():
    """
    Accept a file upload (pdf or txt), extract text, and return it as JSON.
    """
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    if file and allowed_doc_file(file.filename):
        filename = secure_filename(file.filename)
        save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(save_path)

        ext = filename.rsplit('.', 1)[1].lower()
        if ext == 'pdf':
            text = extract_text_from_pdf(save_path)
        else:
            with open(save_path, 'r', encoding='utf-8', errors='ignore') as f:
                text = f.read()

        return jsonify({'text': text})
    else:
        return jsonify({'error': 'File type not allowed (only pdf/txt).'}), 400


# =========================
# API: SUMMARY → PDF
# =========================

@app.route('/summary_pdf', methods=['POST'])
def summary_pdf():
    """
    Convert summary text into a downloadable PDF.
    Expects JSON: { "text": "summary text..." }
    """
    data = request.get_json(force=True, silent=True) or {}
    text = data.get('text', '').strip()
    if not text:
        return jsonify({'error': 'No summary text provided.'}), 400

    buffer = BytesIO()
    p = pdf_canvas(buffer, pagesize=A4)
    width, height = A4

    # Simple word-wrapping
    x_margin = 50
    y = height - 50
    max_chars = 90
    lines = []
    for paragraph in text.split('\n'):
        while len(paragraph) > max_chars:
            split_at = paragraph.rfind(' ', 0, max_chars)
            if split_at == -1:
                split_at = max_chars
            lines.append(paragraph[:split_at])
            paragraph = paragraph[split_at + 1:]
        lines.append(paragraph)

    for line in lines:
        if y < 50:  # new page
            p.showPage()
            y = height - 50
        p.drawString(x_margin, y, line)
        y -= 14

    p.showPage()
    p.save()
    buffer.seek(0)

    return send_file(
        buffer,
        as_attachment=True,
        download_name='summary.pdf',
        mimetype='application/pdf'
    )


# =========================
# MAIN
# =========================

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=7860, debug=True)

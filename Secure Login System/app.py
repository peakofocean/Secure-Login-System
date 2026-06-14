from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_bcrypt import Bcrypt
import sqlite3
import re
import os

app = Flask(__name__)
# In a real production environment, this should be an environment variable.
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(24))
bcrypt = Bcrypt(app)

# --- Database Setup ---
def init_db():
    conn = sqlite3.connect('secure_app.db')
    c = conn.cursor()
    # Create table if it doesn't exist
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# --- Helper Functions ---
def get_db_connection():
    conn = sqlite3.connect('secure_app.db')
    conn.row_factory = sqlite3.Row
    return conn

def validate_input(username, email, password):
    if not re.match(r"^[a-zA-Z0-9_]{3,20}$", username):
        return "Username must be 3-20 characters (letters, numbers, underscores)."
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        return "Invalid email format."
    if len(password) < 8:
        return "Password must be at least 8 characters long."
    return None

# --- Routes ---
@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        # 1. Input Validation
        error = validate_input(username, email, password)
        if error:
            flash(error, 'danger')
            return render_template('register.html')

        # 2. Hash Password (Bcrypt)
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        # 3. Database Insertion (Parameterized to prevent SQL Injection)
        try:
            conn = get_db_connection()
            conn.execute(
                'INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)',
                (username, email, hashed_password)
            )
            conn.commit()
            conn.close()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username or Email already exists.', 'danger')

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        # Parameterized query to fetch user safely
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()

        # 4. Verify Hash and Manage Session
        if user and bcrypt.check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.', 'danger')

    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    # Route Protection
    if 'user_id' not in session:
        flash('Please log in to access the dashboard.', 'warning')
        return redirect(url_for('login'))
    return render_template('dashboard.html', username=session['username'])

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
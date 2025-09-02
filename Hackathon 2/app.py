import os
import json
import requests
from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, jsonify
)
# app.py
from flask import Flask

# create a Flask instance
app = Flask(__name__)

@app.route('/')
def home():
    return "Hello, Flask is working!"

from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import mysql.connector

# Load environment variables from .env
load_dotenv('.env')

# ---------------- CONFIG ----------------
# These will read from .env but default to values you asked to include.
DB_HOST = os.getenv('DB_HOST', 'localhost')
DB_USER = os.getenv('DB_USER', 'root')
DB_PASSWORD = os.getenv('DB_PASSWORD', '1234')      # <- default included
DB_NAME = os.getenv('DB_NAME', 'flashcards_db')
SECRET_KEY = os.getenv('FLASK_SECRET_KEY', 'super_secret_change_me')
OPENAI_KEY = os.getenv('OPENAI_API_KEY', '')       # put your OpenAI key here
PAYSTACK_SECRET = os.getenv('PAYSTACK_SECRET_KEY', 'sk_test_8d0aef1193d25f3b62035f4c5d213f9fee1c875e')
FREE_DAILY_LIMIT = int(os.getenv('FREE_DAILY_LIMIT', '5'))
PREMIUM_PRICE_KES = int(os.getenv('PREMIUM_PRICE_KES', '500'))

app = Flask(__name__)
app.secret_key = SECRET_KEY

# Optional OpenAI (works only if you put a real key in .env)
try:
    import openai
    if OPENAI_KEY:
        openai.api_key = OPENAI_KEY
except Exception:
    openai = None

# ---------------- DB helper ----------------
def get_db():
    """
    Always pass DB_PASSWORD explicitly to avoid (using password: NO) errors.
    """
    return mysql.connector.connect(
        host=DB_HOST,
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME,
        autocommit=False
    )

def init_db_if_needed():
    """
    Create database & tables if they don't exist (safe to run repeatedly).
    """
    # Connect without specifying database to create it if needed
    conn = mysql.connector.connect(host=DB_HOST, user=DB_USER, password=DB_PASSWORD)
    cur = conn.cursor()
    cur.execute(f"CREATE DATABASE IF NOT EXISTS {DB_NAME}")
    conn.commit()
    cur.close()
    conn.close()

    # Now create tables inside the database
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(100) NOT NULL UNIQUE,
        email VARCHAR(200) NOT NULL UNIQUE,
        password_hash VARCHAR(255) NOT NULL,
        is_premium BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS flashcards (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        question TEXT NOT NULL,
        answer TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
    """)
    conn.commit()
    cur.close()
    conn.close()

# Initialize DB/tables at startup
init_db_if_needed()

# ---------------- Auth helpers ----------------
def current_user():
    uid = session.get('user_id')
    if not uid:
        return None
    conn = get_db()
    cur = conn.cursor(dictionary=True)
    cur.execute("SELECT id, username, email, is_premium FROM users WHERE id=%s", (uid,))
    user = cur.fetchone()
    cur.close(); conn.close()
    return user

# ---------------- AI helper ----------------
def ai_generate_flashcards(notes: str):
    """
    Use OpenAI if configured. Fall back to simple sentence split otherwise.
    Returns list of dicts: [{'question':..., 'answer':...}, ...]
    """
    notes = notes.strip()
    if not notes:
        return [{'question':'Empty notes','answer':'Please paste some notes'}]

    # Try OpenAI
    if openai and OPENAI_KEY:
        try:
            prompt = f"""
Turn the following study notes into 6 concise question-answer flashcards.
Return ONLY a valid JSON array like:
[{{"question":"...","answer":"..."}}, ...]

Notes:
{notes}
"""
            resp = openai.ChatCompletion.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role":"system","content":"You are a helpful assistant that returns ONLY JSON."},
                    {"role":"user","content":prompt}
                ],
                temperature=0.2,
                max_tokens=600
            )
            content = resp['choices'][0]['message']['content'].strip()
            # find JSON array in response
            start = content.find('[')
            end = content.rfind(']')
            if start != -1 and end != -1:
                data = json.loads(content[start:end+1])
                cards = []
                for it in data:
                    q = str(it.get('question','')).strip()
                    a = str(it.get('answer','')).strip()
                    if q and a:
                        cards.append({'question':q, 'answer':a})
                if cards:
                    return cards
        except Exception as e:
            print("OpenAI error, falling back:", e)

    # Fallback: naive splitting by sentences
    parts = [p.strip() for p in notes.replace('\n',' ').split('.') if p.strip()]
    cards = []
    for p in parts[:8]:
        q = "What is: " + (p[:80] + "..." if len(p) > 80 else p) + "?"
        a = p
        cards.append({'question': q, 'answer': a})
    if not cards:
        cards = [{'question':'What are the notes about?','answer':notes[:300]}]
    return cards

# ---------------- Routes ----------------
@app.route('/')
def home():
    user = current_user()
    return render_template('index.html', user=user, free_limit=FREE_DAILY_LIMIT)

@app.route('/signup', methods=['GET','POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username','').strip()
        email = request.form.get('email','').strip().lower()
        password = request.form.get('password','')
        if not username or not email or not password:
            flash('All fields are required', 'error')
            return redirect(url_for('signup'))
        pw_hash = generate_password_hash(password)
        try:
            conn = get_db()
            cur = conn.cursor()
            cur.execute("INSERT INTO users (username,email,password_hash) VALUES (%s,%s,%s)",
                        (username, email, pw_hash))
            conn.commit()
            uid = cur.lastrowid
            cur.close(); conn.close()
            session['user_id'] = uid
            session['user_email'] = email
            flash('Account created. You are logged in.', 'success')
            return redirect(url_for('dashboard'))
        except mysql.connector.Error as e:
            # common cause: duplicate username/email
            flash(f"Signup error: {e}", "error")
            return redirect(url_for('signup'))
    return render_template('signup.html')

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email','').strip().lower()
        password = request.form.get('password','')
        conn = get_db()
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT * FROM users WHERE email=%s", (email,))
        user = cur.fetchone()
        cur.close(); conn.close()
        if not user or not check_password_hash(user['password_hash'], password):
            flash('Invalid credentials', 'error')
            return redirect(url_for('login'))
        session['user_id'] = user['id']
        session['user_email'] = user['email']
        flash('Logged in', 'success')
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out', 'success')
    return redirect(url_for('home'))

@app.route('/generate', methods=['POST'])
def generate():
    user = current_user()
    if not user:
        flash('Login required to generate flashcards', 'error')
        return redirect(url_for('login'))

    # check free limit
    if not user['is_premium']:
        conn = get_db(); cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM flashcards WHERE user_id=%s AND DATE(created_at)=CURDATE()", (user['id'],))
        count = cur.fetchone()[0]
        cur.close(); conn.close()
        if count >= FREE_DAILY_LIMIT:
            flash(f'Free plan limit ({FREE_DAILY_LIMIT}/day) reached. Upgrade to premium.', 'error')
            return redirect(url_for('subscribe'))

    notes = request.form.get('notes','').strip()
    cards = ai_generate_flashcards(notes)

    # Save generated cards
    conn = get_db(); cur = conn.cursor()
    for c in cards:
        cur.execute("INSERT INTO flashcards (user_id, question, answer) VALUES (%s,%s,%s)",
                    (user['id'], c['question'], c['answer']))
    conn.commit(); cur.close(); conn.close()

    flash(f'{len(cards)} flashcards generated and saved', 'success')
    return redirect(url_for('dashboard'))

@app.route('/dashboard')
def dashboard():
    user = current_user()
    if not user:
        return redirect(url_for('login'))
    conn = get_db(); cur = conn.cursor(dictionary=True)
    cur.execute("SELECT id, question, answer, created_at FROM flashcards WHERE user_id=%s ORDER BY created_at DESC LIMIT 200", (user['id'],))
    cards = cur.fetchall(); cur.close(); conn.close()
    return render_template('dashboard.html', user=user, cards=cards)

@app.route('/subscribe')
def subscribe():
    user = current_user()
    if not user:
        return redirect(url_for('login'))
    return render_template('subscribe.html', user=user, price_kes=PREMIUM_PRICE_KES)

@app.route('/pay', methods=['POST'])
def pay():
    user = current_user()
    if not user:
        return redirect(url_for('login'))

    # Demo flow if paystack key missing
    if not PAYSTACK_SECRET:
        conn = get_db(); cur = conn.cursor()
        cur.execute("UPDATE users SET is_premium=1 WHERE id=%s", (user['id'],))
        conn.commit(); cur.close(); conn.close()
        flash('Demo upgrade done — you are now premium', 'success')
        return redirect(url_for('dashboard'))

    # Initialize Paystack transaction
    try:
        url = 'https://api.paystack.co/transaction/initialize'
        headers = {
            'Authorization': f'Bearer {PAYSTACK_SECRET}',
            'Content-Type': 'application/json'
        }
        payload = {
            'email': user['email'],
            'amount': PREMIUM_PRICE_KES * 100,
            'callback_url': url_for('payment_callback', _external=True),
            'currency': 'KES',
            'metadata': {'user_id': user['id']}
        }
        r = requests.post(url, headers=headers, json=payload, timeout=30)
        data = r.json()
        if not data.get('status'):
            flash('Paystack init failed: ' + str(data.get('message')), 'error')
            return redirect(url_for('subscribe'))
        return redirect(data['data']['authorization_url'])
    except Exception as e:
        flash('Paystack error: ' + str(e), 'error')
        return redirect(url_for('subscribe'))

@app.route('/payment/callback')
def payment_callback():
    reference = request.args.get('reference')
    if not reference:
        flash('Missing payment reference', 'error'); return redirect(url_for('subscribe'))
    try:
        url = f'https://api.paystack.co/transaction/verify/{reference}'
        headers = {'Authorization': f'Bearer {PAYSTACK_SECRET}'}
        r = requests.get(url, headers=headers, timeout=30)
        data = r.json()
        if data.get('status') and data['data'].get('status') == 'success':
            conn = get_db(); cur = conn.cursor()
            cur.execute("UPDATE users SET is_premium=1 WHERE id=%s", (session.get('user_id'),))
            conn.commit(); cur.close(); conn.close()
            flash('Payment verified — you are premium now', 'success')
            return redirect(url_for('dashboard'))
        flash('Payment not successful', 'error'); return redirect(url_for('subscribe'))
    except Exception as e:
        flash('Verification error: ' + str(e), 'error'); return redirect(url_for('subscribe'))

# ---------------- Error handlers ----------------
@app.errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404

# ---------------- Run ----------------
if __name__ == '__main__':
    app.run(debug=True)

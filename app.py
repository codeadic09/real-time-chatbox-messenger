from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from db import get_connection
from werkzeug.security import generate_password_hash, check_password_hash
import os
import secrets
import re
import bleach
from dotenv import load_dotenv
from functools import wraps

# Load environment variables
load_dotenv()

app = Flask(__name__)

# ============ SECURITY CONFIGURATION ============

# Secure secret key from environment
app.secret_key = os.getenv('SECRET_KEY', secrets.token_hex(32))

# Session security
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,  # No JavaScript access
    SESSION_COOKIE_SAMESITE='Lax',  # CSRF protection
    PERMANENT_SESSION_LIFETIME=1800,  # 30 minutes
)

# Cache control headers
@app.after_request
def add_security_headers(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, private'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response

# ============ VALIDATION FUNCTIONS ============

def validate_username(username):
    """Validate username: 3-20 chars, alphanumeric and underscore only"""
    if not username or len(username) < 3 or len(username) > 20:
        return False
    return bool(re.match(r'^[a-zA-Z0-9_]+$', username))

def validate_password(password):
    """Validate password: min 8 chars, includes uppercase, lowercase, digit"""
    if not password or len(password) < 8:
        return False
    if not re.search(r'[A-Z]', password):
        return False
    if not re.search(r'[a-z]', password):
        return False
    if not re.search(r'\d', password):
        return False
    return True

def sanitize_input(text, max_length=500):
    """Sanitize user input to prevent XSS"""
    if not text:
        return ""
    text = bleach.clean(text, tags=[], strip=True)
    return text[:max_length]

def login_required(f):
    """Decorator to protect routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login to access this page.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# ============ AUTHENTICATION ROUTES ============

@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = sanitize_input(request.form.get("username", ""))
        password = request.form.get("password", "")
        
        if not username or not password:
            flash("Username and password required.", "error")
            return render_template("login.html")
        
        try:
            db = get_connection()
            cursor = db.cursor(dictionary=True)
            cursor.execute(
                "SELECT id, username, password FROM users WHERE username=%s",
                (username,)
            )
            user = cursor.fetchone()
            cursor.close()
            db.close()
            
            if user and check_password_hash(user['password'], password):
                session.clear()  # Clear old session
                session['user_id'] = user['id']
                session['username'] = user['username']
                session.permanent = True
                flash("Login successful.", "success")
                return redirect(url_for("dashboard"))
            else:
                flash("Invalid username or password.", "error")
        except Exception as e:
            print(f"Login error: {e}")
            flash("Login failed. Please try again.", "error")
    
    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = sanitize_input(request.form.get("username", ""))
        password = request.form.get("password", "")
        
        # Validate inputs
        if not validate_username(username):
            flash("Username must be 3-20 characters (letters, numbers, underscore only).", "error")
            return render_template("register.html")
        
        if not validate_password(password):
            flash("Password must be 8+ characters with uppercase, lowercase, and digit.", "error")
            return render_template("register.html")
        
        try:
            db = get_connection()
            cursor = db.cursor()
            
            # Check if username exists
            cursor.execute("SELECT id FROM users WHERE username=%s", (username,))
            if cursor.fetchone():
                flash("Username already exists.", "error")
                cursor.close()
                db.close()
                return render_template("register.html")
            
            # Hash password securely
            hashed_password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)
            
            # Insert user
            cursor.execute(
                "INSERT INTO users (username, password) VALUES (%s, %s)",
                (username, hashed_password)
            )
            db.commit()
            
            # Get user ID
            cursor.execute("SELECT id FROM users WHERE username=%s", (username,))
            user_id = cursor.fetchone()[0]
            
            # Create empty profile
            cursor.execute(
                "INSERT INTO profiles (user_id, bio, city, skills) VALUES (%s, %s, %s, %s)",
                (user_id, "", "", "")
            )
            db.commit()
            cursor.close()
            db.close()
            
            flash("Registration successful. Please login.", "success")
            return redirect(url_for("login"))
            
        except Exception as e:
            print(f"Registration error: {e}")
            flash("Registration failed. Please try again.", "error")
    
    return render_template("register.html")

# ============ PROTECTED ROUTES ============

@app.route("/dashboard")
@login_required
def dashboard():
    try:
        db = get_connection()
        cursor = db.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT u.username, p.bio, p.city, p.skills
            FROM users u
            JOIN profiles p ON u.id = p.user_id
            WHERE u.id = %s
            """,
            (session['user_id'],)
        )
        profile = cursor.fetchone()
        cursor.close()
        db.close()
        return render_template("dashboard.html", profile=profile)
    except Exception as e:
        print(f"Dashboard error: {e}")
        flash("Error loading dashboard.", "error")
        return redirect(url_for("login"))

@app.route("/edit-profile", methods=["GET", "POST"])
@login_required
def edit_profile():
    db = get_connection()
    cursor = db.cursor(dictionary=True)
    
    if request.method == "POST":
        bio = sanitize_input(request.form.get("bio", ""), 500)
        city = sanitize_input(request.form.get("city", ""), 100)
        skills = sanitize_input(request.form.get("skills", ""), 200)
        
        try:
            cursor.execute(
                """
                UPDATE profiles
                SET bio=%s, city=%s, skills=%s
                WHERE user_id=%s
                """,
                (bio, city, skills, session['user_id'])
            )
            db.commit()
            cursor.close()
            db.close()
            flash("Profile updated successfully.", "success")
            return redirect(url_for("dashboard"))
        except Exception as e:
            print(f"Profile update error: {e}")
            flash("Update failed.", "error")
    
    # GET request
    cursor.execute(
        "SELECT bio, city, skills FROM profiles WHERE user_id=%s",
        (session['user_id'],)
    )
    profile = cursor.fetchone()
    cursor.close()
    db.close()
    return render_template("edit_profile.html", profile=profile)

@app.route("/search-users")
@login_required
def search_users():
    query = sanitize_input(request.args.get("q", ""), 50)
    if not query:
        return jsonify([])
    
    try:
        db = get_connection()
        cursor = db.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT id, username
            FROM users
            WHERE username LIKE %s
            AND id != %s
            LIMIT 10
            """,
            (f"%{query}%", session['user_id'])
        )
        users = cursor.fetchall()
        cursor.close()
        db.close()
        return jsonify(users)
    except Exception as e:
        print(f"Search error: {e}")
        return jsonify([])

@app.route("/search", methods=["GET", "POST"])
@login_required
def search_user():
    user = None
    if request.method == "POST":
        username = sanitize_input(request.form.get("username", ""))
        try:
            db = get_connection()
            cursor = db.cursor(dictionary=True)
            cursor.execute(
                "SELECT id, username FROM users WHERE username=%s",
                (username,)
            )
            user = cursor.fetchone()
            cursor.close()
            db.close()
            if not user:
                flash("User not found.", "error")
        except Exception as e:
            print(f"Search error: {e}")
            flash("Search failed.", "error")
    
    return render_template("search.html", user=user)

# ============ CHAT ROUTES ============

@app.route("/chat/<int:receiver_id>", methods=["GET", "POST"])
@login_required
def chat(receiver_id):
    try:
        db = get_connection()
        cursor = db.cursor(dictionary=True)
        
        # Mark messages as seen
        cursor.execute(
            """
            UPDATE messages
            SET seen = TRUE
            WHERE receiver_id = %s AND sender_id = %s
            """,
            (session['user_id'], receiver_id)
        )
        db.commit()
        
        if request.method == "POST":
            message = sanitize_input(request.form.get("message", ""), 1000)
            if message:
                cursor.execute(
                    "INSERT INTO messages (sender_id, receiver_id, message) VALUES (%s, %s, %s)",
                    (session['user_id'], receiver_id, message)
                )
                db.commit()
        
        cursor.execute(
            "SELECT id, username FROM users WHERE id=%s",
            (receiver_id,)
        )
        receiver = cursor.fetchone()
        cursor.close()
        db.close()
        
        if not receiver:
            flash("User not found.", "error")
            return redirect(url_for("dashboard"))
        
        return render_template("chat.html", receiver=receiver)
    except Exception as e:
        print(f"Chat error: {e}")
        flash("Error loading chat.", "error")
        return redirect(url_for("dashboard"))

@app.route("/messages/<int:receiver_id>")
@login_required
def get_messages(receiver_id):
    try:
        db = get_connection()
        cursor = db.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT m.message, u.username AS sender
            FROM messages m
            JOIN users u ON m.sender_id = u.id
            WHERE (m.sender_id=%s AND m.receiver_id=%s)
            OR (m.sender_id=%s AND m.receiver_id=%s)
            ORDER BY m.created_at
            """,
            (session['user_id'], receiver_id, receiver_id, session['user_id'])
        )
        messages = cursor.fetchall()
        cursor.close()
        db.close()
        return jsonify(messages)
    except Exception as e:
        print(f"Get messages error: {e}")
        return jsonify([])

@app.route("/notifications")
@login_required
def notifications():
    try:
        db = get_connection()
        cursor = db.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT
            u.id AS sender_id,
            u.username,
            COUNT(*) AS unread_count
            FROM messages m
            JOIN users u ON m.sender_id = u.id
            WHERE m.receiver_id = %s
            AND m.seen = FALSE
            GROUP BY m.sender_id
            """,
            (session['user_id'],)
        )
        data = cursor.fetchall()
        cursor.close()
        db.close()
        return jsonify(data)
    except Exception as e:
        print(f"Notifications error: {e}")
        return jsonify([])

@app.route("/delete-chat/<int:other_user_id>", methods=["POST"])
@login_required
def delete_chat(other_user_id):
    try:
        db = get_connection()
        cursor = db.cursor()
        cursor.execute(
            """
            DELETE FROM messages
            WHERE (sender_id=%s AND receiver_id=%s)
            OR (sender_id=%s AND receiver_id=%s)
            """,
            (session['user_id'], other_user_id, other_user_id, session['user_id'])
        )
        db.commit()
        cursor.close()
        db.close()
        flash("Chat cleared successfully.", "success")
    except Exception as e:
        print(f"Delete chat error: {e}")
        flash("Failed to delete chat.", "error")
    
    return redirect(url_for("chat", receiver_id=other_user_id))

@app.route("/delete-account", methods=["POST"])
@login_required
def delete_account():
    user_id = session['user_id']
    try:
        db = get_connection()
        cursor = db.cursor()
        
        # Delete in order (foreign key constraints)
        cursor.execute("DELETE FROM messages WHERE sender_id=%s OR receiver_id=%s", (user_id, user_id))
        cursor.execute("DELETE FROM profiles WHERE user_id=%s", (user_id,))
        cursor.execute("DELETE FROM users WHERE id=%s", (user_id,))
        
        db.commit()
        cursor.close()
        db.close()
        
        session.clear()
        flash("Account deleted successfully.", "success")
    except Exception as e:
        print(f"Delete account error: {e}")
        flash("Failed to delete account.", "error")
    
    return redirect(url_for("login"))

@app.route("/logout")
@login_required
def logout():
    session.clear()
    flash("You have been logged out successfully.", "success")
    return redirect(url_for("login"))

# ============ ERROR HANDLERS ============

@app.errorhandler(404)
def not_found(e):
    return render_template("login.html"), 404

@app.errorhandler(500)
def server_error(e):
    return "Internal server error", 500

if __name__ == "__main__":
    app.run(debug=True)

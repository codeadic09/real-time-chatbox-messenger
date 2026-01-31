from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from db import get_connection
import hashlib

from flask import jsonify

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()



app = Flask(__name__)
app.secret_key = "supersecretkey"

# ---------------- LOGIN ----------------
@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = hash_password(request.form["password"])

        try:
            db = get_connection()
            cursor = db.cursor()
            cursor.execute(
                "SELECT id, username FROM users WHERE username=%s AND password=%s",
                (username, password)
            )
            user = cursor.fetchone()
            db.close()

            if user:
                session["user_id"] = user[0]
                session["username"] = user[1]
                flash("Login successful.", "success")
                return redirect(url_for("dashboard"))
            else:
                flash("Invalid username or password.", "error")

        except Exception as e:
            flash("Login failed.", "error")
            print(e)

    return render_template("login.html")



# ---------------- REGISTER ----------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = hash_password(request.form["password"])

        db = get_connection()
        cursor = db.cursor()

        cursor.execute(
            "SELECT id FROM users WHERE username=%s",
            (username,)
        )
        if cursor.fetchone():
            flash("Username already exists.", "error")
            db.close()
            return render_template("register.html")

        # insert user
        cursor.execute(
            "INSERT INTO users (username, password) VALUES (%s, %s)",
            (username, password)
        )
        db.commit()

        # get user id
        cursor.execute(
            "SELECT id FROM users WHERE username=%s",
            (username,)
        )
        user_id = cursor.fetchone()[0]

        # create empty profile
        cursor.execute(
            "INSERT INTO profiles (user_id, bio, city, skills) VALUES (%s, %s, %s, %s)",
            (user_id, "", "", "")
        )
        db.commit()
        db.close()

        flash("Registration successful. Please login.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")



# ---------------- DASHBOARD ----------------
@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))

    db = get_connection()
    cursor = db.cursor(dictionary=True)

    cursor.execute(
        """
        SELECT u.username, p.bio, p.city, p.skills
        FROM users u
        JOIN profiles p ON u.id = p.user_id
        WHERE u.id = %s
        """,
        (session["user_id"],)
    )
    profile = cursor.fetchone()
    db.close()

    return render_template("dashboard.html", profile=profile)


# ---------------- EDIT PROFILE ----------------
@app.route("/edit-profile", methods=["GET", "POST"])
def edit_profile():
    if "user_id" not in session:
        return redirect(url_for("login"))

    db = get_connection()
    cursor = db.cursor(dictionary=True)

    if request.method == "POST":
        bio = request.form["bio"]
        city = request.form["city"]
        skills = request.form["skills"]

        cursor.execute(
            """
            UPDATE profiles
            SET bio=%s, city=%s, skills=%s
            WHERE user_id=%s
            """,
            (bio, city, skills, session["user_id"])
        )
        db.commit()
        db.close()

        flash("Profile updated successfully.", "success")
        return redirect(url_for("dashboard"))

    # GET request → load existing profile
    cursor.execute(
        "SELECT bio, city, skills FROM profiles WHERE user_id=%s",
        (session["user_id"],)
    )
    profile = cursor.fetchone()
    db.close()

    return render_template("edit_profile.html", profile=profile)

# ---------------- SEARCH USER ----------------
@app.route("/search", methods=["GET", "POST"])
def search_user():
    if "user_id" not in session:
        return redirect(url_for("login"))

    user = None

    if request.method == "POST":
        username = request.form["username"]

        db = get_connection()
        cursor = db.cursor(dictionary=True)
        cursor.execute(
            "SELECT id, username FROM users WHERE username=%s",
            (username,)
        )
        user = cursor.fetchone()
        db.close()

        if not user:
            flash("User not found.", "error")

    return render_template("search.html", user=user)

# ---------------- CHAT ----------------
@app.route("/chat/<int:receiver_id>", methods=["GET", "POST"])
def chat(receiver_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    db = get_connection()
    cursor = db.cursor(dictionary=True)


    # mark received messages as seen
    cursor.execute(
    """
    UPDATE messages
    SET seen = TRUE
    WHERE receiver_id = %s AND sender_id = %s
    """,
    (session["user_id"], receiver_id)
)
    db.commit()


    if request.method == "POST":
        message = request.form["message"]

        cursor.execute(
            "INSERT INTO messages (sender_id, receiver_id, message) VALUES (%s, %s, %s)",
            (session["user_id"], receiver_id, message)
        )
        db.commit()

    cursor.execute(
        "SELECT id, username FROM users WHERE id=%s",
        (receiver_id,)
    )
    receiver = cursor.fetchone()

    db.close()

    return render_template("chat.html", receiver=receiver)

# ---------------- FETCH NOTIFICATIONS (AJAX) ----------------
@app.route("/notifications")
def notifications():
    if "user_id" not in session:
        return jsonify([])

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
        (session["user_id"],)
    )

    data = cursor.fetchall()
    db.close()

    return jsonify(data)


# ---------------- DELETE CHAT ----------------
@app.route("/delete-chat/<int:other_user_id>", methods=["POST"])
def delete_chat(other_user_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    db = get_connection()
    cursor = db.cursor()

    cursor.execute(
        """
        DELETE FROM messages
        WHERE (sender_id=%s AND receiver_id=%s)
           OR (sender_id=%s AND receiver_id=%s)
        """,
        (session["user_id"], other_user_id,
         other_user_id, session["user_id"])
    )
    db.commit()
    db.close()

    # store message ONLY for chat page
    session["chat_cleared"] = True

    return redirect(url_for("chat", receiver_id=other_user_id))



# ---------------- FETCH MESSAGES (AJAX) ----------------
@app.route("/messages/<int:receiver_id>")
def get_messages(receiver_id):
    if "user_id" not in session:
        return jsonify([])

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
        (session["user_id"], receiver_id,
         receiver_id, session["user_id"])
    )

    messages = cursor.fetchall()
    db.close()

    return jsonify(messages)


# ---------------- DELETE MY ACCOUNT ----------------
@app.route("/delete-account", methods=["POST"])
def delete_account():
    if "user_id" not in session:
        return redirect(url_for("login"))

    user_id = session["user_id"]

    db = get_connection()
    cursor = db.cursor()

    # 1. delete messages (sent & received)
    cursor.execute(
        "DELETE FROM messages WHERE sender_id=%s OR receiver_id=%s",
        (user_id, user_id)
    )

    # 2. delete profile
    cursor.execute(
        "DELETE FROM profiles WHERE user_id=%s",
        (user_id,)
    )

    # 3. delete user
    cursor.execute(
        "DELETE FROM users WHERE id=%s",
        (user_id,)
    )

    db.commit()
    db.close()

    # 4. logout user
    session.clear()

    # 5. show message ONCE
    flash("Account deleted successfully.", "success")

    return redirect(url_for("login"))




# ---------------- LOGOUT ----------------
@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out successfully.", "success")
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(debug=True)

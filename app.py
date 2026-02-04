"""Disappearing Photo Sharing App - Main Flask Application."""

import base64
import os
import uuid
from datetime import datetime, timedelta
from functools import wraps

import psycopg2
from psycopg2.extras import RealDictCursor
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash,
    jsonify,
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import config

app = Flask(__name__)
app.secret_key = config.SECRET_KEY

# Rate limiter - prevent brute force attacks
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)


def get_db():
    """Get database connection."""
    conn = psycopg2.connect(config.DATABASE_URL, cursor_factory=RealDictCursor)
    return conn


def init_db():
    """Initialize database tables."""
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS photos (
            id VARCHAR(36) PRIMARY KEY,
            sender VARCHAR(50) NOT NULL,
            recipient VARCHAR(50) NOT NULL,
            nonce BYTEA NOT NULL,
            ciphertext BYTEA NOT NULL,
            media_type VARCHAR(50) NOT NULL,
            is_video BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            viewed_at TIMESTAMP NULL
        )
    """)
    conn.commit()
    cur.close()
    conn.close()


# Initialize database on startup
with app.app_context():
    init_db()


def encrypt_media(data: bytes) -> tuple[bytes, bytes]:
    """Encrypt media data with AES-256-GCM.

    Args:
        data: Raw media bytes to encrypt

    Returns:
        Tuple of (nonce, ciphertext)
    """
    key = base64.b64decode(config.ENCRYPTION_KEY)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # 96-bit nonce for GCM
    ciphertext = aesgcm.encrypt(nonce, data, None)
    return nonce, ciphertext


def decrypt_media(nonce: bytes, ciphertext: bytes) -> bytes:
    """Decrypt media data with AES-256-GCM.

    Args:
        nonce: The nonce used during encryption
        ciphertext: The encrypted data

    Returns:
        Decrypted media bytes
    """
    key = base64.b64decode(config.ENCRYPTION_KEY)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)


def cleanup_expired_photos():
    """Remove photos that have expired."""
    conn = get_db()
    cur = conn.cursor()

    # Delete photos that were viewed and view timeout has passed
    cur.execute("""
        DELETE FROM photos
        WHERE viewed_at IS NOT NULL
        AND viewed_at < NOW() - INTERVAL '%s seconds'
    """, (config.VIEW_TIMEOUT_SECONDS,))

    # Delete photos that are too old (unviewed)
    cur.execute("""
        DELETE FROM photos
        WHERE viewed_at IS NULL
        AND created_at < NOW() - INTERVAL '%s hours'
    """, (config.MAX_AGE_HOURS,))

    conn.commit()
    cur.close()
    conn.close()


def login_required(f):
    """Decorator to require login for routes."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "username" not in session:
            flash("Please log in to continue.", "error")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function


def get_other_user(current_user):
    """Get the other user's username."""
    users = config.get_usernames()
    for user in users:
        if user != current_user:
            return user
    return None


@app.before_request
def before_request():
    """Run cleanup before each request."""
    cleanup_expired_photos()


@app.route("/")
def index():
    """Home page - redirect to inbox if logged in, otherwise to login."""
    if "username" in session:
        return redirect(url_for("inbox"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute", methods=["POST"])  # Rate limit login attempts
def login():
    """Login page."""
    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")

        if config.verify_password(username, password):
            session["username"] = username
            flash(f"Welcome, {username}!", "success")
            return redirect(url_for("inbox"))
        else:
            flash("Invalid username or password.", "error")

    return render_template("login.html")


@app.route("/logout")
def logout():
    """Logout and clear session."""
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


@app.route("/inbox")
@login_required
def inbox():
    """Show received photos."""
    username = session["username"]

    conn = get_db()
    cur = conn.cursor()

    # Get photos sent to current user that haven't been viewed yet
    cur.execute("""
        SELECT id, sender, created_at as timestamp, is_video
        FROM photos
        WHERE recipient = %s AND viewed_at IS NULL
        ORDER BY created_at DESC
    """, (username,))

    user_photos = cur.fetchall()
    cur.close()
    conn.close()

    return render_template("inbox.html", photos=user_photos, username=username)


@app.route("/send", methods=["GET", "POST"])
@login_required
def send():
    """Send a photo or video to the other user."""
    username = session["username"]
    recipient = get_other_user(username)

    if request.method == "POST":
        if "media" not in request.files:
            flash("No file selected.", "error")
            return redirect(url_for("send"))

        file = request.files["media"]
        if file.filename == "":
            flash("No file selected.", "error")
            return redirect(url_for("send"))

        # Read the raw media data
        media_bytes = file.read()
        media_type = file.content_type or "image/jpeg"
        is_video = media_type.startswith("video/")

        # Encrypt the media
        nonce, ciphertext = encrypt_media(media_bytes)

        # Store in database
        photo_id = str(uuid.uuid4())
        conn = get_db()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO photos (id, sender, recipient, nonce, ciphertext, media_type, is_video)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (photo_id, username, recipient, nonce, ciphertext, media_type, is_video))
        conn.commit()
        cur.close()
        conn.close()

        flash(f"{'Video' if is_video else 'Photo'} sent to {recipient}!", "success")
        return redirect(url_for("inbox"))

    return render_template("send.html", recipient=recipient, username=username)


@app.route("/view/<photo_id>")
@login_required
def view_photo(photo_id):
    """View a specific photo."""
    username = session["username"]

    conn = get_db()
    cur = conn.cursor()

    # Get the photo
    cur.execute("SELECT * FROM photos WHERE id = %s", (photo_id,))
    photo = cur.fetchone()

    if not photo:
        cur.close()
        conn.close()
        flash("Photo not found or has expired.", "error")
        return redirect(url_for("inbox"))

    # Check if user is the recipient
    if photo["recipient"] != username:
        cur.close()
        conn.close()
        flash("You don't have permission to view this photo.", "error")
        return redirect(url_for("inbox"))

    # Mark as viewed if not already
    if photo["viewed_at"] is None:
        cur.execute("UPDATE photos SET viewed_at = NOW() WHERE id = %s", (photo_id,))
        conn.commit()

    cur.close()
    conn.close()

    # Decrypt the media for viewing
    try:
        decrypted_data = decrypt_media(bytes(photo["nonce"]), bytes(photo["ciphertext"]))
        media_data_uri = f"data:{photo['media_type']};base64,{base64.b64encode(decrypted_data).decode()}"
    except Exception as e:
        flash("Error decrypting media.", "error")
        return redirect(url_for("inbox"))

    # Create a temporary photo object for the template
    photo_for_template = {
        "sender": photo["sender"],
        "data": media_data_uri,
        "is_video": photo.get("is_video", False),
    }

    return render_template(
        "view.html",
        photo=photo_for_template,
        photo_id=photo_id,
        timeout=config.VIEW_TIMEOUT_SECONDS,
        username=username,
    )


@app.route("/api/delete/<photo_id>", methods=["POST"])
@login_required
def delete_photo(photo_id):
    """Delete a photo (called when timer expires)."""
    username = session["username"]

    conn = get_db()
    cur = conn.cursor()

    # Delete only if user is the recipient
    cur.execute("DELETE FROM photos WHERE id = %s AND recipient = %s", (photo_id, username))
    deleted = cur.rowcount > 0

    conn.commit()
    cur.close()
    conn.close()

    if deleted:
        return jsonify({"success": True})
    return jsonify({"success": False, "error": "Photo not found"})


@app.errorhandler(429)
def ratelimit_handler(e):
    """Handle rate limit exceeded."""
    flash("Too many login attempts. Please try again later.", "error")
    return render_template("login.html"), 429


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5050, use_reloader=False)

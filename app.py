"""Disappearing Photo Sharing App - Main Flask Application."""

import base64
import os
import uuid
from datetime import datetime, timedelta
from functools import wraps

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

# In-memory photo storage (encrypted)
# Structure: {photo_id: {sender, recipient, nonce, ciphertext, media_type, timestamp, viewed_at, is_video}}
photos = {}


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
    now = datetime.now()
    expired_ids = []

    for photo_id, photo in photos.items():
        # Check if photo was viewed and view timeout has passed
        if photo.get("viewed_at"):
            view_expiry = photo["viewed_at"] + timedelta(seconds=config.VIEW_TIMEOUT_SECONDS)
            if now > view_expiry:
                expired_ids.append(photo_id)
                continue

        # Check if photo is too old (unviewed)
        max_age_expiry = photo["timestamp"] + timedelta(hours=config.MAX_AGE_HOURS)
        if now > max_age_expiry:
            expired_ids.append(photo_id)

    for photo_id in expired_ids:
        del photos[photo_id]


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

    # Get photos sent to current user that haven't been viewed yet
    user_photos = []
    for photo_id, photo in photos.items():
        if photo["recipient"] == username and photo.get("viewed_at") is None:
            user_photos.append({
                "id": photo_id,
                "sender": photo["sender"],
                "timestamp": photo["timestamp"],
                "is_video": photo.get("is_video", False),
            })

    # Sort by newest first
    user_photos.sort(key=lambda x: x["timestamp"], reverse=True)

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

        # Create encrypted media entry
        photo_id = str(uuid.uuid4())
        photos[photo_id] = {
            "sender": username,
            "recipient": recipient,
            "nonce": nonce,
            "ciphertext": ciphertext,
            "media_type": media_type,
            "timestamp": datetime.now(),
            "viewed_at": None,
            "is_video": is_video,
        }

        flash(f"{'Video' if is_video else 'Photo'} sent to {recipient}!", "success")
        return redirect(url_for("inbox"))

    return render_template("send.html", recipient=recipient, username=username)


@app.route("/view/<photo_id>")
@login_required
def view_photo(photo_id):
    """View a specific photo."""
    username = session["username"]

    if photo_id not in photos:
        flash("Photo not found or has expired.", "error")
        return redirect(url_for("inbox"))

    photo = photos[photo_id]

    # Check if user is the recipient
    if photo["recipient"] != username:
        flash("You don't have permission to view this photo.", "error")
        return redirect(url_for("inbox"))

    # Mark as viewed if not already
    if photo["viewed_at"] is None:
        photo["viewed_at"] = datetime.now()

    # Decrypt the media for viewing
    try:
        decrypted_data = decrypt_media(photo["nonce"], photo["ciphertext"])
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

    if photo_id in photos:
        photo = photos[photo_id]
        if photo["recipient"] == username:
            del photos[photo_id]
            return jsonify({"success": True})

    return jsonify({"success": False, "error": "Photo not found"})


@app.errorhandler(429)
def ratelimit_handler(e):
    """Handle rate limit exceeded."""
    flash("Too many login attempts. Please try again later.", "error")
    return render_template("login.html"), 429


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5050, use_reloader=False)

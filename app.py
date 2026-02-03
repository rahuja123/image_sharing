"""Disappearing Photo Sharing App - Main Flask Application."""

import base64
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

import config

app = Flask(__name__)
app.secret_key = config.SECRET_KEY

# In-memory photo storage
# Structure: {photo_id: {sender, recipient, data, timestamp, viewed_at}}
photos = {}


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
    users = list(config.USERS.keys())
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
def login():
    """Login page."""
    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")

        if username in config.USERS and config.USERS[username] == password:
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

        # Read and encode the media
        media_data = base64.b64encode(file.read()).decode("utf-8")
        media_type = file.content_type or "image/jpeg"
        is_video = media_type.startswith("video/")

        # Create media entry
        photo_id = str(uuid.uuid4())
        photos[photo_id] = {
            "sender": username,
            "recipient": recipient,
            "data": f"data:{media_type};base64,{media_data}",
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

    return render_template(
        "view.html",
        photo=photo,
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


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5050, use_reloader=False)

"""Configuration for the disappearing photo sharing app."""

import os
import bcrypt

# Database URL (PostgreSQL)
# In production, set via environment variable (Render provides this automatically)
DATABASE_URL = os.environ.get("DATABASE_URL", "")

# Encryption key for AES-256-GCM (32 bytes, base64 encoded)
# In production, set via environment variable
ENCRYPTION_KEY = os.environ.get(
    "ENCRYPTION_KEY",
    "juPFe9OWbxazqDi+LfzJ0HB+bjSTcuX199Ci9wZXemY="
)

# User credentials with bcrypt hashed passwords
# Passwords are hashed with bcrypt - original password: peachpooch
_USERS = {
    os.environ.get("USER1_NAME", "rahul"): os.environ.get(
        "USER1_HASH",
        "$2b$12$tNOAJPQ2Lyw0tjzoplMgdeQ9Coozyywx2mC5ctPAwc96M1QBnXATK"
    ),
    os.environ.get("USER2_NAME", "ashwini"): os.environ.get(
        "USER2_HASH",
        "$2b$12$mPGDkHlTD1NRA68PGBXLseqlH2CDksAePHQP.3aUmRnK6Cf.4n8AS"
    ),
}


def verify_password(username: str, password: str) -> bool:
    """Verify a password against the stored bcrypt hash."""
    username = username.lower()
    if username not in _USERS:
        return False
    stored_hash = _USERS[username].encode()
    return bcrypt.checkpw(password.encode(), stored_hash)


def get_usernames() -> list:
    """Get list of valid usernames."""
    return list(_USERS.keys())


# Photo disappears this many seconds after being viewed
VIEW_TIMEOUT_SECONDS = int(os.environ.get("VIEW_TIMEOUT_SECONDS", 30))

# Unviewed photos expire after this many hours
MAX_AGE_HOURS = int(os.environ.get("MAX_AGE_HOURS", 24))

# Secret key for Flask sessions
SECRET_KEY = os.environ.get("SECRET_KEY", "your-secret-key-change-in-production")

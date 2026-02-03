"""Configuration for the disappearing photo sharing app."""

import os

# User credentials (username: password)
# In production, set these via environment variables for extra security
USERS = {
    os.environ.get("USER1_NAME", "rahul"): os.environ.get("USER1_PASS", "peachpooch"),
    os.environ.get("USER2_NAME", "ashwini"): os.environ.get("USER2_PASS", "peachpooch"),
}

# Photo disappears this many seconds after being viewed
VIEW_TIMEOUT_SECONDS = int(os.environ.get("VIEW_TIMEOUT_SECONDS", 30))

# Unviewed photos expire after this many hours
MAX_AGE_HOURS = int(os.environ.get("MAX_AGE_HOURS", 24))

# Secret key for Flask sessions
SECRET_KEY = os.environ.get("SECRET_KEY", "your-secret-key-change-in-production")

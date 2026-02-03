"""Gunicorn configuration for production."""

bind = "0.0.0.0:10000"
workers = 1  # Single worker to keep in-memory storage consistent
threads = 2
timeout = 120

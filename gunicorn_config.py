# gunicorn_config.py
workers = 2  # Start with 2, adjust based on your Render plan
worker_class = "gevent"  # Use async workers for Flask
bind = "0.0.0.0:5000"
timeout = 120  # Increase from default 30s
keepalive = 5  # Helps with connection reuse
max_requests = 1000  # Helps prevent memory leaks
max_requests_jitter = 50
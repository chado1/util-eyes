bind = "0.0.0.0:8000"
workers = 2  # Reduced for free tier
timeout = 120
worker_class = "sync"
# Use stdout/stderr for logging
accesslog = "-"  # stdout
errorlog = "-"   # stderr
capture_output = True
loglevel = "info"

bind = "0.0.0.0:8000"
workers = 3
timeout = 120
worker_class = "sync"
accesslog = "/var/log/gunicorn/access.log"
errorlog = "/var/log/gunicorn/error.log"

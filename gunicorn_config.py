"""Gunicorn configuration file for auth server"""


# Server socket
bind = "127.0.0.1:4000"
backlog = 2048

# Worker processes
workers = 8
worker_class = "sync"
worker_connections = 1000
timeout = 30
keepalive = 2

# Logging
accesslog = "/var/log/auth/access.log"
errorlog = "/var/log/auth/error.log"
loglevel = "info"
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s"'

# Process naming
proc_name = "auth-server"

# Server mechanics
daemon = False
pidfile = "/home/farshid/develop/auth/auth_server.pid"
user = None
group = None
tmp_upload_dir = None

# Load the app once in the master and fork workers from it, so the schema/table
# bootstrap in create_app() runs a single time instead of racing across workers.
preload_app = True


def post_fork(server, worker):
    # The SQLAlchemy engine/pool is created before the fork; dispose it so each
    # worker opens its own connections rather than sharing the master's sockets.
    from auth.database import engine

    engine.dispose()

# SSL (disabled for now, will use Nginx)
# keyfile = None
# certfile = None

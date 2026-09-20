"""Gunicorn configuration file for auth server"""


# Server socket
bind = "127.0.0.1:4000"
backlog = 2048

# Worker processes
#
# Eight sync workers, not two threaded ones. The problem #13 identified was the
# CONCURRENCY LIMIT -- two workers cap the service at two in-flight requests, so
# a merely slow database (commit stalls of 20-27s have been observed on the DB
# host) takes auth fully offline rather than making it slower. gthread fixed
# that and introduced a connection-level fault: from its first run, nginx logged
# "upstream prematurely closed connection" at roughly 0.28% of requests, with
# rt=0.000, against 1,766,168 requests and zero occurrences under sync. Adding
# processes raises the same limit without that behaviour.
#
# threads MUST stay 1. gunicorn's Config.worker_class resolves `sync` to
# gthread whenever threads > 1, silently, so leaving it at 8 would keep the
# thread pool while this file appeared to say otherwise. `Using worker: sync`
# in the startup log is the check.
#
# Cost: 8 processes at ~91 MB RSS (less in practice; preload_app shares pages
# copy-on-write) on an 8 GB host, and at most 32 database connections against
# max_connections=200.
workers = 8
worker_class = "sync"
threads = 1
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

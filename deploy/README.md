# Deployment reference files

These are reference copies of the production deployment configuration —
they are **not** part of the published `auth` package.

- `auth.service` — systemd unit (the live copy lives at
  `/etc/systemd/system/auth.service`; update it separately after changing
  this file, then `systemctl daemon-reload && systemctl restart auth`).
- `auth.rodmena.app.conf` — nginx vhost for the public endpoint.

Note: `gunicorn_config.py` intentionally stays at the repository root — the
live systemd unit runs gunicorn with `--config gunicorn_config.py` relative
to its `WorkingDirectory`, which is this repository.

#!/usr/bin/env python3
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from urllib.parse import quote

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _harness import Probe  # noqa: E402

IMAGE = os.environ.get("AUTH_TLS_PROBE_IMAGE", "postgres:16-alpine")
CLIENT_CN = "auth_tls"


def _run(*cmd, **kw):
    return subprocess.run(cmd, check=True, capture_output=True, text=True, **kw)


def _openssl_ca(d, name):
    key, crt = f"{d}/{name}.key", f"{d}/{name}.crt"
    _run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
         "-subj", f"/CN={name}", "-keyout", key, "-out", crt)
    return key, crt


def _openssl_leaf(d, name, cn, ca_key, ca_crt, san=None):
    key, csr, crt = f"{d}/{name}.key", f"{d}/{name}.csr", f"{d}/{name}.crt"
    _run("openssl", "req", "-newkey", "rsa:2048", "-nodes", "-subj", f"/CN={cn}",
         "-keyout", key, "-out", csr)
    cmd = ["openssl", "x509", "-req", "-in", csr, "-CA", ca_crt, "-CAkey", ca_key,
           "-CAcreateserial", "-days", "2", "-out", crt]
    if san:
        ext = f"{d}/{name}.ext"
        with open(ext, "w") as f:
            f.write(f"subjectAltName={san}\n")
        cmd += ["-extfile", ext]
    _run(*cmd)
    os.chmod(key, 0o600)
    return key, crt


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _start_server(d, port):
    with open(f"{d}/pg_hba.conf", "w") as f:
        f.write("local all all trust\nhostssl all all all cert\n")
    boot = (
        "mkdir -p /tls && cp /src/server.crt /src/server.key /src/ca.crt "
        "/src/pg_hba.conf /tls/ && chown -R postgres /tls && chmod 600 /tls/server.key "
        "&& exec docker-entrypoint.sh postgres -c ssl=on "
        "-c ssl_cert_file=/tls/server.crt -c ssl_key_file=/tls/server.key "
        "-c ssl_ca_file=/tls/ca.crt -c hba_file=/tls/pg_hba.conf"
    )
    name = f"auth-tls-probe-{os.getpid()}"
    _run("docker", "run", "-d", "--rm", "--name", name,
         "-e", f"POSTGRES_USER={CLIENT_CN}", "-e", "POSTGRES_PASSWORD=unused",
         "-e", "POSTGRES_DB=probe", "-v", f"{d}:/src:ro",
         "-p", f"127.0.0.1:{port}:5432", "--entrypoint", "sh", IMAGE, "-c", boot)
    return name


def _engine_for(url):
    from auth.database import DatabaseEngine

    return object.__new__(DatabaseEngine)._create_postgresql_engine(url)


def _attempt(url):
    from sqlalchemy import text

    engine = _engine_for(url)
    try:
        with engine.connect() as conn:
            row = conn.execute(
                text(
                    "SELECT ssl, client_dn, version FROM pg_stat_ssl "
                    "WHERE pid = pg_backend_pid()"
                )
            ).one()
            return True, tuple(row)
    except Exception as e:
        return False, str(getattr(e, "orig", e)).strip().splitlines()[0]
    finally:
        engine.dispose()


def _url(host, port, rootcert, cert, key, mode="verify-full"):
    q = f"sslmode={mode}&sslrootcert={quote(rootcert)}"
    if cert:
        q += f"&sslcert={quote(cert)}&sslkey={quote(key)}"
    return f"postgresql+psycopg://{CLIENT_CN}@{host}:{port}/probe?{q}"


def main():
    missing = [t for t in ("docker", "openssl") if not shutil.which(t)]
    if missing:
        print("== tls dsn params reach libpq")
        print(f"   SKIPPED: {', '.join(missing)} not on PATH. This is NOT a pass.")
        return 0

    d = tempfile.mkdtemp(prefix="auth-tls-probe-")
    os.chmod(d, 0o755)
    ca_key, ca_crt = _openssl_ca(d, "ca")
    _, rogue_crt = _openssl_ca(d, "rogue")
    srv_key, srv_crt = _openssl_leaf(d, "server", "localhost", ca_key, ca_crt,
                                     san="DNS:localhost")
    os.chmod(srv_key, 0o644)
    cli_key, cli_crt = _openssl_leaf(d, "client", CLIENT_CN, ca_key, ca_crt)

    sandbox = tempfile.mkdtemp(prefix="auth-tls-probe-db-")
    os.environ.update(
        AUTH_DATABASE_URL=f"sqlite:///{sandbox}/unused.db",
        AUTH_JWT_SECRET_KEY="probe-jwt-secret-not-for-production-0001",
        HOME=sandbox,
    )
    os.environ.pop("PGSSLMODE", None)

    port = _free_port()
    container = _start_server(d, port)
    good = _url("localhost", port, ca_crt, cli_crt, cli_key)
    try:
        deadline = time.monotonic() + 60
        ok, seen = _attempt(good)
        while not ok and time.monotonic() < deadline:
            time.sleep(1)
            ok, seen = _attempt(good)

        p = Probe(
            "tls dsn params reach libpq",
            "auth's engine factory drops or overrides sslmode/sslrootcert/"
            "sslcert/sslkey from the URL",
        )
        p.check(
            "verify-full with the right CA and client cert connects over TLS "
            f"as CN={CLIENT_CN}",
            ok and seen[0] is True and seen[1] == f"/CN={CLIENT_CN}",
            seen,
        )
        ok, seen = _attempt(_url("localhost", port, rogue_crt, cli_crt, cli_key))
        p.check("a foreign sslrootcert is enforced (refused)",
                not ok and "certificate verify failed" in seen, seen)
        ok, seen = _attempt(_url("127.0.0.1", port, ca_crt, cli_crt, cli_key))
        p.check("verify-full checks the host name (127.0.0.1 not in SAN, refused)",
                not ok and "does not match host name" in seen, seen)
        ok, seen = _attempt(_url("localhost", port, ca_crt, None, None))
        p.check("without sslcert/sslkey the server's cert-auth refuses",
                not ok and "certificate" in seen, seen)
        return p.done()
    finally:
        subprocess.run(["docker", "stop", container], capture_output=True)
        shutil.rmtree(d, ignore_errors=True)
        shutil.rmtree(sandbox, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())

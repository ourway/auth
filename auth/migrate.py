import importlib.util
import os
import subprocess
import sys
from pathlib import Path
from typing import List, Mapping, Optional

COMMANDS = ("apply", "status", "verify", "head", "list")
URL_VARIABLES = ("MG_DATABASE_URL", "AUTH_DATABASE_URL", "AUTH_POSTGRESQL_URL")
DRIVER_PREFIXES = ("postgresql+psycopg://", "postgres+psycopg://")
USAGE = (
    "usage: auth-migrate {apply,status,verify,head,list} [migretti options]\n"
    "Runs the migrations shipped with this auth release against the database "
    "named by the first of MG_DATABASE_URL, AUTH_DATABASE_URL or "
    "AUTH_POSTGRESQL_URL that is set."
)


def migrations_root() -> Path:
    return Path(__file__).resolve().parent


def database_url(environ: Mapping[str, str]) -> Optional[str]:
    for name in URL_VARIABLES:
        value = environ.get(name, "").strip()
        if not value:
            continue
        for prefix in DRIVER_PREFIXES:
            if value.startswith(prefix):
                return "postgresql://" + value[len(prefix) :]
        return value
    return None


def _refuse(message: str) -> int:
    print(f"auth-migrate: {message}", file=sys.stderr)
    return 2


def main(argv: Optional[List[str]] = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args or args[0] not in COMMANDS:
        print(USAGE, file=sys.stderr)
        return 2
    if importlib.util.find_spec("migretti") is None:
        return _refuse('migretti is not installed; install "auth[migrations]"')
    url = database_url(os.environ)
    if url is None:
        return _refuse("set MG_DATABASE_URL, AUTH_DATABASE_URL or AUTH_POSTGRESQL_URL")
    if not url.startswith(("postgresql://", "postgres://")):
        return _refuse("the shipped migrations target PostgreSQL only")
    environment = dict(os.environ, MG_DATABASE_URL=url)
    return subprocess.call(
        [sys.executable, "-m", "migretti", *args],
        cwd=migrations_root(),
        env=environment,
    )


if __name__ == "__main__":
    sys.exit(main())

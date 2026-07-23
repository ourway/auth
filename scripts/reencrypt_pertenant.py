#!/usr/bin/env python
"""Re-encrypt field-encrypted rows into the per-tenant (v2) format.

Each encrypted column is decrypted with whatever scheme it is currently in
(legacy global-key, already-v2, or never-encrypted plaintext) and rewritten
under the row's own tenant key, tagged ``v2:``. The pass is idempotent and
resumable — already-``v2:`` rows are skipped — so it is safe to re-run.

  RUN THIS IN A MAINTENANCE WINDOW, with the app stopped and after a DB backup.
  While rows are a mix of v1 and v2, an equality query only matches one form, so
  the service must not serve traffic mid-migration.

Usage (defaults to a dry run; pass --apply to write):
    AUTH_...=...  python -m scripts.reencrypt_pertenant            # preview
    AUTH_...=...  python -m scripts.reencrypt_pertenant --apply    # migrate
"""

import argparse
import logging
import sys
from typing import Dict, Optional

from sqlalchemy import select, update

from auth.config import get_settings
from auth.database import engine
from auth.encryption import (
    _V2_PREFIX,
    DeterministicEncryption,
    InvalidCiphertextError,
)
from auth.models.sql import AuthGroup, AuthMembership, AuthPermission

logger = logging.getLogger("auth.reencrypt")

# (table, table name, encrypted column name)
_TARGETS = [
    (AuthMembership.__table__, "auth_membership", "user"),
    (AuthPermission.__table__, "auth_permission", "name"),
    (AuthGroup.__table__, "auth_group", "description"),
]


def reencrypt_value(
    enc: DeterministicEncryption, stored: Optional[str], creator: str
) -> Optional[str]:
    """Return the v2 form of ``stored``, or ``None`` when there is nothing to do.

    Raises :class:`InvalidCiphertextError` if ``stored`` looks like ciphertext
    but does not authenticate (corrupt / wrong key) — the caller decides what to
    do rather than silently rewriting bad data.
    """
    if not stored or stored.startswith(_V2_PREFIX):
        return None  # empty or already migrated
    try:
        plaintext = enc.decrypt(stored, creator)  # legacy global-key path
    except InvalidCiphertextError:
        raise
    except ValueError:
        plaintext = stored  # legacy plaintext row (never encrypted)
    return enc.encrypt(plaintext, creator)


def _flush(table, column, pending) -> None:
    with engine.begin() as conn:
        for row_id, new_value in pending:
            conn.execute(
                update(table).where(table.c.id == row_id).values({column: new_value})
            )


def run(dry_run: bool = True, batch_size: int = 500) -> Dict[str, int]:
    settings = get_settings()
    if not (settings.enable_encryption and settings.encryption_key):
        logger.error("Encryption is not enabled/configured; nothing to migrate.")
        return {"migrated": 0, "skipped": 0, "corrupt": 0}

    enc = DeterministicEncryption(settings.encryption_key)
    stats = {"migrated": 0, "skipped": 0, "corrupt": 0}

    for table, table_name, column in _TARGETS:
        with engine.connect() as conn:
            rows = conn.execute(
                select(table.c.id, table.c.creator, table.c[column])
            ).fetchall()

        pending = []
        for row_id, creator, value in rows:
            try:
                new_value = reencrypt_value(enc, value, creator)
            except InvalidCiphertextError:
                stats["corrupt"] += 1
                logger.error(
                    "CORRUPT %s.%s id=%s creator=%s does not authenticate; left as-is",
                    table_name,
                    column,
                    row_id,
                    creator,
                )
                continue
            if new_value is None:
                stats["skipped"] += 1
                continue
            pending.append((row_id, new_value))
            stats["migrated"] += 1
            if not dry_run and len(pending) >= batch_size:
                _flush(table, column, pending)
                pending = []
        if not dry_run and pending:
            _flush(table, column, pending)
        logger.info("%s.%s scanned (%d rows)", table_name, column, len(rows))

    return stats


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--apply",
        action="store_true",
        help="actually write changes (default is a dry run / preview)",
    )
    parser.add_argument("--batch-size", type=int, default=500)
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    dry_run = not args.apply
    if dry_run:
        logger.info("DRY RUN — no changes will be written. Re-run with --apply.")
    stats = run(dry_run=dry_run, batch_size=args.batch_size)
    logger.info(
        "%s: migrated=%d skipped=%d corrupt=%d",
        "would migrate" if dry_run else "migrated",
        stats["migrated"],
        stats["skipped"],
        stats["corrupt"],
    )
    return 1 if stats["corrupt"] else 0


if __name__ == "__main__":
    sys.exit(main())

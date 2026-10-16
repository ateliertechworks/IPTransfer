"""Command-line maintenance tools.

``python -m universal_p2p_sync db-upgrade --app-id echo``
    Create or upgrade the application's sync schema (normally done on start).
``python -m universal_p2p_sync identity --app-id echo``
    Show (creating if needed) this device's ID and fingerprint.

The database URL comes from ``--database-url`` or ``UP2P_<APP>_DATABASE_URL`` /
``UP2P_DATABASE_URL``, so passwords need not appear on the command line.
"""

from __future__ import annotations

import argparse
import os
import sys

from .config import validate_app_id
from .crypto import DeviceIdentity, identity_directory
from .errors import P2PSyncError


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m universal_p2p_sync")
    sub = parser.add_subparsers(dest="command", required=True)
    up = sub.add_parser("db-upgrade", help="create/upgrade the sync schema")
    up.add_argument("--app-id", required=True)
    up.add_argument("--database-url")
    up.add_argument("--schema", help="default: up2p_<app_id>")
    ident = sub.add_parser("identity", help="show this device's identity")
    ident.add_argument("--app-id", required=True)
    ident.add_argument("--data-dir")
    args = parser.parse_args(argv)
    try:
        app_id = validate_app_id(args.app_id)
        if args.command == "db-upgrade":
            from .storage.database import Database, run_migrations

            url = (
                args.database_url
                or os.environ.get(f"UP2P_{app_id.upper()}_DATABASE_URL")
                or os.environ.get("UP2P_DATABASE_URL")
            )
            if not url:
                parser.error("--database-url or UP2P_DATABASE_URL is required")
            schema = args.schema or f"up2p_{app_id}"
            db = Database(url, schema)
            try:
                run_migrations(db._raw_engine, schema)
            finally:
                db.close()
            print(f"schema {schema!r} is up to date")
        else:
            passphrase = os.environ.get(f"UP2P_{app_id.upper()}_KEY_PASSPHRASE") or os.environ.get(
                "UP2P_KEY_PASSPHRASE"
            )
            identity = DeviceIdentity.load_or_create(
                identity_directory(args.data_dir, app_id), passphrase
            )
            print(f"device id:   {identity.device_id}")
            print(f"fingerprint: {identity.fingerprint}")
            print(f"key files:   {identity.directory}")
    except P2PSyncError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

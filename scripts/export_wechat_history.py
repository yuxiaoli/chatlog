# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "duckdb>=1.2.0",
#     "pycryptodome==3.23.0",
#     "pyarrow>=17.0.0",
# ]
# ///

"""Load staged WeChat SQLite databases into one auditable DuckDB file.

The companion staging script owns account discovery and decryption.  This
loader deliberately accepts only a key-free manifest and never stores or logs
WeChat database/image keys.

Normalized contacts are written to ``chatlog.contacts``.  The short display
name remains ``remark`` while the longer profile note is exported separately
as ``description``.  Verified Windows-v3 ``ExtraBuf`` profile fields are
decoded into ``signature``, raw ``add_scene``, ``add_scene_enum``,
``add_scene_string``, ``country``, and ``city`` while the verified
state/province field is exposed separately as ``province`` and the raw blob
remains available in the raw table.  Windows-v3 label definitions and
ordered contact-label assignments are preserved in
``chatlog.contact_tag_definitions`` and ``chatlog.contact_tags`` respectively.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sqlite3
import sys
import uuid
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Sequence

import duckdb

from duckdb_bulk import insert_batch
from wechat_backup_archive import BackupArchiveError, iter_backup_segments


CATALOG_SCHEMA = "export_catalog"
CHATLOG_SCHEMA = "chatlog"
STAGING_MANIFEST_FORMAT_VERSION = 2
EXPORT_SCHEMA_VERSION = 7
BATCH_SIZE = 65_536
BACKUP_MESSAGE_BATCH_SIZE = 65_536
V4_MESSAGE_TABLE = re.compile(r"^Msg_[0-9a-fA-F]{32}$")
V4_MESSAGE_DB = re.compile(r"^message_[0-9]{1,2}\.db$", re.IGNORECASE)
V4_SENDER_ROWID_COLUMN = "__chatlog_sqlite_rowid"
SQLITE_DYNAMIC_TYPE = "UNION(i BIGINT, d DOUBLE, s VARCHAR, b BLOB)"
V3_MESSAGE_DB = re.compile(r"^MSG[0-9]{0,2}\.db$", re.IGNORECASE)
_ACTIVE_RUN_ID: str | None = None


class ExportError(RuntimeError):
    """An error that makes a strict export incomplete."""


@dataclass(frozen=True)
class AccountSpec:
    account_id: str
    account_name: str
    platform: str
    version: int | None
    full_version: str
    data_dir: str
    stage_dir: str
    running: bool | None
    key_source: str
    resolved: bool
    status: str
    errors: tuple[str, ...]
    raw_schema: str


@dataclass(frozen=True)
class DatabaseSpec:
    database_id: str
    account: AccountSpec
    source_path: str
    relative_path: str
    staged_path: Path | None
    source_size: int | None
    source_modified_at: str
    source_sha256: str
    snapshot_size: int | None
    snapshot_sha256: str
    auxiliary_sha256: str
    mode: str
    stage_status: str
    stage_error: str
    legacy_phone_bootstrap: bool = False


@dataclass(frozen=True)
class SourceColumn:
    ordinal: int
    name: str
    declared_type: str
    not_null: bool
    default_sql: str | None
    primary_key_position: int


@dataclass(frozen=True)
class SourceObject:
    object_type: str
    name: str
    original_ddl: str | None
    columns: tuple[SourceColumn, ...]


@dataclass(frozen=True)
class SkippedObject:
    object_type: str
    name: str
    original_ddl: str | None
    reason: str


@dataclass(frozen=True)
class ImportedObject:
    object_id: str
    database: DatabaseSpec
    source: SourceObject
    raw_table: str
    source_rows: int
    imported_rows: int
    import_method: str


@dataclass(frozen=True)
class ContactExtraBufProfile:
    signature: str | None
    add_scene: int | None
    add_scene_enum: str | None
    add_scene_string: str | None
    country: str | None
    province: str | None
    city: str | None
    parse_status: str
    parse_warning: str | None


@dataclass(frozen=True)
class PersistentViewSnapshot:
    schema_name: str
    view_name: str
    create_sql: str
    comment: str | None
    column_comments: tuple[tuple[str, str], ...]


def quote_ident(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'


def sql_string(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def short_hash(value: str, length: int = 16) -> str:
    return hashlib.sha256(value.encode("utf-8", "surrogatepass")).hexdigest()[:length]


def safe_error(exc: BaseException | str, limit: int = 4_000) -> str:
    # Database errors can contain SQL and paths, but this loader never places
    # message values in generated SQL.  Still cap errors before cataloguing.
    value = str(exc).replace("\x00", "\\0")
    return value[:limit]


def as_string(value: Any, default: str = "") -> str:
    return default if value is None else str(value)


def as_optional_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def raw_schema_name(account_id: str) -> str:
    return "raw_" + short_hash(account_id, 16)


def raw_table_name(relative_path: str, object_name: str) -> str:
    stem = Path(relative_path.replace("\\", "/")).stem
    readable = re.sub(r"[^0-9A-Za-z_]+", "_", f"{stem}__{object_name}").strip("_").lower()
    if not readable:
        readable = "sqlite_object"
    return f"{readable[:70]}_{short_hash(relative_path.casefold() + chr(0) + object_name.casefold(), 12)}"


def sqlite_uri(path: Path) -> str:
    return path.resolve().as_uri() + "?mode=ro&immutable=1"


def lossless_sqlite_text(value: bytes) -> str | bytes:
    try:
        return value.decode("utf-8")
    except UnicodeDecodeError:
        return bytes(value)


def open_sqlite(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(sqlite_uri(path), uri=True)
    connection.text_factory = lossless_sqlite_text
    connection.execute("PRAGMA query_only = ON")
    return connection


def read_manifest(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ExportError(f"cannot read manifest {path}: {safe_error(exc)}") from exc
    if not isinstance(value, dict):
        raise ExportError("manifest root must be a JSON object")
    if value.get("format_version") not in {1, 2}:
        raise ExportError(f"unsupported manifest format_version: {value.get('format_version')!r}")
    return value


def read_backup_key(
    path: Path | None, config_path: Path | None = None
) -> bytes | None:
    """Resolve the phone-backup key without ever copying it into a manifest.

    An explicitly supplied key file is authoritative.  The central
    ``chatlog.json`` cache is consulted only when no explicit file was given.
    """

    if path is not None:
        try:
            value = path.read_text(encoding="ascii").strip()
        except (OSError, UnicodeError) as exc:
            raise ExportError(f"cannot read backup key file: {safe_error(exc)}") from exc
        if re.fullmatch(r"[0-9a-fA-F]{64}", value) is None:
            raise ExportError(
                "backup key file must contain exactly one 32-byte hexadecimal key"
            )
        return bytes.fromhex(value)

    if config_path is None:
        return None
    try:
        config = json.loads(config_path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ExportError(
            f"cannot read cached backup key from chatlog.json: {safe_error(exc)}"
        ) from exc
    if not isinstance(config, dict):
        raise ExportError("chatlog.json root must be an object")
    value = config.get("backup_key")
    if value is None or value == "":
        return None
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-fA-F]{64}", value.strip()) is None:
        raise ExportError(
            "chatlog.json backup_key must be exactly one 32-byte hexadecimal key"
        )
    return bytes.fromhex(value.strip())


def resolve_staged_path(raw_path: Any, manifest_dir: Path) -> Path | None:
    if raw_path is None or str(raw_path).strip() == "":
        return None
    path = Path(str(raw_path))
    if not path.is_absolute():
        path = manifest_dir / path
    return path.resolve()


def parse_specs(manifest: dict[str, Any], manifest_path: Path) -> tuple[list[AccountSpec], list[DatabaseSpec]]:
    raw_accounts = manifest.get("accounts")
    if not isinstance(raw_accounts, list):
        raise ExportError("manifest accounts must be an array")

    accounts: list[AccountSpec] = []
    databases: list[DatabaseSpec] = []
    seen_accounts: set[str] = set()
    seen_databases: set[str] = set()

    for account_index, raw_account in enumerate(raw_accounts):
        if not isinstance(raw_account, dict):
            raise ExportError(f"manifest account #{account_index + 1} must be an object")
        account_id = as_string(raw_account.get("id") or raw_account.get("account")).strip()
        if not account_id:
            account_id = "account-" + short_hash(
                as_string(raw_account.get("data_dir")) + f"\0{account_index}", 20
            )
        if account_id in seen_accounts:
            raise ExportError(f"duplicate account id in manifest: {account_id}")
        seen_accounts.add(account_id)

        raw_errors = raw_account.get("errors") or []
        if not isinstance(raw_errors, list):
            raw_errors = [raw_errors]
        account = AccountSpec(
            account_id=account_id,
            # Staging IDs include a path hash and are not source usernames.
            account_name=as_string(raw_account.get("account")),
            platform=as_string(raw_account.get("platform")),
            version=as_optional_int(raw_account.get("version")),
            full_version=as_string(raw_account.get("full_version")),
            data_dir=as_string(raw_account.get("data_dir")),
            stage_dir=as_string(raw_account.get("stage_dir")),
            running=raw_account.get("running") if isinstance(raw_account.get("running"), bool) else None,
            key_source=as_string(raw_account.get("key_source")),
            resolved=bool(raw_account.get("resolved", False)),
            status=as_string(raw_account.get("status")),
            errors=tuple(safe_error(item) for item in raw_errors),
            raw_schema=raw_schema_name(account_id),
        )
        accounts.append(account)

        raw_files = raw_account.get("files") or []
        if not isinstance(raw_files, list):
            raise ExportError(f"files for account {account_id} must be an array")
        for file_index, raw_file in enumerate(raw_files):
            if not isinstance(raw_file, dict):
                raise ExportError(f"file #{file_index + 1} for account {account_id} must be an object")
            relative_path = as_string(raw_file.get("relative_path")).replace("\\", "/").lstrip("/")
            source_path = as_string(raw_file.get("source_path"))
            staged_path = resolve_staged_path(raw_file.get("staged_path"), manifest_path.parent)
            stable_path = relative_path or source_path or as_string(staged_path)
            database_id = short_hash(account_id + "\0" + stable_path.casefold(), 24)
            if database_id in seen_databases:
                raise ExportError(f"duplicate database entry for account {account_id}: {stable_path}")
            seen_databases.add(database_id)
            databases.append(
                DatabaseSpec(
                    database_id=database_id,
                    account=account,
                    source_path=source_path,
                    relative_path=relative_path,
                    staged_path=staged_path,
                    source_size=as_optional_int(raw_file.get("source_size")),
                    source_modified_at=as_string(raw_file.get("source_modified_at")),
                    source_sha256=as_string(raw_file.get("source_sha256")).lower(),
                    snapshot_size=as_optional_int(raw_file.get("snapshot_size")),
                    snapshot_sha256=as_string(raw_file.get("snapshot_sha256")).lower(),
                    auxiliary_sha256=as_string(raw_file.get("auxiliary_sha256")).lower(),
                    mode=as_string(raw_file.get("mode")),
                    stage_status=as_string(raw_file.get("status")),
                    stage_error=safe_error(raw_file.get("error") or ""),
                    legacy_phone_bootstrap=(
                        raw_file.get("legacy_phone_bootstrap") is True
                    ),
                )
            )
    return accounts, databases


def create_catalog(connection: duckdb.DuckDBPyConnection) -> None:
    connection.execute(f"CREATE SCHEMA {quote_ident(CATALOG_SCHEMA)}")
    connection.execute(f"CREATE SCHEMA {quote_ident(CHATLOG_SCHEMA)}")
    connection.execute(
        f"""
        CREATE TABLE {quote_ident(CATALOG_SCHEMA)}.meta (
            schema_version INTEGER NOT NULL,
            exporter VARCHAR NOT NULL
        )
        """
    )
    connection.execute(
        f"INSERT INTO {quote_ident(CATALOG_SCHEMA)}.meta VALUES (?, ?)",
        [EXPORT_SCHEMA_VERSION, "scripts/export_wechat_history.py"],
    )
    connection.execute(
        f"""
        CREATE TABLE {quote_ident(CATALOG_SCHEMA)}.runs (
            run_id VARCHAR PRIMARY KEY,
            manifest_path VARCHAR NOT NULL,
            manifest_format_version INTEGER NOT NULL,
            manifest_generated_at VARCHAR,
            manifest_status VARCHAR,
            allow_partial BOOLEAN NOT NULL,
            imported_at TIMESTAMPTZ NOT NULL,
            completed_at TIMESTAMPTZ,
            completed BOOLEAN NOT NULL,
            partial BOOLEAN NOT NULL,
            sqlite_extension_available BOOLEAN NOT NULL,
            sqlite_extension_error VARCHAR,
            imported_accounts BIGINT NOT NULL,
            imported_databases BIGINT NOT NULL,
            imported_objects BIGINT NOT NULL,
            imported_rows HUGEINT NOT NULL,
            message_rows HUGEINT NOT NULL,
            contact_rows HUGEINT NOT NULL DEFAULT 0,
            contact_tag_definition_rows HUGEINT NOT NULL DEFAULT 0,
            contact_tag_rows HUGEINT NOT NULL DEFAULT 0,
            error_count BIGINT NOT NULL,
            export_mode VARCHAR NOT NULL,
            base_run_id VARCHAR,
            added_databases BIGINT NOT NULL,
            changed_databases BIGINT NOT NULL,
            removed_databases BIGINT NOT NULL,
            reused_databases BIGINT NOT NULL
        )
        """
    )
    connection.execute(
        f"""
        CREATE TABLE {quote_ident(CATALOG_SCHEMA)}.accounts (
            account_id VARCHAR PRIMARY KEY,
            account_name VARCHAR,
            platform VARCHAR,
            version INTEGER,
            full_version VARCHAR,
            data_dir VARCHAR,
            stage_dir VARCHAR,
            running BOOLEAN,
            key_source VARCHAR,
            resolved BOOLEAN NOT NULL,
            manifest_status VARCHAR,
            raw_schema VARCHAR NOT NULL
        )
        """
    )
    connection.execute(
        f"""
        CREATE TABLE {quote_ident(CATALOG_SCHEMA)}.database_files (
            database_id VARCHAR PRIMARY KEY,
            account_id VARCHAR NOT NULL,
            source_path VARCHAR,
            relative_path VARCHAR,
            staged_path VARCHAR,
            source_size BIGINT,
            source_modified_at VARCHAR,
            stage_mode VARCHAR,
            stage_status VARCHAR,
            stage_error VARCHAR,
            import_status VARCHAR NOT NULL,
            imported_objects BIGINT NOT NULL,
            source_rows HUGEINT NOT NULL,
            imported_rows HUGEINT NOT NULL,
            import_error VARCHAR,
            source_sha256 VARCHAR,
            snapshot_size BIGINT,
            snapshot_sha256 VARCHAR,
            auxiliary_sha256 VARCHAR,
            first_seen_run_id VARCHAR,
            last_seen_run_id VARCHAR,
            last_changed_run_id VARCHAR,
            present BOOLEAN NOT NULL
        )
        """
    )
    connection.execute(
        f"""
        CREATE TABLE {quote_ident(CATALOG_SCHEMA)}.objects (
            object_id VARCHAR PRIMARY KEY,
            database_id VARCHAR NOT NULL,
            account_id VARCHAR NOT NULL,
            source_type VARCHAR NOT NULL,
            source_name VARCHAR NOT NULL,
            original_ddl VARCHAR,
            source_columns_json VARCHAR NOT NULL,
            raw_schema VARCHAR NOT NULL,
            raw_table VARCHAR NOT NULL,
            raw_columns_json VARCHAR,
            source_rows HUGEINT,
            imported_rows HUGEINT,
            import_method VARCHAR,
            import_status VARCHAR NOT NULL,
            import_error VARCHAR,
            imported_at TIMESTAMPTZ
        )
        """
    )
    connection.execute(
        f"""
        CREATE TABLE {quote_ident(CATALOG_SCHEMA)}.errors (
            error_id VARCHAR PRIMARY KEY,
            scope VARCHAR NOT NULL,
            account_id VARCHAR,
            database_id VARCHAR,
            object_name VARCHAR,
            message VARCHAR NOT NULL,
            occurred_at TIMESTAMPTZ NOT NULL,
            run_id VARCHAR
        )
        """
    )
    connection.execute(
        f"""
        CREATE TABLE {quote_ident(CATALOG_SCHEMA)}.warnings (
            warning_id VARCHAR PRIMARY KEY,
            scope VARCHAR NOT NULL,
            account_id VARCHAR,
            database_id VARCHAR,
            object_name VARCHAR,
            message VARCHAR NOT NULL,
            occurred_at TIMESTAMPTZ NOT NULL,
            run_id VARCHAR
        )
        """
    )
    connection.execute(
        f"""
        CREATE TABLE {quote_ident(CATALOG_SCHEMA)}.unresolved_accounts (
            account_name VARCHAR,
            data_dir VARCHAR,
            platform VARCHAR,
            version INTEGER,
            reason VARCHAR,
            run_id VARCHAR
        )
        """
    )


def table_exists(connection: duckdb.DuckDBPyConnection, schema: str, table: str) -> bool:
    return bool(
        connection.execute(
            "SELECT count(*) FROM information_schema.tables "
            "WHERE table_schema=? AND table_name=? AND table_type='BASE TABLE'",
            [schema, table],
        ).fetchone()[0]
    )


def table_columns(
    connection: duckdb.DuckDBPyConnection, schema: str, table: str
) -> set[str]:
    return {
        str(row[0]).casefold()
        for row in connection.execute(
            f"DESCRIBE {quote_ident(schema)}.{quote_ident(table)}"
        ).fetchall()
    }


def add_column_if_missing(
    connection: duckdb.DuckDBPyConnection,
    schema: str,
    table: str,
    column: str,
    definition: str,
) -> None:
    if column.casefold() not in table_columns(connection, schema, table):
        connection.execute(
            f"ALTER TABLE {quote_ident(schema)}.{quote_ident(table)} "
            f"ADD COLUMN {quote_ident(column)} {definition}"
        )


def latest_completed_run_id(connection: duckdb.DuckDBPyConnection) -> str:
    row = connection.execute(
        f"SELECT run_id FROM {quote_ident(CATALOG_SCHEMA)}.runs "
        "WHERE completed=TRUE ORDER BY completed_at DESC NULLS LAST, imported_at DESC LIMIT 1"
    ).fetchone()
    if row is None or not row[0]:
        raise ExportError("baseline has no completed export run")
    return str(row[0])


def migrate_catalog(connection: duckdb.DuckDBPyConnection) -> int:
    required = ("runs", "accounts", "database_files", "objects", "errors", "warnings")
    missing = [
        name for name in required if not table_exists(connection, CATALOG_SCHEMA, name)
    ]
    if missing:
        raise ExportError(
            "baseline is not a compatible WeChat export; missing catalog table(s): "
            + ", ".join(missing)
        )
    if not table_exists(connection, CHATLOG_SCHEMA, "messages"):
        raise ExportError("baseline is not a compatible WeChat export; chatlog.messages is missing")

    if table_exists(connection, CATALOG_SCHEMA, "meta"):
        rows = connection.execute(
            f"SELECT schema_version FROM {quote_ident(CATALOG_SCHEMA)}.meta"
        ).fetchall()
        if len(rows) != 1:
            raise ExportError("baseline export_catalog.meta must contain exactly one row")
        version = int(rows[0][0])
        if version > EXPORT_SCHEMA_VERSION:
            raise ExportError(
                f"baseline schema version {version} is newer than this exporter "
                f"(version {EXPORT_SCHEMA_VERSION})"
            )
    else:
        version = 1
        connection.execute(
            f"CREATE TABLE {quote_ident(CATALOG_SCHEMA)}.meta "
            "(schema_version INTEGER NOT NULL, exporter VARCHAR NOT NULL)"
        )
        connection.execute(
            f"INSERT INTO {quote_ident(CATALOG_SCHEMA)}.meta VALUES (?, ?)",
            [version, "legacy export"],
        )

    base_run_id = latest_completed_run_id(connection)
    for column, definition in (
        ("export_mode", "VARCHAR DEFAULT 'full'"),
        ("base_run_id", "VARCHAR"),
        ("added_databases", "BIGINT DEFAULT 0"),
        ("changed_databases", "BIGINT DEFAULT 0"),
        ("removed_databases", "BIGINT DEFAULT 0"),
        ("reused_databases", "BIGINT DEFAULT 0"),
        ("contact_rows", "HUGEINT DEFAULT 0"),
        ("contact_tag_definition_rows", "HUGEINT DEFAULT 0"),
        ("contact_tag_rows", "HUGEINT DEFAULT 0"),
    ):
        add_column_if_missing(connection, CATALOG_SCHEMA, "runs", column, definition)
    connection.execute(
        f"UPDATE {quote_ident(CATALOG_SCHEMA)}.runs SET "
        "export_mode=coalesce(export_mode, 'full'), "
        "added_databases=coalesce(added_databases, 0), "
        "changed_databases=coalesce(changed_databases, 0), "
        "removed_databases=coalesce(removed_databases, 0), "
        "reused_databases=coalesce(reused_databases, 0), "
        "contact_rows=coalesce(contact_rows, 0), "
        "contact_tag_definition_rows=coalesce(contact_tag_definition_rows, 0), "
        "contact_tag_rows=coalesce(contact_tag_rows, 0)"
    )
    for column in (
        "contact_rows",
        "contact_tag_definition_rows",
        "contact_tag_rows",
    ):
        connection.execute(
            f"ALTER TABLE {quote_ident(CATALOG_SCHEMA)}.runs "
            f"ALTER COLUMN {quote_ident(column)} SET NOT NULL"
        )

    for column, definition in (
        ("source_sha256", "VARCHAR"),
        ("snapshot_size", "BIGINT"),
        ("snapshot_sha256", "VARCHAR"),
        ("auxiliary_sha256", "VARCHAR"),
        ("first_seen_run_id", "VARCHAR"),
        ("last_seen_run_id", "VARCHAR"),
        ("last_changed_run_id", "VARCHAR"),
        ("present", "BOOLEAN DEFAULT TRUE"),
    ):
        add_column_if_missing(
            connection, CATALOG_SCHEMA, "database_files", column, definition
        )
    connection.execute(
        f"UPDATE {quote_ident(CATALOG_SCHEMA)}.database_files "
        "SET first_seen_run_id=coalesce(first_seen_run_id, ?), "
        "last_seen_run_id=coalesce(last_seen_run_id, ?), "
        "last_changed_run_id=coalesce(last_changed_run_id, ?), "
        "present=coalesce(present, TRUE)",
        [base_run_id, base_run_id, base_run_id],
    )

    for table in ("errors", "warnings"):
        add_column_if_missing(connection, CATALOG_SCHEMA, table, "run_id", "VARCHAR")
        connection.execute(
            f"UPDATE {quote_ident(CATALOG_SCHEMA)}.{quote_ident(table)} "
            "SET run_id=? WHERE run_id IS NULL",
            [base_run_id],
        )
    if not table_exists(connection, CATALOG_SCHEMA, "unresolved_accounts"):
        connection.execute(
            f"CREATE TABLE {quote_ident(CATALOG_SCHEMA)}.unresolved_accounts "
            "(account_name VARCHAR, data_dir VARCHAR, platform VARCHAR, version INTEGER, "
            "reason VARCHAR, run_id VARCHAR)"
        )
    else:
        add_column_if_missing(
            connection, CATALOG_SCHEMA, "unresolved_accounts", "run_id", "VARCHAR"
        )
        connection.execute(
            f"UPDATE {quote_ident(CATALOG_SCHEMA)}.unresolved_accounts "
            "SET run_id=? WHERE run_id IS NULL",
            [base_run_id],
        )

    connection.execute(
        f"UPDATE {quote_ident(CATALOG_SCHEMA)}.meta "
        "SET schema_version=?, exporter=?",
        [EXPORT_SCHEMA_VERSION, "scripts/export_wechat_history.py"],
    )
    return version


def record_error(
    connection: duckdb.DuckDBPyConnection,
    scope: str,
    message: BaseException | str,
    account_id: str | None = None,
    database_id: str | None = None,
    object_name: str | None = None,
) -> None:
    connection.execute(
        f"INSERT INTO {quote_ident(CATALOG_SCHEMA)}.errors "
        "(error_id, scope, account_id, database_id, object_name, message, occurred_at, run_id) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        [
            str(uuid.uuid4()),
            scope,
            account_id,
            database_id,
            object_name,
            safe_error(message),
            datetime.now(timezone.utc),
            _ACTIVE_RUN_ID,
        ],
    )


def record_warning(
    connection: duckdb.DuckDBPyConnection,
    scope: str,
    message: BaseException | str,
    account_id: str | None = None,
    database_id: str | None = None,
    object_name: str | None = None,
) -> None:
    connection.execute(
        f"INSERT INTO {quote_ident(CATALOG_SCHEMA)}.warnings "
        "(warning_id, scope, account_id, database_id, object_name, message, occurred_at, run_id) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        [
            str(uuid.uuid4()),
            scope,
            account_id,
            database_id,
            object_name,
            safe_error(message),
            datetime.now(timezone.utc),
            _ACTIVE_RUN_ID,
        ],
    )


def try_load_sqlite_extension(connection: duckdb.DuckDBPyConnection) -> tuple[bool, str]:
    failures: list[str] = []
    try:
        connection.execute("LOAD sqlite")
        return True, ""
    except Exception as exc:  # DuckDB exception classes vary by release.
        failures.append(safe_error(exc))
    try:
        connection.execute("INSTALL sqlite")
        connection.execute("LOAD sqlite")
        return True, ""
    except Exception as exc:
        failures.append(safe_error(exc))
    return False, " | ".join(failures)


def is_mm_tokenizer_virtual(ddl: str | None) -> bool:
    if not ddl or "create virtual table" not in ddl.casefold():
        return False
    return re.search(r"\btokenize\s*=\s*mmtokenizer\b", ddl, re.IGNORECASE) is not None


def is_mm_tokenizer_error(error: BaseException) -> bool:
    return "unknown tokenizer: mmtokenizer" in safe_error(error).casefold()


def introspect_sqlite(
    connection: sqlite3.Connection,
) -> tuple[list[SourceObject], list[SkippedObject]]:
    objects: list[SourceObject] = []
    skipped: list[SkippedObject] = []
    rows = connection.execute(
        """
        SELECT type, name, sql
        FROM sqlite_schema
        WHERE type IN ('table', 'view')
        ORDER BY CASE type WHEN 'table' THEN 0 ELSE 1 END, name COLLATE NOCASE, name
        """
    ).fetchall()
    for object_type, name, ddl in rows:
        if is_mm_tokenizer_virtual(ddl):
            skipped.append(
                SkippedObject(
                    "virtual_table",
                    as_string(name),
                    None if ddl is None else str(ddl),
                    "WeChat's proprietary mmTokenizer is unavailable; all physical FTS shadow tables are imported separately",
                )
            )
            continue
        escaped = name.replace('"', '""')
        try:
            pragma_rows = connection.execute(f'PRAGMA table_info("{escaped}")').fetchall()
        except sqlite3.OperationalError as exc:
            if is_mm_tokenizer_error(exc):
                skipped.append(
                    SkippedObject(
                        as_string(object_type),
                        as_string(name),
                        None if ddl is None else str(ddl),
                        "object depends on WeChat's unavailable proprietary mmTokenizer",
                    )
                )
                continue
            raise
        columns = tuple(
            SourceColumn(
                ordinal=int(row[0]),
                name=as_string(row[1]),
                declared_type=as_string(row[2]),
                not_null=bool(row[3]),
                default_sql=None if row[4] is None else str(row[4]),
                primary_key_position=int(row[5]),
            )
            for row in pragma_rows
        )
        # SELECT * is the actual import surface for views and virtual tables.
        try:
            cursor = connection.execute(f'SELECT * FROM "{escaped}" LIMIT 0')
        except sqlite3.OperationalError as exc:
            if is_mm_tokenizer_error(exc):
                skipped.append(
                    SkippedObject(
                        as_string(object_type),
                        as_string(name),
                        None if ddl is None else str(ddl),
                        "object depends on WeChat's unavailable proprietary mmTokenizer",
                    )
                )
                continue
            raise
        visible_names = [item[0] for item in (cursor.description or [])]
        if visible_names and visible_names != [column.name for column in columns]:
            by_name = {column.name.casefold(): column for column in columns}
            columns = tuple(
                by_name.get(
                    visible.casefold(),
                    SourceColumn(i, visible, "", False, None, 0),
                )
                for i, visible in enumerate(visible_names)
            )
        objects.append(SourceObject(object_type, name, ddl, columns))
    return objects, skipped


def require_quick_check_ok(rows: Sequence[Sequence[Any]], scope: str) -> None:
    if len(rows) == 1 and str(rows[0][0]).casefold() == "ok":
        return
    details = "; ".join(str(row[0]) for row in rows[:10]) or "no result"
    raise ExportError(f"SQLite PRAGMA quick_check failed for {scope}: {details}")


def verify_sqlite(connection: sqlite3.Connection) -> str:
    try:
        rows = connection.execute("PRAGMA quick_check").fetchall()
        require_quick_check_ok(rows, "database")
        return ""
    except sqlite3.OperationalError as exc:
        if not is_mm_tokenizer_error(exc):
            raise

    tables = connection.execute(
        "SELECT name, sql FROM sqlite_schema WHERE type='table' ORDER BY name COLLATE NOCASE, name"
    ).fetchall()
    unsupported = {as_string(name) for name, ddl in tables if is_mm_tokenizer_virtual(ddl)}
    if not unsupported:
        raise ExportError("SQLite quick_check requires mmTokenizer but no matching virtual table was found")
    checked = 0
    for name, _ddl in tables:
        table_name = as_string(name)
        if table_name in unsupported:
            continue
        rows = connection.execute(f"PRAGMA quick_check({sql_string(table_name)})").fetchall()
        require_quick_check_ok(rows, f"table {table_name!r}")
        checked += 1
    return (
        "Global SQLite quick_check could not load WeChat's proprietary mmTokenizer; "
        f"all {checked} physical tables passed table-scoped quick_check"
    )


def columns_json(columns: Sequence[SourceColumn]) -> str:
    return json.dumps(
        [
            {
                "ordinal": column.ordinal,
                "name": column.name,
                "declared_type": column.declared_type,
                "not_null": column.not_null,
                "default_sql": column.default_sql,
                "primary_key_position": column.primary_key_position,
            }
            for column in columns
        ],
        ensure_ascii=False,
        separators=(",", ":"),
    )


def deduplicate_names(names: Sequence[str]) -> list[str]:
    used: set[str] = set()
    result: list[str] = []
    for index, original in enumerate(names):
        base = original or f"column_{index + 1}"
        candidate = base
        counter = 2
        while candidate.casefold() in used:
            candidate = f"{base}_{counter}"
            counter += 1
        used.add(candidate.casefold())
        result.append(candidate)
    return result


def fallback_type(
    column: SourceColumn, storage_classes: Iterable[str], force_blob: bool = False
) -> str:
    if force_blob:
        return "BLOB"
    observed = {value.casefold() for value in storage_classes if value.casefold() != "null"}
    if observed == {"integer"}:
        return "BIGINT"
    if observed == {"real"}:
        return "DOUBLE"
    if observed == {"text"}:
        return "VARCHAR"
    if observed == {"blob"}:
        return "BLOB"
    if len(observed) > 1:
        return SQLITE_DYNAMIC_TYPE

    declared = column.declared_type.upper()
    if not declared:
        # SQLite columns without a declared affinity can change storage class
        # on any row. DuckDB's tagged union preserves that dynamic type exactly.
        return SQLITE_DYNAMIC_TYPE
    if "INT" in declared:
        return "BIGINT"
    if any(token in declared for token in ("CHAR", "CLOB", "TEXT", "JSON")):
        return "VARCHAR"
    if "BLOB" in declared:
        return "BLOB"
    if any(token in declared for token in ("REAL", "FLOA", "DOUB")):
        return "DOUBLE"
    return SQLITE_DYNAMIC_TYPE


def coerce_value(value: Any, destination_type: str) -> Any:
    if value is None:
        return None
    if isinstance(value, memoryview):
        value = value.tobytes()
    if destination_type == "BLOB":
        if isinstance(value, bytearray):
            return bytes(value)
        if isinstance(value, bytes):
            return value
        if isinstance(value, str):
            return value.encode("utf-8")
        raise TypeError(f"cannot preserve {type(value).__name__} value in a BLOB column")
    if destination_type == "VARCHAR":
        if isinstance(value, bytes):
            return value.decode("utf-8")
        return value if isinstance(value, str) else str(value)
    return value


def import_with_python(
    duck: duckdb.DuckDBPyConnection,
    sqlite_connection: sqlite3.Connection,
    database: DatabaseSpec,
    source: SourceObject,
    destination: str,
) -> tuple[int, int, list[tuple[str, str]]]:
    source_name = quote_ident(source.name)
    source_rows = int(sqlite_connection.execute(f"SELECT count(*) FROM {source_name}").fetchone()[0])
    preserve_sender_rowid = (
        database.account.version == 4 and source.name.casefold() == "name2id"
        and "user_name" in {column.name.casefold() for column in source.columns}
    )
    if preserve_sender_rowid and V4_SENDER_ROWID_COLUMN in {column.name.casefold() for column in source.columns}:
        raise ExportError("Name2Id collides with reserved SQLite row-id provenance column")
    projection = f"rowid AS {quote_ident(V4_SENDER_ROWID_COLUMN)}, *" if preserve_sender_rowid else "*"
    cursor = sqlite_connection.execute(f"SELECT {projection} FROM {source_name}")
    first_batch = cursor.fetchmany(BATCH_SIZE)
    source_names = [item[0] for item in (cursor.description or [])]
    destination_names = deduplicate_names(source_names)
    declared_by_name = {column.name.casefold(): column for column in source.columns}
    if preserve_sender_rowid:
        declared_by_name[V4_SENDER_ROWID_COLUMN] = SourceColumn(
            -1, V4_SENDER_ROWID_COLUMN, "INTEGER", True, None, 0
        )
    source_columns = [
        declared_by_name.get(name.casefold(), SourceColumn(i, name, "", False, None, 0))
        for i, name in enumerate(source_names)
    ]
    storage_by_column: list[set[str]] = [set() for _ in source_names]
    if source_names:
        storage_query = ", ".join(
            "typeof(rowid)" if preserve_sender_rowid and name == V4_SENDER_ROWID_COLUMN
            else f"typeof({quote_ident(name)})" for name in source_names
        )
        for storage_row in sqlite_connection.execute(
            f"SELECT DISTINCT {storage_query} FROM {source_name}"
        ):
            for index, storage_class in enumerate(storage_row):
                storage_by_column[index].add(as_string(storage_class))
    text_indexes = [index for index, values in enumerate(storage_by_column) if "text" in values]
    if text_indexes:
        text_query = ", ".join(quote_ident(source_names[index]) for index in text_indexes)
        undecodable: set[int] = set()
        for text_row in sqlite_connection.execute(f"SELECT {text_query} FROM {source_name}"):
            for result_index, value in enumerate(text_row):
                if isinstance(value, bytes):
                    undecodable.add(text_indexes[result_index])
            if len(undecodable) == len(text_indexes):
                break
        for index in undecodable:
            storage_by_column[index].add("invalid_text")
    is_v4_message = V4_MESSAGE_TABLE.fullmatch(source.name) is not None and V4_MESSAGE_DB.fullmatch(
        Path(database.relative_path.replace("\\", "/")).name
    ) is not None
    destination_types = []
    for i, column in enumerate(source_columns):
        force_blob = is_v4_message and column.name.casefold() in {
            "message_content",
            "compress_content",
            "packed_info_data",
        }
        destination_types.append(
            fallback_type(column, storage_by_column[i], force_blob=force_blob)
        )
    definitions = ", ".join(
        f"{quote_ident(name)} {destination_type}"
        for name, destination_type in zip(destination_names, destination_types, strict=True)
    )
    if not definitions:
        raise ExportError(f"SQLite object {source.name!r} exposes no columns")
    duck.execute(f"CREATE TABLE {destination} ({definitions})")
    placeholders = ", ".join("?" for _ in destination_names)
    insert_sql = f"INSERT INTO {destination} VALUES ({placeholders})"
    bulk_columns = list(zip(destination_names, destination_types, strict=True))
    can_bulk_insert = all(
        destination_type != SQLITE_DYNAMIC_TYPE for destination_type in destination_types
    )
    imported_rows = 0
    batch = first_batch
    while batch:
        converted = [
            tuple(
                coerce_value(value, destination_types[index])
                for index, value in enumerate(row)
            )
            for row in batch
        ]
        if can_bulk_insert:
            insert_batch(duck, destination, converted, bulk_columns)
        else:
            # DuckDB's tagged UNION preserves SQLite columns whose storage class
            # varies by row.  Arrow has no equivalent tagged representation, so
            # retain the lossless prepared-statement path for these rare tables.
            duck.executemany(insert_sql, converted)
        imported_rows += len(converted)
        batch = cursor.fetchmany(BATCH_SIZE)
    return source_rows, imported_rows, list(zip(destination_names, destination_types, strict=True))


def destination_columns(duck: duckdb.DuckDBPyConnection, destination: str) -> list[tuple[str, str]]:
    return [(str(row[0]), str(row[1])) for row in duck.execute(f"DESCRIBE {destination}").fetchall()]


def insert_object_catalog(
    duck: duckdb.DuckDBPyConnection,
    imported: ImportedObject,
    raw_columns: Sequence[tuple[str, str]],
) -> None:
    duck.execute(
        f"""
        INSERT INTO {quote_ident(CATALOG_SCHEMA)}.objects VALUES
        (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        [
            imported.object_id,
            imported.database.database_id,
            imported.database.account.account_id,
            imported.source.object_type,
            imported.source.name,
            imported.source.original_ddl,
            columns_json(imported.source.columns),
            imported.database.account.raw_schema,
            imported.raw_table,
            json.dumps(
                [{"name": name, "type": typ} for name, typ in raw_columns],
                ensure_ascii=False,
                separators=(",", ":"),
            ),
            imported.source_rows,
            imported.imported_rows,
            imported.import_method,
            "ok",
            None,
            datetime.now(timezone.utc),
        ],
    )


def insert_failed_object(
    duck: duckdb.DuckDBPyConnection,
    database: DatabaseSpec,
    source: SourceObject,
    raw_table: str,
    error: BaseException | str,
) -> None:
    object_id = short_hash(database.database_id + "\0" + source.object_type + "\0" + source.name, 28)
    duck.execute(
        f"""
        INSERT INTO {quote_ident(CATALOG_SCHEMA)}.objects VALUES
        (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        [
            object_id,
            database.database_id,
            database.account.account_id,
            source.object_type,
            source.name,
            source.original_ddl,
            columns_json(source.columns),
            database.account.raw_schema,
            raw_table,
            None,
            None,
            None,
            None,
            "error",
            safe_error(error),
            datetime.now(timezone.utc),
        ],
    )
    record_error(duck, "object_import", error, database.account.account_id, database.database_id, source.name)


def insert_skipped_object(
    duck: duckdb.DuckDBPyConnection,
    database: DatabaseSpec,
    skipped: SkippedObject,
) -> None:
    object_id = short_hash(database.database_id + "\0" + skipped.object_type + "\0" + skipped.name, 28)
    raw_table = raw_table_name(database.relative_path or database.source_path, skipped.name)
    duck.execute(
        f"""
        INSERT INTO {quote_ident(CATALOG_SCHEMA)}.objects VALUES
        (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        [
            object_id,
            database.database_id,
            database.account.account_id,
            skipped.object_type,
            skipped.name,
            skipped.original_ddl,
            "[]",
            database.account.raw_schema,
            raw_table,
            None,
            None,
            None,
            None,
            "skipped_derived_virtual",
            skipped.reason,
            datetime.now(timezone.utc),
        ],
    )
    record_warning(
        duck,
        "sqlite_derived_virtual",
        skipped.reason,
        database.account.account_id,
        database.database_id,
        skipped.name,
    )


def import_one_object(
    duck: duckdb.DuckDBPyConnection,
    sqlite_connection: sqlite3.Connection,
    attached_alias: str | None,
    database: DatabaseSpec,
    source: SourceObject,
) -> ImportedObject:
    raw_table = raw_table_name(database.relative_path or database.source_path, source.name)
    destination = f"{quote_ident(database.account.raw_schema)}.{quote_ident(raw_table)}"
    object_id = short_hash(database.database_id + "\0" + source.object_type + "\0" + source.name, 28)
    extension_error = ""

    # The generic SQLite scanner SELECT * omits implicit rowid. Sender IDs
    # require original sparse SQLite rowids, never DuckDB's physical rowid.
    preserve_sender_rowid = (
        database.account.version == 4 and source.name.casefold() == "name2id"
        and "user_name" in {column.name.casefold() for column in source.columns}
    )
    if attached_alias is not None and not preserve_sender_rowid:
        duck.execute("BEGIN TRANSACTION")
        try:
            attached_source = (
                f"{quote_ident(attached_alias)}.{quote_ident('main')}.{quote_ident(source.name)}"
            )
            source_rows = int(duck.execute(f"SELECT count(*) FROM {attached_source}").fetchone()[0])
            duck.execute(f"CREATE TABLE {destination} AS SELECT * FROM {attached_source}")
            imported_rows = int(duck.execute(f"SELECT count(*) FROM {destination}").fetchone()[0])
            if imported_rows != source_rows:
                raise ExportError(
                    f"row-count mismatch for {source.name}: source={source_rows}, imported={imported_rows}"
                )
            imported = ImportedObject(
                object_id, database, source, raw_table, source_rows, imported_rows, "duckdb_sqlite"
            )
            insert_object_catalog(duck, imported, destination_columns(duck, destination))
            duck.execute("COMMIT")
            return imported
        except Exception as exc:
            extension_error = safe_error(exc)
            duck.execute("ROLLBACK")

    duck.execute("BEGIN TRANSACTION")
    try:
        source_rows, imported_rows, raw_columns = import_with_python(
            duck, sqlite_connection, database, source, destination
        )
        verified_rows = int(duck.execute(f"SELECT count(*) FROM {destination}").fetchone()[0])
        if source_rows != imported_rows or imported_rows != verified_rows:
            raise ExportError(
                f"row-count mismatch for {source.name}: source={source_rows}, "
                f"inserted={imported_rows}, verified={verified_rows}"
            )
        method = "sqlite3_fallback" if not extension_error else "sqlite3_fallback_after_extension_error"
        imported = ImportedObject(object_id, database, source, raw_table, source_rows, imported_rows, method)
        insert_object_catalog(duck, imported, raw_columns)
        duck.execute("COMMIT")
        return imported
    except Exception:
        duck.execute("ROLLBACK")
        raise


def column_lookup(source: SourceObject) -> dict[str, str]:
    return {column.name.casefold(): column.name for column in source.columns}


def expr(columns: dict[str, str], name: str, cast: str, alias: str | None = None) -> str:
    output = alias or name
    actual = columns.get(name.casefold())
    if actual is None:
        return f"CAST(NULL AS {cast}) AS {quote_ident(output)}"
    return f"CAST({quote_ident(actual)} AS {cast}) AS {quote_ident(output)}"


def canonical_kind(imported: ImportedObject) -> tuple[str | None, set[str]]:
    name = imported.source.name
    folded = name.casefold()
    relative = imported.database.relative_path.replace("\\", "/")
    basename = Path(relative).name
    required: set[str]
    if folded == "msg" and V3_MESSAGE_DB.fullmatch(basename):
        required = {"localid", "msgsvrid", "type", "issender", "createtime", "strtalker", "strcontent"}
        return "v3_msg", required
    if folded == "publicmsg" and basename.casefold() == "publicmsg.db":
        required = {"localid", "msgsvrid", "type", "issender", "createtime", "strtalker", "strcontent"}
        return "v3_public", required
    if folded in {"chatcrmsg", "chatmsg"} and basename.casefold() in {
        "openimmsg.db",
        "customerservice.db",
        "chatmsg.db",
        "bizchatmsg.db",
    }:
        required = {"localid", "msgsvrid", "type", "issender", "createtime", "strtalker", "strcontent"}
        return "v3_" + Path(basename).stem.casefold(), required
    if V4_MESSAGE_TABLE.fullmatch(name) and V4_MESSAGE_DB.fullmatch(basename):
        required = {
            "local_id",
            "server_id",
            "local_type",
            "sort_seq",
            "real_sender_id",
            "create_time",
            "message_content",
            "packed_info_data",
            "status",
        }
        return "v4_msg", required
    return None, set()


CONTACT_EXTRA_BUF_FIELDS = {
    bytes.fromhex("46cf10c4"): ("signature", 0x18),
    bytes.fromhex("4d6c4570"): ("add_scene", 0x04),
    bytes.fromhex("a4d9024a"): ("country", 0x18),
    bytes.fromhex("e2eaa8d1"): ("province", 0x18),
    bytes.fromhex("1d025bbf"): ("city", 0x18),
}
CONTACT_EXTRA_BUF_FIXED_WIDTHS = {0x02: 1, 0x04: 4, 0x05: 8}
CONTACT_EXTRA_BUF_LENGTH_TYPES = {0x17, 0x18}

# Published legacy FriendshipSceneType symbols for the known numeric values:
# https://github.com/wechaty/grpc/blob/main/proto/wechaty/puppet/friendship.proto
# The readable English strings are exporter policy, not official WeChat UI
# labels, and this legacy enum is incomplete for modern Windows scene codes.
# Keep conversion here so full exports, delta backfills, and validation agree.
CONTACT_ADD_SCENES: dict[int, tuple[str, str]] = {
    0: ("FRIENDSHIP_SCENE_TYPE_UNSPECIFIED", "Unspecified"),
    1: ("FRIENDSHIP_SCENE_TYPE_QQ", "QQ"),
    2: ("FRIENDSHIP_SCENE_TYPE_EMAIL", "Email"),
    3: ("FRIENDSHIP_SCENE_TYPE_WEIXIN", "WeChat ID"),
    12: ("FRIENDSHIP_SCENE_TYPE_QQTBD", "QQ (TBD)"),
    14: ("FRIENDSHIP_SCENE_TYPE_ROOM", "Group Chat"),
    15: ("FRIENDSHIP_SCENE_TYPE_PHONE", "Phone Contacts"),
    17: ("FRIENDSHIP_SCENE_TYPE_CARD", "Contact Card"),
    18: ("FRIENDSHIP_SCENE_TYPE_LOCATION", "Location"),
    25: ("FRIENDSHIP_SCENE_TYPE_BOTTLE", "Drift Bottle"),
    29: ("FRIENDSHIP_SCENE_TYPE_SHAKING", "Shake"),
    30: ("FRIENDSHIP_SCENE_TYPE_QRCODE", "Scan QR Code"),
}


def contact_add_scene_values(value: int | None) -> tuple[str | None, str | None]:
    """Return a legacy enum symbol and exporter-owned readable scene string."""
    if value is None:
        return None, None
    known = CONTACT_ADD_SCENES.get(value)
    if known is not None:
        return known
    return f"FRIENDSHIP_SCENE_TYPE_UNKNOWN_{value}", f"Unknown ({value})"


def malformed_contact_extra_buf(message: str) -> ContactExtraBufProfile:
    return ContactExtraBufProfile(
        None, None, None, None, None, None, None, "malformed", message
    )


def parse_contact_extra_buf(value: Any) -> ContactExtraBufProfile:
    """Decode the verified Windows-v3 profile fields from one ExtraBuf blob.

    The parser validates the complete TLV framing so a target-looking byte
    sequence inside another field cannot be mistaken for a profile field.
    Unknown or truncated framing fails soft: all decoded values are discarded,
    while the caller retains the raw blob and records the warning on the
    canonical contact row.
    """
    if value is None:
        return ContactExtraBufProfile(
            None, None, None, None, None, None, None, "not_present", None
        )
    if not isinstance(value, (bytes, bytearray, memoryview)):
        return malformed_contact_extra_buf("ExtraBuf is not a binary value")
    blob = memoryview(value)
    if not blob:
        return ContactExtraBufProfile(
            None, None, None, None, None, None, None, "not_present", None
        )

    decoded: dict[str, str | int | None] = {
        "signature": None,
        "add_scene": None,
        "country": None,
        "province": None,
        "city": None,
    }
    seen_targets: set[bytes] = set()
    offset = 0
    try:
        while offset < len(blob):
            field_offset = offset
            if len(blob) - offset < 5:
                raise ValueError(f"offset {field_offset}: truncated TLV header")
            field_id = bytes(blob[offset : offset + 4])
            type_code = int(blob[offset + 4])
            offset += 5

            fixed_width = CONTACT_EXTRA_BUF_FIXED_WIDTHS.get(type_code)
            if fixed_width is not None:
                payload_size = fixed_width
            elif type_code in CONTACT_EXTRA_BUF_LENGTH_TYPES:
                if len(blob) - offset < 4:
                    raise ValueError(
                        f"offset {field_offset}: truncated TLV length for "
                        f"field {field_id.hex()}"
                    )
                payload_size = int.from_bytes(blob[offset : offset + 4], "little")
                offset += 4
            else:
                raise ValueError(
                    f"offset {field_offset}: unsupported TLV type 0x{type_code:02x} "
                    f"for field {field_id.hex()}"
                )
            if payload_size > len(blob) - offset:
                raise ValueError(
                    f"offset {field_offset}: TLV payload for field {field_id.hex()} "
                    "extends past the end of ExtraBuf"
                )
            payload = blob[offset : offset + payload_size]
            offset += payload_size

            target = CONTACT_EXTRA_BUF_FIELDS.get(field_id)
            if target is None:
                continue
            field_name, expected_type = target
            if field_id in seen_targets:
                raise ValueError(
                    f"offset {field_offset}: duplicate target field {field_id.hex()}"
                )
            seen_targets.add(field_id)
            if type_code != expected_type:
                raise ValueError(
                    f"offset {field_offset}: target field {field_id.hex()} has "
                    f"type 0x{type_code:02x}, expected 0x{expected_type:02x}"
                )
            if type_code == 0x04:
                decoded[field_name] = int.from_bytes(payload, "little", signed=True)
                continue
            try:
                decoded[field_name] = payload.tobytes().decode("utf-16-le").rstrip("\x00")
            except UnicodeDecodeError as exc:
                raise ValueError(
                    f"offset {field_offset}: target field {field_id.hex()} is not "
                    "valid UTF-16LE"
                ) from exc
    except ValueError as exc:
        return malformed_contact_extra_buf(str(exc))

    add_scene = decoded["add_scene"] if isinstance(decoded["add_scene"], int) else None
    add_scene_enum, add_scene_string = contact_add_scene_values(add_scene)
    return ContactExtraBufProfile(
        signature=decoded["signature"] if isinstance(decoded["signature"], str) else None,
        add_scene=add_scene,
        add_scene_enum=add_scene_enum,
        add_scene_string=add_scene_string,
        country=decoded["country"] if isinstance(decoded["country"], str) else None,
        province=decoded["province"] if isinstance(decoded["province"], str) else None,
        city=decoded["city"] if isinstance(decoded["city"], str) else None,
        parse_status="ok",
        parse_warning=None,
    )


def contact_kind_for(source_name: str, relative_path: str) -> tuple[str | None, set[str]]:
    folded = source_name.casefold()
    relative = relative_path.replace("\\", "/")
    basename = Path(relative).name.casefold()
    if folded == "contact" and basename == "micromsg.db":
        return "windows_v3_contact", {"username"}
    if folded == "contact" and basename == "contact.db":
        return "v4_contact", {"username"}
    if folded == "wccontact" and basename == "wccontact_new2.db":
        return "darwin_v3_contact", {"m_nsusrname"}
    return None, set()


def canonical_contact_kind(imported: ImportedObject) -> tuple[str | None, set[str]]:
    """Identify contact tables whose common fields can be projected losslessly."""
    return contact_kind_for(imported.source.name, imported.database.relative_path)


def contact_tag_role_for(source_name: str, relative_path: str) -> str | None:
    """Identify only the verified Windows-v3 contact-label source tables."""
    relative = relative_path.replace("\\", "/")
    if Path(relative).name.casefold() != "micromsg.db":
        return None
    folded = source_name.casefold()
    if folded == "contact":
        return "contact"
    if folded == "contactlabel":
        return "definition"
    return None


def windows_v3_contact_tag_role(imported: ImportedObject) -> str | None:
    return contact_tag_role_for(
        imported.source.name, imported.database.relative_path
    )


CONTACT_EXTRA_BUF_COLUMN_DEFINITIONS = (
    ("signature", "VARCHAR"),
    ("add_scene", "INTEGER"),
    ("add_scene_enum", "VARCHAR"),
    ("add_scene_string", "VARCHAR"),
    ("country", "VARCHAR"),
    ("province", "VARCHAR"),
    ("city", "VARCHAR"),
    ("extra_buf_parse_status", "VARCHAR"),
    ("extra_buf_parse_warning", "VARCHAR"),
)
CONTACT_EXTRA_BUF_CONTACT_COLUMNS = {
    name for name, _definition in CONTACT_EXTRA_BUF_COLUMN_DEFINITIONS
}

CONTACT_COLUMNS = {
    "account_id",
    "wechat_version",
    "source_kind",
    "database_id",
    "source_relative_path",
    "raw_schema",
    "raw_table",
    "source_object",
    "source_contact_key",
    "source_rowid",
    "user_name",
    "alias",
    "remark",
    "nickname",
    "description",
    "is_friend",
} | CONTACT_EXTRA_BUF_CONTACT_COLUMNS

CONTACT_TAG_DEFINITION_COLUMNS = {
    "account_id",
    "wechat_version",
    "source_kind",
    "database_id",
    "source_relative_path",
    "raw_schema",
    "raw_table",
    "source_object",
    "source_label_key",
    "source_rowid",
    "raw_label_id",
    "label_id_text",
    "label_id",
    "label_name",
}

CONTACT_TAG_COLUMNS = {
    "account_id",
    "wechat_version",
    "source_kind",
    "database_id",
    "source_relative_path",
    "raw_schema",
    "raw_table",
    "source_object",
    "source_contact_key",
    "source_contact_rowid",
    "source_tag_key",
    "tag_ordinal",
    "raw_label_id",
    "label_id_text",
    "label_id",
    "label_definition_key",
    "label_name",
    "definition_match_count",
    "resolved",
}


def create_contacts_table(duck: duckdb.DuckDBPyConnection) -> None:
    duck.execute(
        f"""
        CREATE TABLE {quote_ident(CHATLOG_SCHEMA)}.contacts (
            account_id VARCHAR NOT NULL,
            wechat_version INTEGER,
            source_kind VARCHAR NOT NULL,
            database_id VARCHAR NOT NULL,
            source_relative_path VARCHAR,
            raw_schema VARCHAR NOT NULL,
            raw_table VARCHAR NOT NULL,
            source_object VARCHAR NOT NULL,
            source_contact_key VARCHAR NOT NULL,
            source_rowid BIGINT NOT NULL,
            user_name VARCHAR,
            alias VARCHAR,
            remark VARCHAR,
            nickname VARCHAR,
            description VARCHAR,
            is_friend BOOLEAN,
            signature VARCHAR,
            add_scene INTEGER,
            add_scene_enum VARCHAR,
            add_scene_string VARCHAR,
            country VARCHAR,
            province VARCHAR,
            city VARCHAR,
            extra_buf_parse_status VARCHAR NOT NULL,
            extra_buf_parse_warning VARCHAR
        )
        """
    )


def create_contact_tag_tables(duck: duckdb.DuckDBPyConnection) -> None:
    duck.execute(
        f"""
        CREATE TABLE {quote_ident(CHATLOG_SCHEMA)}.contact_tag_definitions (
            account_id VARCHAR NOT NULL,
            wechat_version INTEGER,
            source_kind VARCHAR NOT NULL,
            database_id VARCHAR NOT NULL,
            source_relative_path VARCHAR,
            raw_schema VARCHAR NOT NULL,
            raw_table VARCHAR NOT NULL,
            source_object VARCHAR NOT NULL,
            source_label_key VARCHAR NOT NULL,
            source_rowid BIGINT NOT NULL,
            raw_label_id VARCHAR,
            label_id_text VARCHAR,
            label_id BIGINT,
            label_name VARCHAR
        )
        """
    )
    duck.execute(
        f"""
        CREATE TABLE {quote_ident(CHATLOG_SCHEMA)}.contact_tags (
            account_id VARCHAR NOT NULL,
            wechat_version INTEGER,
            source_kind VARCHAR NOT NULL,
            database_id VARCHAR NOT NULL,
            source_relative_path VARCHAR,
            raw_schema VARCHAR NOT NULL,
            raw_table VARCHAR NOT NULL,
            source_object VARCHAR NOT NULL,
            source_contact_key VARCHAR NOT NULL,
            source_contact_rowid BIGINT NOT NULL,
            source_tag_key VARCHAR NOT NULL,
            tag_ordinal BIGINT NOT NULL,
            raw_label_id VARCHAR NOT NULL,
            label_id_text VARCHAR NOT NULL,
            label_id BIGINT,
            label_definition_key VARCHAR,
            label_name VARCHAR,
            definition_match_count BIGINT NOT NULL,
            resolved BOOLEAN NOT NULL
        )
        """
    )


def validate_contacts_table_schema(duck: duckdb.DuckDBPyConnection) -> None:
    missing = CONTACT_COLUMNS - table_columns(duck, CHATLOG_SCHEMA, "contacts")
    if missing:
        raise ExportError(
            "baseline chatlog.contacts has an incompatible schema; missing column(s): "
            + ", ".join(sorted(missing))
        )


def validate_contact_tag_table_schemas(duck: duckdb.DuckDBPyConnection) -> None:
    for table, expected in (
        ("contact_tag_definitions", CONTACT_TAG_DEFINITION_COLUMNS),
        ("contact_tags", CONTACT_TAG_COLUMNS),
    ):
        missing = expected - table_columns(duck, CHATLOG_SCHEMA, table)
        if missing:
            raise ExportError(
                f"baseline chatlog.{table} has an incompatible schema; "
                "missing column(s): " + ", ".join(sorted(missing))
            )


def contact_value_expr(
    columns: dict[str, str], name: str, cast: str, qualifier: str | None = None
) -> str:
    actual = columns.get(name.casefold())
    if actual is None:
        return f"CAST(NULL AS {cast})"
    identifier = quote_ident(actual)
    if qualifier is not None:
        identifier = f"{quote_ident(qualifier)}.{identifier}"
    return f"CAST({identifier} AS {cast})"


def contact_flag_expr(columns: dict[str, str], name: str, qualifier: str) -> str:
    """Only canonical integral source values qualify; malformed flags stay unknown."""
    value = contact_value_expr(columns, name, "VARCHAR", qualifier)
    return (
        f"CASE WHEN regexp_full_match({value}, '-?(0|[1-9][0-9]*)') "
        f"THEN TRY_CAST({value} AS BIGINT) ELSE NULL END"
    )


def stage_contact_extra_buf_profiles(
    duck: duckdb.DuckDBPyConnection,
    raw: str,
    source_alias: str,
    extra_buf_column: str,
) -> str:
    """Create a temporary, rowid-keyed table of fail-soft ExtraBuf results."""
    table = "_contact_extra_buf_" + uuid.uuid4().hex
    duck.execute(
        f"""
        CREATE TEMP TABLE {quote_ident(table)} (
            source_rowid BIGINT NOT NULL,
            signature VARCHAR,
            add_scene BIGINT,
            add_scene_enum VARCHAR,
            add_scene_string VARCHAR,
            country VARCHAR,
            province VARCHAR,
            city VARCHAR,
            parse_status VARCHAR NOT NULL,
            parse_warning VARCHAR
        )
        """
    )
    rows = duck.execute(
        f"SELECT CAST({quote_ident(source_alias)}.rowid AS BIGINT), "
        f"{quote_ident(source_alias)}.{quote_ident(extra_buf_column)} "
        f"FROM {raw} AS {quote_ident(source_alias)} ORDER BY 1"
    ).fetchall()
    bulk_columns = (
        ("source_rowid", "BIGINT"),
        ("signature", "VARCHAR"),
        ("add_scene", "BIGINT"),
        ("add_scene_enum", "VARCHAR"),
        ("add_scene_string", "VARCHAR"),
        ("country", "VARCHAR"),
        ("province", "VARCHAR"),
        ("city", "VARCHAR"),
        ("parse_status", "VARCHAR"),
        ("parse_warning", "VARCHAR"),
    )
    for start in range(0, len(rows), BATCH_SIZE):
        decoded_rows = []
        for source_rowid, value in rows[start : start + BATCH_SIZE]:
            profile = parse_contact_extra_buf(value)
            decoded_rows.append(
                (
                    int(source_rowid),
                    profile.signature,
                    profile.add_scene,
                    profile.add_scene_enum,
                    profile.add_scene_string,
                    profile.country,
                    profile.province,
                    profile.city,
                    profile.parse_status,
                    profile.parse_warning,
                )
            )
        insert_batch(duck, quote_ident(table), decoded_rows, bulk_columns)
    return table


def count_nonblank_contact_tag_tokens(
    duck: duckdb.DuckDBPyConnection,
    raw_schema: str,
    raw_table: str,
    label_list_column: str,
) -> int:
    raw = f"{quote_ident(raw_schema)}.{quote_ident(raw_table)}"
    label_list = quote_ident(label_list_column)
    return int(
        duck.execute(
            f"""
            SELECT count(*)
            FROM (
                SELECT unnest(string_split(CAST({label_list} AS VARCHAR), ','))
                    AS raw_label_id
                FROM {raw}
            ) tokens
            WHERE trim(raw_label_id) <> ''
            """
        ).fetchone()[0]
    )


def insert_contacts(
    duck: duckdb.DuckDBPyConnection, imported: ImportedObject, kind: str
) -> int:
    columns = column_lookup(imported.source)
    raw = f"{quote_ident(imported.database.account.raw_schema)}.{quote_ident(imported.raw_table)}"
    source_alias = "raw_contact"
    account_id = sql_string(imported.database.account.account_id)
    version = (
        "NULL"
        if imported.database.account.version is None
        else str(imported.database.account.version)
    )
    database_id = sql_string(imported.database.database_id)
    relative = sql_string(imported.database.relative_path)
    raw_schema = sql_string(imported.database.account.raw_schema)
    raw_table = sql_string(imported.raw_table)
    source_object = sql_string(imported.source.name)
    profile_table: str | None = None
    profile_join = ""

    if kind == "windows_v3_contact":
        user_name = contact_value_expr(columns, "username", "VARCHAR", source_alias)
        alias = contact_value_expr(columns, "alias", "VARCHAR", source_alias)
        remark = contact_value_expr(columns, "remark", "VARCHAR", source_alias)
        nickname = contact_value_expr(columns, "nickname", "VARCHAR", source_alias)
        # The long profile note is Reserved6. Remark is only the short display name.
        description = contact_value_expr(columns, "reserved6", "VARCHAR", source_alias)
        # ContactV3 documents Reserved1: 1 is an address-book contact, 0 is
        # a nonfriend room member. Other values have no verified meaning.
        reserved1 = contact_flag_expr(columns, "reserved1", source_alias)
        is_friend = f"CASE WHEN {reserved1} IN (0, 1) THEN {reserved1} = 1 ELSE NULL END"
        extra_buf_column = columns.get("extrabuf")
        if extra_buf_column is None:
            signature = "CAST(NULL AS VARCHAR)"
            add_scene = "CAST(NULL AS INTEGER)"
            add_scene_enum = "CAST(NULL AS VARCHAR)"
            add_scene_string = "CAST(NULL AS VARCHAR)"
            country = "CAST(NULL AS VARCHAR)"
            province = "CAST(NULL AS VARCHAR)"
            city = "CAST(NULL AS VARCHAR)"
            parse_status = "'not_available'"
            parse_warning = "CAST(NULL AS VARCHAR)"
        else:
            profile_table = stage_contact_extra_buf_profiles(
                duck, raw, source_alias, extra_buf_column
            )
            profile_alias = quote_ident("extra_buf_profile")
            profile_join = (
                f" LEFT JOIN {quote_ident(profile_table)} AS {profile_alias} "
                f"ON {profile_alias}.source_rowid="
                f"CAST({quote_ident(source_alias)}.rowid AS BIGINT)"
            )
            signature = f"{profile_alias}.signature"
            add_scene = f"CAST({profile_alias}.add_scene AS INTEGER)"
            add_scene_enum = f"{profile_alias}.add_scene_enum"
            add_scene_string = f"{profile_alias}.add_scene_string"
            country = f"{profile_alias}.country"
            province = f"{profile_alias}.province"
            city = f"{profile_alias}.city"
            parse_status = f"{profile_alias}.parse_status"
            parse_warning = f"{profile_alias}.parse_warning"
    elif kind == "v4_contact":
        user_name = contact_value_expr(columns, "username", "VARCHAR", source_alias)
        alias = contact_value_expr(columns, "alias", "VARCHAR", source_alias)
        remark = contact_value_expr(columns, "remark", "VARCHAR", source_alias)
        nickname = contact_value_expr(columns, "nick_name", "VARCHAR", source_alias)
        description = contact_value_expr(columns, "description", "VARCHAR", source_alias)
        local_type = contact_flag_expr(columns, "local_type", source_alias)
        flag = contact_flag_expr(columns, "flag", source_alias)
        verify_flag = contact_flag_expr(columns, "verify_flag", source_alias)
        delete_flag = contact_flag_expr(columns, "delete_flag", source_alias)
        # Primary implementation documentation describes (flag & 3) != 0:
        # https://welink.click/database . Never treat local_type <> 3 or a
        # nonempty remark as positive friendship evidence. This is a local
        # address-book predicate, not proof of reciprocal server friendship.
        is_friend = (
            f"CASE WHEN {local_type} IN (2, 3) OR {delete_flag} = 1 "
            f"OR {verify_flag} > 0 THEN FALSE "
            f"WHEN {flag} IS NULL OR {flag} < 0 OR {verify_flag} IS NULL "
            f"OR {verify_flag} < 0 OR {delete_flag} IS NULL "
            f"OR {delete_flag} <> 0 THEN NULL "
            f"ELSE ({flag} & 3) <> 0 END"
        )
        signature = "CAST(NULL AS VARCHAR)"
        add_scene = "CAST(NULL AS INTEGER)"
        add_scene_enum = "CAST(NULL AS VARCHAR)"
        add_scene_string = "CAST(NULL AS VARCHAR)"
        country = "CAST(NULL AS VARCHAR)"
        province = "CAST(NULL AS VARCHAR)"
        city = "CAST(NULL AS VARCHAR)"
        parse_status = "'not_applicable'"
        parse_warning = "CAST(NULL AS VARCHAR)"
    elif kind == "darwin_v3_contact":
        user_name = contact_value_expr(columns, "m_nsusrname", "VARCHAR", source_alias)
        alias = contact_value_expr(columns, "m_nsaliasname", "VARCHAR", source_alias)
        remark = contact_value_expr(columns, "m_nsremark", "VARCHAR", source_alias)
        nickname = contact_value_expr(columns, "nickname", "VARCHAR", source_alias)
        # No Darwin v3 equivalent of Windows Reserved6 has been verified.
        description = "CAST(NULL AS VARCHAR)"
        # Table membership alone has not been verified as friendship evidence.
        is_friend = "CAST(NULL AS BOOLEAN)"
        signature = "CAST(NULL AS VARCHAR)"
        add_scene = "CAST(NULL AS INTEGER)"
        add_scene_enum = "CAST(NULL AS VARCHAR)"
        add_scene_string = "CAST(NULL AS VARCHAR)"
        country = "CAST(NULL AS VARCHAR)"
        province = "CAST(NULL AS VARCHAR)"
        city = "CAST(NULL AS VARCHAR)"
        parse_status = "'not_applicable'"
        parse_warning = "CAST(NULL AS VARCHAR)"
    else:  # pragma: no cover - callers classify the kind before dispatching
        raise ExportError(f"unsupported canonical contact kind: {kind}")

    # These source identities are not eligible person-to-person friends. Keep
    # their rows/raw evidence while avoiding the old broad contact predicate.
    is_friend = (
        f"CASE WHEN {user_name} IS NULL OR trim({user_name}) = '' THEN NULL "
        f"WHEN ends_with({user_name}, '@chatroom') OR starts_with({user_name}, 'gh_') "
        f"OR {user_name} = 'filehelper' OR {user_name} = "
        f"{sql_string(imported.database.account.account_name)} THEN FALSE "
        f"ELSE {is_friend} END"
    )

    try:
        source = quote_ident(source_alias)
        result = duck.execute(
            f"""
            INSERT INTO {quote_ident(CHATLOG_SCHEMA)}.contacts (
                account_id, wechat_version, source_kind, database_id,
                source_relative_path, raw_schema, raw_table, source_object,
                source_contact_key, source_rowid, user_name, alias, remark,
                nickname, description, is_friend, signature, add_scene,
                add_scene_enum, add_scene_string, country, province, city,
                extra_buf_parse_status, extra_buf_parse_warning
            )
            SELECT
                {account_id}, {version}, {sql_string(kind)}, {database_id}, {relative},
                {raw_schema}, {raw_table}, {source_object},
                {database_id} || ':' || {source_object} || ':' ||
                    CAST({source}.rowid AS VARCHAR),
                CAST({source}.rowid AS BIGINT),
                {user_name}, {alias}, {remark}, {nickname}, {description}, {is_friend},
                {signature}, {add_scene}, {add_scene_enum}, {add_scene_string},
                {country}, {province}, {city},
                {parse_status}, {parse_warning}
            FROM {raw} AS {source}{profile_join}
            """
        )
        return int(result.fetchone()[0])
    finally:
        if profile_table is not None:
            duck.execute(f"DROP TABLE IF EXISTS {quote_ident(profile_table)}")


def contact_tag_provenance(imported: ImportedObject) -> tuple[str, ...]:
    account = imported.database.account
    version = "NULL" if account.version is None else str(account.version)
    return (
        sql_string(account.account_id),
        version,
        sql_string(imported.database.database_id),
        sql_string(imported.database.relative_path),
        sql_string(account.raw_schema),
        sql_string(imported.raw_table),
        sql_string(imported.source.name),
    )


def insert_contact_tag_definitions(
    duck: duckdb.DuckDBPyConnection, imported: ImportedObject
) -> int:
    columns = column_lookup(imported.source)
    raw = f"{quote_ident(imported.database.account.raw_schema)}.{quote_ident(imported.raw_table)}"
    label_id = quote_ident(columns["labelid"])
    label_name = quote_ident(columns["labelname"])
    account_id, version, database_id, relative, raw_schema, raw_table, source_object = (
        contact_tag_provenance(imported)
    )
    result = duck.execute(
        f"""
        INSERT INTO {quote_ident(CHATLOG_SCHEMA)}.contact_tag_definitions
        SELECT
            {account_id}, {version}, 'windows_v3_contact_label', {database_id},
            {relative}, {raw_schema}, {raw_table}, {source_object},
            {database_id} || ':' || {source_object} || ':' || CAST(rowid AS VARCHAR),
            CAST(rowid AS BIGINT), CAST({label_id} AS VARCHAR),
            trim(CAST({label_id} AS VARCHAR)),
            try_cast(trim(CAST({label_id} AS VARCHAR)) AS BIGINT),
            CAST({label_name} AS VARCHAR)
        FROM {raw}
        """
    )
    return int(result.fetchone()[0])


def insert_contact_tags(
    duck: duckdb.DuckDBPyConnection, imported: ImportedObject
) -> int:
    columns = column_lookup(imported.source)
    label_list = columns.get("labelidlist")
    if label_list is None:
        return 0
    raw = f"{quote_ident(imported.database.account.raw_schema)}.{quote_ident(imported.raw_table)}"
    label_list = quote_ident(label_list)
    account_id, version, database_id, relative, raw_schema, raw_table, source_object = (
        contact_tag_provenance(imported)
    )
    source_contact_key = (
        f"{database_id} || ':' || {source_object} || ':' || CAST(rowid AS VARCHAR)"
    )
    result = duck.execute(
        f"""
        INSERT INTO {quote_ident(CHATLOG_SCHEMA)}.contact_tags
        WITH contact_tokens AS (
            SELECT
                CAST(rowid AS BIGINT) AS source_contact_rowid,
                {source_contact_key} AS source_contact_key,
                unnest(string_split(CAST({label_list} AS VARCHAR), ','))
                    AS raw_label_id,
                generate_subscripts(
                    string_split(CAST({label_list} AS VARCHAR), ','), 1
                ) AS tag_ordinal
            FROM {raw}
        ),
        tokens AS (
            SELECT
                source_contact_rowid, source_contact_key, tag_ordinal,
                raw_label_id, trim(raw_label_id) AS label_id_text,
                try_cast(trim(raw_label_id) AS BIGINT) AS label_id
            FROM contact_tokens
            WHERE trim(raw_label_id) <> ''
        ),
        ranked_definitions AS (
            SELECT
                source_label_key, label_id, label_name,
                count(*) OVER (PARTITION BY label_id) AS definition_match_count
            FROM {quote_ident(CHATLOG_SCHEMA)}.contact_tag_definitions
            WHERE database_id={database_id} AND label_id IS NOT NULL
        ),
        definition_summary AS (
            SELECT
                label_id,
                max(definition_match_count) AS definition_match_count,
                max(CASE WHEN definition_match_count=1 THEN source_label_key END)
                    AS source_label_key,
                max(CASE WHEN definition_match_count=1 THEN label_name END)
                    AS label_name
            FROM ranked_definitions
            GROUP BY label_id
        )
        SELECT
            {account_id}, {version}, 'windows_v3_contact_tag', {database_id},
            {relative}, {raw_schema}, {raw_table}, {source_object},
            tokens.source_contact_key, tokens.source_contact_rowid,
            tokens.source_contact_key || ':' || CAST(tokens.tag_ordinal AS VARCHAR),
            tokens.tag_ordinal, tokens.raw_label_id, tokens.label_id_text,
            tokens.label_id, definitions.source_label_key, definitions.label_name,
            coalesce(definitions.definition_match_count, 0),
            definitions.source_label_key IS NOT NULL
        FROM tokens
        LEFT JOIN definition_summary definitions
          ON definitions.label_id=tokens.label_id
        """
    )
    return int(result.fetchone()[0])


def project_contact_tag_objects(
    duck: duckdb.DuckDBPyConnection,
    imported_objects: Sequence[ImportedObject],
    allow_partial: bool,
) -> None:
    grouped: dict[str, dict[str, ImportedObject]] = {}
    for imported in imported_objects:
        role = windows_v3_contact_tag_role(imported)
        if role is not None:
            grouped.setdefault(imported.database.database_id, {})[role] = imported

    for objects in grouped.values():
        contact = objects.get("contact")
        definition = objects.get("definition")
        if contact is not None and "username" not in column_lookup(contact.source):
            contact = None
        if definition is not None:
            missing = {"labelid", "labelname"} - set(column_lookup(definition.source))
            if missing:
                error = ExportError(
                    f"canonical contact-label object {definition.source.name!r} "
                    "is missing columns: " + ", ".join(sorted(missing))
                )
                record_error(
                    duck,
                    "contact_tag_projection",
                    error,
                    definition.database.account.account_id,
                    definition.database.database_id,
                    definition.source.name,
                )
                if not allow_partial:
                    raise error
                definition = None
        if contact is None and definition is None:
            continue
        duck.execute("BEGIN TRANSACTION")
        try:
            if definition is not None:
                inserted = insert_contact_tag_definitions(duck, definition)
                if inserted != definition.imported_rows:
                    raise ExportError(
                        "contact-label definition row-count mismatch for "
                        f"{definition.source.name}: raw={definition.imported_rows}, "
                        f"projected={inserted}"
                    )
            if contact is not None:
                insert_contact_tags(duck, contact)
            duck.execute("COMMIT")
        except Exception as exc:
            duck.execute("ROLLBACK")
            source = contact if contact is not None else definition
            assert source is not None
            record_error(
                duck,
                "contact_tag_projection",
                exc,
                source.database.account.account_id,
                source.database.database_id,
                source.source.name,
            )
            if not allow_partial:
                raise


def project_contact_objects(
    duck: duckdb.DuckDBPyConnection,
    imported_objects: Sequence[ImportedObject],
    allow_partial: bool,
) -> None:
    for imported in imported_objects:
        kind, required = canonical_contact_kind(imported)
        if kind is None:
            continue
        available = set(column_lookup(imported.source))
        missing = sorted(required - available)
        if missing:
            error = ExportError(
                f"canonical contact object {imported.source.name!r} is missing columns: "
                + ", ".join(missing)
            )
            record_error(
                duck,
                "contact_projection",
                error,
                imported.database.account.account_id,
                imported.database.database_id,
                imported.source.name,
            )
            if not allow_partial:
                raise error
            continue
        duck.execute("BEGIN TRANSACTION")
        try:
            projected_rows = insert_contacts(duck, imported, kind)
            if projected_rows != imported.imported_rows:
                raise ExportError(
                    f"contact projection row-count mismatch for {imported.source.name}: "
                    f"raw={imported.imported_rows}, projected={projected_rows}"
                )
            duck.execute("COMMIT")
        except Exception as exc:
            duck.execute("ROLLBACK")
            record_error(
                duck,
                "contact_projection",
                exc,
                imported.database.account.account_id,
                imported.database.database_id,
                imported.source.name,
            )
            if not allow_partial:
                raise


def build_contacts(
    duck: duckdb.DuckDBPyConnection,
    imported_objects: Sequence[ImportedObject],
    allow_partial: bool,
) -> int:
    create_contacts_table(duck)
    create_contact_tag_tables(duck)
    project_contact_objects(duck, imported_objects, allow_partial)
    project_contact_tag_objects(duck, imported_objects, allow_partial)
    return int(
        duck.execute(
            f"SELECT count(*) FROM {quote_ident(CHATLOG_SCHEMA)}.contacts"
        ).fetchone()[0]
    )


def record_contact_extra_buf_warnings(duck: duckdb.DuckDBPyConnection) -> None:
    """Catalog one non-sensitive warning per malformed source object."""
    for account_id, database_id, source_object, row_count in duck.execute(
        f"SELECT account_id, database_id, source_object, count(*) "
        f"FROM {quote_ident(CHATLOG_SCHEMA)}.contacts "
        "WHERE extra_buf_parse_status='malformed' "
        "GROUP BY account_id, database_id, source_object"
    ).fetchall():
        record_warning(
            duck,
            "contact_extra_buf",
            f"{int(row_count)} Contact.ExtraBuf row(s) could not be decoded; "
            "decoded profile fields are NULL; see "
            "chatlog.contacts.extra_buf_parse_warning",
            str(account_id),
            str(database_id),
            str(source_object),
        )


def create_messages_table(duck: duckdb.DuckDBPyConnection) -> None:
    duck.execute(
        f"""
        CREATE TABLE {quote_ident(CHATLOG_SCHEMA)}.messages (
            account_id VARCHAR NOT NULL,
            wechat_version INTEGER,
            source_kind VARCHAR NOT NULL,
            database_id VARCHAR NOT NULL,
            source_relative_path VARCHAR,
            raw_schema VARCHAR NOT NULL,
            raw_table VARCHAR NOT NULL,
            source_object VARCHAR NOT NULL,
            source_message_key VARCHAR,
            source_local_id BIGINT,
            server_id HUGEINT,
            sequence BIGINT,
            create_time BIGINT,
            created_at TIMESTAMPTZ,
            talker_id VARCHAR,
            talker_hash VARCHAR,
            sender_id VARCHAR,
            is_chat_room BOOLEAN,
            is_self BOOLEAN,
            message_type BIGINT,
            message_subtype BIGINT,
            raw_type BIGINT,
            raw_subtype BIGINT,
            status BIGINT,
            status_ex BIGINT,
            flag_ex BIGINT,
            msg_server_seq BIGINT,
            msg_sequence BIGINT,
            raw_content VARCHAR,
            display_content VARCHAR,
            message_content BLOB,
            compressed_content BLOB,
            packed_info_data BLOB,
            bytes_extra BLOB,
            bytes_trans BLOB,
            translated_content VARCHAR,
            translated_brand VARCHAR
        )
        """
    )


def create_v4_maps(
    duck: duckdb.DuckDBPyConnection,
    imported_objects: Sequence[ImportedObject],
    replace_account_ids: set[str] | None = None,
) -> None:
    create_clause = "CREATE TABLE" if replace_account_ids is None else "CREATE TABLE IF NOT EXISTS"
    duck.execute(
        f"""
        {create_clause} {quote_ident(CHATLOG_SCHEMA)}.v4_talker_map (
            account_id VARCHAR NOT NULL,
            talker_hash VARCHAR NOT NULL,
            user_name VARCHAR NOT NULL,
            candidate_sources BIGINT NOT NULL
        )
        """
    )
    if replace_account_ids:
        placeholders = ", ".join("?" for _ in replace_account_ids)
        duck.execute(
            f"DELETE FROM {quote_ident(CHATLOG_SCHEMA)}.v4_talker_map "
            f"WHERE account_id IN ({placeholders})",
            sorted(replace_account_ids),
        )
    candidates: dict[tuple[str, str], set[str]] = {}
    for imported in imported_objects:
        if imported.database.account.version != 4:
            continue
        if (
            replace_account_ids is not None
            and imported.database.account.account_id not in replace_account_ids
        ):
            continue
        folded = imported.source.name.casefold()
        columns = column_lookup(imported.source)
        candidate_column = None
        if folded in {"contact", "sessiontable"}:
            candidate_column = columns.get("username")
        elif folded == "name2id":
            candidate_column = columns.get("user_name")
        if candidate_column is None:
            continue
        raw = f"{quote_ident(imported.database.account.raw_schema)}.{quote_ident(imported.raw_table)}"
        for (value,) in duck.execute(
            f"SELECT DISTINCT CAST({quote_ident(candidate_column)} AS VARCHAR) "
            f"FROM {raw} WHERE {quote_ident(candidate_column)} IS NOT NULL"
        ).fetchall():
            if not value:
                continue
            key = (imported.database.account.account_id, str(value))
            candidates.setdefault(key, set()).add(imported.object_id)
    rows = [
        (
            account_id,
            hashlib.md5(user_name.encode("utf-8"), usedforsecurity=False).hexdigest(),
            user_name,
            len(sources),
        )
        for (account_id, user_name), sources in candidates.items()
    ]
    if rows:
        duck.executemany(
            f"INSERT INTO {quote_ident(CHATLOG_SCHEMA)}.v4_talker_map VALUES (?, ?, ?, ?)", rows
        )

    duck.execute(
        f"""
        {create_clause} {quote_ident(CHATLOG_SCHEMA)}.v4_sender_map (
            account_id VARCHAR NOT NULL,
            database_id VARCHAR NOT NULL,
            source_rowid BIGINT NOT NULL,
            user_name VARCHAR
        )
        """
    )
    seen_databases: set[str] = set()
    sender_rows: list[tuple[str, str, int, str | None]] = []
    for imported in imported_objects:
        database = imported.database
        if database.account.version != 4 or imported.source.name.casefold() != "name2id" or database.database_id in seen_databases:
            continue
        if (
            replace_account_ids is not None
            and database.account.account_id not in replace_account_ids
        ):
            continue
        seen_databases.add(database.database_id)
        user_column = column_lookup(imported.source).get("user_name")
        if user_column is None:
            raise ExportError("v4 Name2Id lacks its verified user_name source column")
        ownership = duck.execute(
            f"SELECT o.account_id,o.database_id,o.raw_schema,o.raw_table,d.account_id,d.present "
            f"FROM {quote_ident(CATALOG_SCHEMA)}.objects o JOIN "
            f"{quote_ident(CATALOG_SCHEMA)}.database_files d ON d.database_id=o.database_id "
            "WHERE o.object_id=? AND o.import_status='ok'",
            [imported.object_id],
        ).fetchone()
        if ownership != (database.account.account_id, database.database_id, database.account.raw_schema, imported.raw_table, database.account.account_id, True):
            raise ExportError("v4 sender source does not match its current account/database partition")
        raw = f"{quote_ident(database.account.raw_schema)}.{quote_ident(imported.raw_table)}"
        raw_columns = dict(destination_columns(duck, raw))
        if raw_columns.get(user_column) != "VARCHAR":
            raise ExportError("v4 Name2Id user_name must be retained as text")
        names = quote_ident(user_column)
        source_rows = int(duck.execute(f"SELECT count(*) FROM {raw}").fetchone()[0])
        if source_rows != imported.imported_rows:
            raise ExportError("v4 Name2Id retained row count changed")
        if V4_SENDER_ROWID_COLUMN not in raw_columns:
            # Legacy raw exports omitted implicit SQLite rowid. Their existing
            # source-rowid map is the only verified identity evidence. Validate
            # and retain it; never infer rowid from DuckDB order or stale paths.
            count, unique = duck.execute(
                f"SELECT count(*),count(DISTINCT source_rowid) FROM {quote_ident(CHATLOG_SCHEMA)}.v4_sender_map "
                "WHERE account_id=? AND database_id=?",
                [database.account.account_id, database.database_id],
            ).fetchone()
            invalid = duck.execute(
                f"SELECT count(*) FROM (SELECT sm.user_name FROM "
                f"{quote_ident(CHATLOG_SCHEMA)}.v4_sender_map sm "
                "WHERE sm.account_id=? AND sm.database_id=? EXCEPT ALL "
                f"SELECT r.{names} FROM {raw} r) AS unmatched_names",
                [database.account.account_id, database.database_id],
            ).fetchone()[0]
            if count != source_rows or unique != count or invalid:
                raise ExportError("Legacy v4 Name2Id has no verified complete retained sender map; create a full export")
            continue
        if raw_columns[V4_SENDER_ROWID_COLUMN] != "BIGINT":
            raise ExportError("v4 Name2Id SQLite row-id provenance must be integral")
        rowid_column = quote_ident(V4_SENDER_ROWID_COLUMN)
        count, unique = duck.execute(f"SELECT count(*),count(DISTINCT {rowid_column}) FROM {raw}").fetchone()
        if count != unique:
            raise ExportError("v4 Name2Id SQLite row-id provenance is missing or duplicated")
        duck.execute(
            f"DELETE FROM {quote_ident(CHATLOG_SCHEMA)}.v4_sender_map WHERE account_id=? AND database_id=?",
            [database.account.account_id, database.database_id],
        )
        sender_rows.extend(
            (database.account.account_id, database.database_id, int(rowid), user_name)
            for rowid, user_name in duck.execute(f"SELECT {rowid_column},{names} FROM {raw}").fetchall()
        )
    if sender_rows:
        duck.executemany(
            f"INSERT INTO {quote_ident(CHATLOG_SCHEMA)}.v4_sender_map VALUES (?, ?, ?, ?)",
            sender_rows,
        )


def insert_v3_messages(duck: duckdb.DuckDBPyConnection, imported: ImportedObject, kind: str) -> int:
    columns = column_lookup(imported.source)
    raw = f"{quote_ident(imported.database.account.raw_schema)}.{quote_ident(imported.raw_table)}"
    account_id = sql_string(imported.database.account.account_id)
    version = "NULL" if imported.database.account.version is None else str(imported.database.account.version)
    relative = sql_string(imported.database.relative_path)
    database_id = sql_string(imported.database.database_id)
    raw_schema = sql_string(imported.database.account.raw_schema)
    raw_table = sql_string(imported.raw_table)
    source_object = sql_string(imported.source.name)
    local_id = columns["localid"]
    talker = columns["strtalker"]
    sender_flag = contact_flag_expr(columns, "issender", "raw_message")
    create_time = columns["createtime"]
    raw_type = columns["type"]
    raw_subtype_expr = (
        f"CAST({quote_ident(columns['subtype'])} AS BIGINT)" if "subtype" in columns else "NULL"
    )
    semantic_subtype_expr = (
        f"CASE WHEN {raw_subtype_expr} IS NOT NULL AND {raw_subtype_expr} <> 0 "
        f"THEN {raw_subtype_expr} ELSE CAST({quote_ident(raw_type)} AS BIGINT) >> 32 END"
    )
    sequence_expr = (
        f"CAST({quote_ident(columns['sequence'])} AS BIGINT)" if "sequence" in columns else "NULL"
    )
    result = duck.execute(
        f"""
        INSERT INTO {quote_ident(CHATLOG_SCHEMA)}.messages
        SELECT
            {account_id}, {version}, {sql_string(kind)}, {database_id}, {relative},
            {raw_schema}, {raw_table}, {source_object},
            {database_id} || ':' || {source_object} || ':' || CAST({quote_ident(local_id)} AS VARCHAR),
            CAST({quote_ident(local_id)} AS BIGINT),
            {expr(columns, 'msgsvrid', 'BIGINT')},
            {sequence_expr},
            CAST({quote_ident(create_time)} AS BIGINT),
            CASE WHEN CAST({quote_ident(create_time)} AS BIGINT) BETWEEN 0 AND 253402300799
                 THEN to_timestamp(CAST({quote_ident(create_time)} AS BIGINT)) ELSE NULL END,
            CAST({quote_ident(talker)} AS VARCHAR), NULL,
            CASE WHEN {sender_flag} = 0
                      AND NOT ends_with(CAST({quote_ident(talker)} AS VARCHAR), '@chatroom')
                 THEN CAST({quote_ident(talker)} AS VARCHAR) ELSE NULL END,
            ends_with(CAST({quote_ident(talker)} AS VARCHAR), '@chatroom'),
            CASE WHEN {sender_flag} IN (0, 1) THEN {sender_flag} = 1 ELSE NULL END,
            CAST({quote_ident(raw_type)} AS BIGINT) & 4294967295,
            {semantic_subtype_expr},
            CAST({quote_ident(raw_type)} AS BIGINT), {raw_subtype_expr},
            {expr(columns, 'status', 'BIGINT')},
            {expr(columns, 'statusex', 'BIGINT')},
            {expr(columns, 'flagex', 'BIGINT')},
            {expr(columns, 'msgserverseq', 'BIGINT')},
            {expr(columns, 'msgsequence', 'BIGINT')},
            {expr(columns, 'strcontent', 'VARCHAR')},
            {expr(columns, 'displaycontent', 'VARCHAR')},
            NULL,
            {expr(columns, 'compresscontent', 'BLOB')},
            NULL,
            {expr(columns, 'bytesextra', 'BLOB')},
            {expr(columns, 'bytestrans', 'BLOB')},
            {expr(columns, 'translatedcontent', 'VARCHAR')},
            {expr(columns, 'translatedbrand', 'VARCHAR')}
        FROM {raw} AS raw_message
        """
    )
    return int(result.fetchone()[0])


def sender_direction_expr(sender: str, talker: str, owner: str) -> str:
    """Use resolved identities; unrelated private senders do not prove outgoing."""
    known_owner = f"({owner} IS NOT NULL AND trim({owner}) <> '')"
    return (
        f"CASE WHEN {sender} IS NULL OR trim({sender}) = '' THEN NULL "
        f"WHEN {known_owner} AND {sender} = {owner} THEN TRUE "
        f"WHEN {talker} IS NOT NULL AND trim({talker}) <> '' "
        f"AND NOT ends_with({talker}, '@chatroom') AND {sender} = {talker} THEN FALSE "
        f"WHEN {known_owner} AND ends_with({talker}, '@chatroom') THEN FALSE "
        f"ELSE NULL END"
    )


def refresh_identity_directions(duck: duckdb.DuckDBPyConnection) -> None:
    """Correct reused v4/phone rows without opening live sources or changing keys."""
    owner = "NULLIF(a.account_name, a.account_id)"
    direction = sender_direction_expr("m.sender_id", "m.talker_id", owner)
    duck.execute(
        f"UPDATE {quote_ident(CHATLOG_SCHEMA)}.messages AS m SET is_self={direction} "
        f"FROM {quote_ident(CATALOG_SCHEMA)}.accounts AS a "
        "WHERE a.account_id=m.account_id AND m.source_kind IN ('v4_msg', 'phone_backup')"
    )


def insert_v4_messages(duck: duckdb.DuckDBPyConnection, imported: ImportedObject) -> int:
    columns = column_lookup(imported.source)
    raw = f"{quote_ident(imported.database.account.raw_schema)}.{quote_ident(imported.raw_table)}"
    account_id_value = imported.database.account.account_id
    account_id = sql_string(account_id_value)
    database_id_value = imported.database.database_id
    database_id = sql_string(database_id_value)
    relative = sql_string(imported.database.relative_path)
    version = "NULL" if imported.database.account.version is None else str(imported.database.account.version)
    raw_schema = sql_string(imported.database.account.raw_schema)
    raw_table = sql_string(imported.raw_table)
    source_object = sql_string(imported.source.name)
    talker_hash = imported.source.name[4:].lower()
    raw_type = quote_ident(columns["local_type"])
    create_time = quote_ident(columns["create_time"])
    status = quote_ident(columns["status"])
    sender_id = quote_ident(columns["real_sender_id"])
    local_id = quote_ident(columns["local_id"])
    raw_types = {
        name.casefold(): data_type.upper()
        for name, data_type in destination_columns(duck, raw)
    }

    def payload_as_blob(column_name: str) -> str:
        actual = columns[column_name]
        qualified = f"m.{quote_ident(actual)}"
        data_type = raw_types.get(actual.casefold(), "")
        if data_type == "BLOB":
            return qualified
        return f"encode(CAST({qualified} AS VARCHAR))"

    message_content = payload_as_blob("message_content")
    packed_info_data = payload_as_blob("packed_info_data")
    # status=2 is a transport heuristic marked inaccurate in MessageV4.Wrap.
    # account_id contains a path hash; only account_name is a sender username.
    direction = sender_direction_expr(
        "sm.user_name", "tm.user_name", sql_string(imported.database.account.account_name)
    )
    result = duck.execute(
        f"""
        INSERT INTO {quote_ident(CHATLOG_SCHEMA)}.messages
        SELECT
            {account_id}, {version}, 'v4_msg', {database_id}, {relative},
            {raw_schema}, {raw_table}, {source_object},
            {database_id} || ':' || {source_object} || ':' || CAST(m.{local_id} AS VARCHAR),
            CAST(m.{local_id} AS BIGINT),
            CAST(m.{quote_ident(columns['server_id'])} AS BIGINT),
            CAST(m.{quote_ident(columns['sort_seq'])} AS BIGINT),
            CAST(m.{create_time} AS BIGINT),
            CASE WHEN CAST(m.{create_time} AS BIGINT) BETWEEN 0 AND 253402300799
                 THEN to_timestamp(CAST(m.{create_time} AS BIGINT)) ELSE NULL END,
            tm.user_name, {sql_string(talker_hash)}, sm.user_name,
            CASE WHEN tm.user_name IS NULL THEN NULL ELSE ends_with(tm.user_name, '@chatroom') END,
            {direction},
            CAST(m.{raw_type} AS BIGINT) & 4294967295,
            CAST(m.{raw_type} AS BIGINT) >> 32,
            CAST(m.{raw_type} AS BIGINT), NULL,
            CAST(m.{status} AS BIGINT), NULL, NULL, NULL, NULL,
            NULL, NULL,
            {message_content},
            NULL,
            {packed_info_data},
            NULL, NULL, NULL, NULL
        FROM {raw} AS m
        LEFT JOIN {quote_ident(CHATLOG_SCHEMA)}.v4_talker_map AS tm
          ON tm.account_id = {account_id} AND tm.talker_hash = {sql_string(talker_hash)}
        LEFT JOIN {quote_ident(CHATLOG_SCHEMA)}.v4_sender_map AS sm
          ON sm.account_id = {account_id}
         AND sm.database_id = {database_id}
         AND sm.source_rowid = CAST(m.{sender_id} AS BIGINT)
        """
    )
    return int(result.fetchone()[0])


def project_message_objects(
    duck: duckdb.DuckDBPyConnection,
    imported_objects: Sequence[ImportedObject],
    allow_partial: bool,
) -> None:
    for imported in imported_objects:
        kind, required = canonical_kind(imported)
        if kind is None:
            continue
        available = set(column_lookup(imported.source))
        missing = sorted(required - available)
        if missing:
            error = ExportError(
                f"canonical message object {imported.source.name!r} is missing columns: {', '.join(missing)}"
            )
            record_error(
                duck,
                "message_projection",
                error,
                imported.database.account.account_id,
                imported.database.database_id,
                imported.source.name,
            )
            if not allow_partial:
                raise error
            continue
        duck.execute("BEGIN TRANSACTION")
        try:
            if kind == "v4_msg":
                projected_rows = insert_v4_messages(duck, imported)
            else:
                projected_rows = insert_v3_messages(duck, imported, kind)
            if projected_rows != imported.imported_rows:
                raise ExportError(
                    f"message projection row-count mismatch for {imported.source.name}: "
                    f"raw={imported.imported_rows}, projected={projected_rows}"
                )
            duck.execute("COMMIT")
        except Exception as exc:
            duck.execute("ROLLBACK")
            record_error(
                duck,
                "message_projection",
                exc,
                imported.database.account.account_id,
                imported.database.database_id,
                imported.source.name,
            )
            if not allow_partial:
                raise


def build_messages(
    duck: duckdb.DuckDBPyConnection,
    imported_objects: Sequence[ImportedObject],
    allow_partial: bool,
) -> int:
    create_messages_table(duck)
    create_v4_maps(duck, imported_objects)
    project_message_objects(duck, imported_objects, allow_partial)
    return int(duck.execute(f"SELECT count(*) FROM {quote_ident(CHATLOG_SCHEMA)}.messages").fetchone()[0])


def create_backup_message_tables(duck: duckdb.DuckDBPyConnection) -> None:
    duck.execute(
        f"""
        CREATE TABLE IF NOT EXISTS {quote_ident(CHATLOG_SCHEMA)}.backup_archive_files (
            archive_file_key VARCHAR NOT NULL,
            account_id VARCHAR NOT NULL,
            database_id VARCHAR NOT NULL,
            payload_kind VARCHAR NOT NULL,
            source_name VARCHAR NOT NULL,
            source_path VARCHAR NOT NULL,
            source_size BIGINT NOT NULL,
            source_modified_ns HUGEINT NOT NULL,
            indexed_segments BIGINT NOT NULL,
            indexed_bytes HUGEINT NOT NULL,
            unindexed_bytes HUGEINT NOT NULL
        )
        """
    )
    duck.execute(
        f"""
        CREATE TABLE IF NOT EXISTS {quote_ident(CHATLOG_SCHEMA)}.backup_text_segments (
            segment_key VARCHAR NOT NULL,
            account_id VARCHAR NOT NULL,
            database_id VARCHAR NOT NULL,
            index_rowid BIGINT NOT NULL,
            talker_numeric_id BIGINT NOT NULL,
            talker_id VARCHAR,
            segment_id VARCHAR,
            start_time BIGINT,
            end_time BIGINT,
            bundle_path VARCHAR NOT NULL,
            source_file VARCHAR NOT NULL,
            source_offset BIGINT NOT NULL,
            encrypted_length BIGINT NOT NULL,
            plaintext_length BIGINT NOT NULL,
            padding_length INTEGER NOT NULL,
            root_value BLOB NOT NULL,
            message_count BIGINT NOT NULL,
            ciphertext_sha256 VARCHAR NOT NULL,
            plaintext_sha256 VARCHAR NOT NULL
        )
        """
    )
    duck.execute(
        f"""
        CREATE TABLE IF NOT EXISTS {quote_ident(CHATLOG_SCHEMA)}.backup_message_records (
            source_message_key VARCHAR NOT NULL,
            account_id VARCHAR NOT NULL,
            database_id VARCHAR NOT NULL,
            segment_key VARCHAR NOT NULL,
            message_ordinal BIGINT NOT NULL,
            record_offset BIGINT NOT NULL,
            record_length BIGINT NOT NULL,
            talker_id VARCHAR,
            sender_id VARCHAR,
            recipient_id VARCHAR,
            message_type BIGINT,
            create_time BIGINT,
            server_id UBIGINT,
            msg_sequence BIGINT,
            sequence BIGINT,
            content VARCHAR,
            raw_record BLOB NOT NULL
        )
        """
    )


def _safe_archive_path(bundle_root: Path, raw_name: Any) -> Path:
    name = _optional_utf8(raw_name)
    if not name or Path(name).name != name or "/" in name or "\\" in name:
        raise ExportError(f"unsafe phone-backup payload name: {name!r}")
    path = (bundle_root / name).resolve()
    root_prefix = str(bundle_root.resolve()).rstrip("\\/") + os.sep
    if not str(path).startswith(root_prefix):
        raise ExportError(f"phone-backup payload escapes its bundle: {name!r}")
    try:
        stat = path.lstat()
    except OSError as exc:
        raise ExportError(f"phone-backup payload is unavailable: {name!r}: {safe_error(exc)}") from exc
    reparse_flag = getattr(stat, "st_file_attributes", 0) & getattr(os, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    if path.is_symlink() or reparse_flag or not path.is_file():
        raise ExportError(f"phone-backup payload is not a regular non-reparse file: {name!r}")
    return path


def catalog_backup_archive_files(
    duck: duckdb.DuckDBPyConnection,
    database: DatabaseSpec,
    bundle_root: Path,
) -> None:
    if database.staged_path is None:
        raise ExportError("phone-backup index has no staged path")
    connection = open_sqlite(database.staged_path)
    try:
        tables = {
            str(name).casefold(): str(name)
            for (name,) in connection.execute("SELECT name FROM sqlite_schema WHERE type='table'")
        }
        specifications = [
            ("text", tables.get("msgsegments"), "FilePath"),
            ("media", tables.get("msgfilesegment") or tables.get("msgfilesegments"), "FileName"),
        ]
        referenced: set[str] = set()
        for kind, table, file_column in specifications:
            if table is None:
                raise ExportError(f"Backup.db is missing the required {kind} segment index")
            columns = {
                str(row[1]).casefold(): str(row[1])
                for row in connection.execute(f"PRAGMA table_info({quote_ident(table)})")
            }
            actual_file = columns.get(file_column.casefold())
            actual_offset = columns.get("offset")
            actual_length = columns.get("length")
            if not actual_file or not actual_offset or not actual_length:
                raise ExportError(f"{table} is missing file, offset, or length columns")
            current_name: str | None = None
            current_path: Path | None = None
            current_stat: os.stat_result | None = None
            expected_offset = 0
            indexed_bytes = 0
            segment_count = 0

            def flush() -> None:
                nonlocal current_name, current_path, current_stat, expected_offset, indexed_bytes, segment_count
                if current_name is None or current_path is None or current_stat is None:
                    return
                after = current_path.stat()
                if after.st_size != current_stat.st_size or after.st_mtime_ns != current_stat.st_mtime_ns:
                    raise ExportError(f"phone-backup payload changed during validation: {current_name}")
                if expected_offset != current_stat.st_size:
                    raise ExportError(
                        f"phone-backup index does not reach the end of {current_name}: "
                        f"indexed_end={expected_offset}, size={current_stat.st_size}"
                    )
                unindexed = current_stat.st_size - indexed_bytes
                if kind == "media" and unindexed != 0:
                    raise ExportError(f"media payload {current_name} has {unindexed} unindexed byte(s)")
                archive_key = short_hash(database.database_id + "\0" + current_name, 32)
                duck.execute(
                    f"INSERT INTO {quote_ident(CHATLOG_SCHEMA)}.backup_archive_files VALUES "
                    "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    [
                        archive_key,
                        database.account.account_id,
                        database.database_id,
                        kind,
                        current_name,
                        str(current_path),
                        current_stat.st_size,
                        current_stat.st_mtime_ns,
                        segment_count,
                        indexed_bytes,
                        unindexed,
                    ],
                )

            query = (
                f"SELECT {quote_ident(actual_file)}, {quote_ident(actual_offset)}, "
                f"{quote_ident(actual_length)} FROM {quote_ident(table)} "
                f"ORDER BY {quote_ident(actual_file)}, {quote_ident(actual_offset)}"
            )
            for raw_name, raw_offset, raw_length in connection.execute(query):
                name = _optional_utf8(raw_name)
                if not name:
                    raise ExportError(f"{table} contains an empty payload filename")
                offset = int(raw_offset)
                length = int(raw_length)
                if name != current_name:
                    flush()
                    current_name = name
                    current_path = _safe_archive_path(bundle_root, name)
                    current_stat = current_path.stat()
                    referenced.add(name.casefold())
                    expected_offset = 0
                    indexed_bytes = 0
                    segment_count = 0
                assert current_stat is not None
                if offset < expected_offset:
                    raise ExportError(f"overlapping indexed ranges in {name} at offset {offset}")
                if offset < 0 or length <= 0 or length % 16 != 0 or offset + length > current_stat.st_size:
                    raise ExportError(f"invalid indexed range in {name}: offset={offset}, length={length}")
                expected_offset = offset + length
                indexed_bytes += length
                segment_count += 1
            flush()

        inventory = {
            entry.name.casefold()
            for entry in bundle_root.iterdir()
            if entry.is_file() and re.fullmatch(r"BAK_[0-9]+_(?:TEXT|MEDIA)", entry.name, re.IGNORECASE)
        }
        if inventory != referenced:
            missing = sorted(inventory - referenced)
            absent = sorted(referenced - inventory)
            raise ExportError(
                f"phone-backup payload inventory mismatch; unindexed={missing}, missing={absent}"
            )
    finally:
        connection.close()


def _hash_text(value: Any) -> str:
    if isinstance(value, bytes):
        return value.hex()
    return str(value)


def _optional_utf8(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    if isinstance(value, (bytes, bytearray, memoryview)):
        try:
            return bytes(value).decode("utf-8")
        except UnicodeDecodeError:
            return None
    return str(value)


def phone_backup_auxiliary_sha256(directory: Path) -> str:
    """Mirror the Go stager's domain-separated BAK inventory fingerprint."""

    def inventory() -> list[tuple[str, str, Path, tuple[int, int, int, int, int]]]:
        result: list[tuple[str, str, Path, tuple[int, int, int, int, int]]] = []
        seen: set[str] = set()
        try:
            entries = list(os.scandir(directory))
        except OSError as exc:
            raise ExportError(
                f"cannot inventory phone-backup directory {directory}: {safe_error(exc)}"
            ) from exc
        for entry in entries:
            upper = entry.name.upper()
            if upper.startswith("BAK_") and upper.endswith("_TEXT"):
                kind = "text"
            elif upper.startswith("BAK_") and upper.endswith("_MEDIA"):
                kind = "media"
            else:
                continue
            identity = entry.name.lower()
            if identity in seen:
                raise ExportError(
                    f"duplicate case-insensitive phone-backup payload name: {entry.name}"
                )
            seen.add(identity)
            path = Path(entry.path)
            try:
                # pathlib's Windows stat populates stable file identity fields;
                # DirEntry.stat can report zero device/inode values there.
                stat = path.stat(follow_symlinks=False)
            except OSError as exc:
                raise ExportError(
                    f"cannot inspect phone-backup payload {entry.path}: {safe_error(exc)}"
                ) from exc
            if entry.is_symlink() or not entry.is_file(follow_symlinks=False):
                raise ExportError(
                    f"phone-backup payload is not a regular non-symlink file: {entry.path}"
                )
            state = (
                int(stat.st_size),
                int(stat.st_mtime_ns),
                int(stat.st_mode),
                int(stat.st_dev),
                int(stat.st_ino),
            )
            result.append((entry.name, kind, path, state))
        result.sort(key=lambda item: (item[0].lower(), item[0]))
        return result

    before = inventory()
    digest = hashlib.sha256()
    digest.update(b"wechat-phone-backup-auxiliary-v1\x00")
    for name, kind, path, state in before:
        encoded_name = name.encode("utf-8")
        encoded_kind = kind.encode("ascii")
        digest.update(
            f"{len(encoded_name)}:".encode("ascii")
            + encoded_name
            + f":{len(encoded_kind)}:".encode("ascii")
            + encoded_kind
            + f":{state[0]}:{state[1]}:".encode("ascii")
        )
        if kind != "text":
            continue
        digest.update(f"12:text-content:true:{state[0]}:".encode("ascii"))
        try:
            with path.open("rb") as source:
                opened_before = os.fstat(source.fileno())
                while chunk := source.read(8 * 1024 * 1024):
                    digest.update(chunk)
                opened_after = os.fstat(source.fileno())
        except OSError as exc:
            raise ExportError(
                f"cannot fingerprint phone-backup payload {path}: {safe_error(exc)}"
            ) from exc
        opened_states = (
            (
                int(opened_before.st_size),
                int(opened_before.st_mtime_ns),
                int(opened_before.st_mode),
                int(opened_before.st_dev),
                int(opened_before.st_ino),
            ),
            (
                int(opened_after.st_size),
                int(opened_after.st_mtime_ns),
                int(opened_after.st_mode),
                int(opened_after.st_dev),
                int(opened_after.st_ino),
            ),
        )
        if opened_states[0] != state or opened_states[1] != state:
            raise ExportError(
                f"phone-backup payload changed while it was being fingerprinted: {path}"
            )
    if inventory() != before:
        raise ExportError(
            f"phone-backup inventory changed while it was being fingerprinted: {directory}"
        )
    return digest.hexdigest()


def import_phone_backup_messages(
    duck: duckdb.DuckDBPyConnection,
    databases: Sequence[DatabaseSpec],
    backup_key: bytes | None,
    allow_partial: bool,
) -> int:
    create_backup_message_tables(duck)
    backup_databases = [
        database
        for database in databases
        if database.stage_status == "ok" and database.mode == "decrypted_phone_backup_index"
    ]
    if not backup_databases:
        return 0
    if backup_key is None:
        raise ExportError(
            "a decrypted phone-backup index is present but no --backup-key-file was provided"
        )

    segment_insert = (
        f"INSERT INTO {quote_ident(CHATLOG_SCHEMA)}.backup_text_segments "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    )
    record_columns = (
        ("source_message_key", "VARCHAR"),
        ("account_id", "VARCHAR"),
        ("database_id", "VARCHAR"),
        ("segment_key", "VARCHAR"),
        ("message_ordinal", "BIGINT"),
        ("record_offset", "BIGINT"),
        ("record_length", "BIGINT"),
        ("talker_id", "VARCHAR"),
        ("sender_id", "VARCHAR"),
        ("recipient_id", "VARCHAR"),
        ("message_type", "BIGINT"),
        ("create_time", "BIGINT"),
        ("server_id", "UBIGINT"),
        ("msg_sequence", "BIGINT"),
        ("sequence", "BIGINT"),
        ("content", "VARCHAR"),
        ("raw_record", "BLOB"),
    )

    imported_records = 0
    for database in backup_databases:
        if database.staged_path is None or not database.staged_path.is_file():
            error = ExportError(f"staged Backup.db is unavailable: {database.staged_path}")
            record_error(
                duck,
                "phone_backup_import",
                error,
                database.account.account_id,
                database.database_id,
            )
            if not allow_partial:
                raise error
            continue
        source_index = Path(database.source_path).resolve()
        bundle_root = source_index.parent
        database_record_count = 0
        try:
            auxiliary_before = phone_backup_auxiliary_sha256(bundle_root)
            if (
                database.auxiliary_sha256
                and auxiliary_before != database.auxiliary_sha256
            ):
                raise ExportError(
                    "phone-backup archives no longer match the staging manifest"
                )
            duck.execute("BEGIN TRANSACTION")
            catalog_backup_archive_files(duck, database, bundle_root)
            rows: list[tuple[Any, ...]] = []
            for segment in iter_backup_segments(
                database.staged_path, bundle_root, backup_key[:16]
            ):
                segment_key = short_hash(
                    database.database_id
                    + "\0"
                    + str(segment.index_rowid)
                    + "\0"
                    + str(segment.source_file)
                    + "\0"
                    + str(segment.source_offset),
                    32,
                )
                duck.execute(
                    segment_insert,
                    [
                        segment_key,
                        database.account.account_id,
                        database.database_id,
                        segment.index_rowid,
                        segment.talker_id,
                        _optional_utf8(segment.user_name),
                        _optional_utf8(segment.segment_id),
                        segment.start_time,
                        segment.end_time,
                        str(bundle_root),
                        str(segment.source_file),
                        segment.source_offset,
                        segment.encrypted_length,
                        segment.plaintext_length,
                        segment.padding_length,
                        segment.root_value,
                        len(segment.messages),
                        _hash_text(segment.ciphertext_sha256),
                        _hash_text(segment.plaintext_sha256),
                    ],
                )
                for message in segment.messages:
                    source_message_key = (
                        f"{database.database_id}:MsgSegments:{segment.index_rowid}:"
                        f"{message.ordinal}"
                    )
                    rows.append(
                        (
                            source_message_key,
                            database.account.account_id,
                            database.database_id,
                            segment_key,
                            message.ordinal,
                            message.record_offset,
                            message.record_length,
                            _optional_utf8(segment.user_name),
                            _optional_utf8(message.sender_id),
                            _optional_utf8(message.recipient_id),
                            message.message_type,
                            message.create_time,
                            message.server_id,
                            message.msg_sequence,
                            message.sequence,
                            _optional_utf8(message.content),
                            message.raw_record,
                        )
                    )
                    if len(rows) >= BACKUP_MESSAGE_BATCH_SIZE:
                        insert_batch(
                            duck,
                            f"{quote_ident(CHATLOG_SCHEMA)}.backup_message_records",
                            rows,
                            record_columns,
                        )
                        database_record_count += len(rows)
                        rows.clear()
            if rows:
                insert_batch(
                    duck,
                    f"{quote_ident(CHATLOG_SCHEMA)}.backup_message_records",
                    rows,
                    record_columns,
                )
                database_record_count += len(rows)
            auxiliary_after = phone_backup_auxiliary_sha256(bundle_root)
            if auxiliary_after != auxiliary_before:
                raise ExportError(
                    "phone-backup archives changed while messages were being imported"
                )
            duck.execute("COMMIT")
            imported_records += database_record_count
        except (
            BackupArchiveError,
            OSError,
            sqlite3.DatabaseError,
            duckdb.Error,
            ExportError,
            ValueError,
        ) as exc:
            try:
                duck.execute("ROLLBACK")
            except duckdb.TransactionException:
                pass
            record_error(
                duck,
                "phone_backup_import",
                exc,
                database.account.account_id,
                database.database_id,
                "MsgSegments",
            )
            if not allow_partial:
                raise ExportError(f"phone backup import failed: {safe_error(exc)}") from exc

    duplicates = int(
        duck.execute(
            f"SELECT count(*) - count(DISTINCT source_message_key) "
            f"FROM {quote_ident(CHATLOG_SCHEMA)}.backup_message_records"
        ).fetchone()[0]
    )
    if duplicates:
        raise ExportError(f"phone backup produced {duplicates} duplicate message key(s)")

    return imported_records


def project_phone_backup_messages(
    duck: duckdb.DuckDBPyConnection, database_ids: Sequence[str]
) -> int:
    if not database_ids:
        return 0
    placeholders = ", ".join("?" for _ in database_ids)
    before = int(
        duck.execute(
            f"SELECT count(*) FROM {quote_ident(CHATLOG_SCHEMA)}.messages"
        ).fetchone()[0]
    )
    expected = int(
        duck.execute(
            f"SELECT count(*) FROM {quote_ident(CHATLOG_SCHEMA)}.backup_message_records "
            f"WHERE database_id IN ({placeholders})",
            list(database_ids),
        ).fetchone()[0]
    )
    direction = sender_direction_expr("r.sender_id", "r.talker_id", "a.account_name")
    duck.execute(
        f"""
        INSERT INTO {quote_ident(CHATLOG_SCHEMA)}.messages (
            account_id, wechat_version, source_kind, database_id,
            source_relative_path, raw_schema, raw_table, source_object,
            source_message_key, server_id, sequence, create_time, created_at,
            talker_id, sender_id, is_chat_room, is_self, message_type,
            raw_type, msg_sequence, raw_content, display_content, message_content
        )
        SELECT
            r.account_id,
            a.version,
            'phone_backup',
            r.database_id,
            d.relative_path,
            {sql_string(CHATLOG_SCHEMA)},
            'backup_message_records',
            'MsgSegments',
            r.source_message_key,
            r.server_id,
            r.sequence,
            r.create_time,
            CASE WHEN r.create_time BETWEEN 0 AND 253402300799
                 THEN to_timestamp(r.create_time) ELSE NULL END,
            r.talker_id,
            r.sender_id,
            CASE WHEN r.talker_id IS NULL THEN NULL
                 ELSE ends_with(r.talker_id, '@chatroom') END,
            {direction},
            r.message_type,
            r.message_type,
            r.msg_sequence,
            r.content,
            r.content,
            r.raw_record
        FROM {quote_ident(CHATLOG_SCHEMA)}.backup_message_records AS r
        JOIN {quote_ident(CATALOG_SCHEMA)}.database_files AS d
          ON d.database_id = r.database_id
        JOIN {quote_ident(CATALOG_SCHEMA)}.accounts AS a
          ON a.account_id = r.account_id
        WHERE r.database_id IN ({placeholders})
        """
        ,
        list(database_ids),
    )
    after = int(
        duck.execute(f"SELECT count(*) FROM {quote_ident(CHATLOG_SCHEMA)}.messages").fetchone()[0]
    )
    projected = after - before
    if projected != expected:
        raise ExportError(
            f"phone backup message projection mismatch: raw={expected}, projected={projected}"
        )
    return projected


def insert_manifest_catalog(
    duck: duckdb.DuckDBPyConnection,
    manifest: dict[str, Any],
    accounts: Sequence[AccountSpec],
    databases: Sequence[DatabaseSpec],
) -> None:
    for account in accounts:
        duck.execute(f"CREATE SCHEMA {quote_ident(account.raw_schema)}")
        duck.execute(
            f"INSERT INTO {quote_ident(CATALOG_SCHEMA)}.accounts "
            "(account_id, account_name, platform, version, full_version, data_dir, stage_dir, "
            "running, key_source, resolved, manifest_status, raw_schema) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                account.account_id,
                account.account_name,
                account.platform,
                account.version,
                account.full_version,
                account.data_dir,
                account.stage_dir,
                account.running,
                account.key_source,
                account.resolved,
                account.status,
                account.raw_schema,
            ],
        )
        for error in account.errors:
            record_error(duck, "account_stage", error, account.account_id)

    for database in databases:
        duck.execute(
            f"""
            INSERT INTO {quote_ident(CATALOG_SCHEMA)}.database_files (
                database_id, account_id, source_path, relative_path, staged_path,
                source_size, source_modified_at, stage_mode, stage_status, stage_error,
                import_status, imported_objects, source_rows, imported_rows, import_error,
                source_sha256, snapshot_size, snapshot_sha256, auxiliary_sha256,
                first_seen_run_id, last_seen_run_id, last_changed_run_id, present
            ) VALUES
            (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0, 0, NULL, ?, ?, ?, ?, ?, ?, ?, TRUE)
            """,
            [
                database.database_id,
                database.account.account_id,
                database.source_path,
                database.relative_path,
                None if database.staged_path is None else str(database.staged_path),
                database.source_size,
                database.source_modified_at,
                database.mode,
                database.stage_status,
                database.stage_error or None,
                "pending",
                database.source_sha256 or None,
                database.snapshot_size,
                database.snapshot_sha256 or None,
                database.auxiliary_sha256 or None,
                _ACTIVE_RUN_ID,
                _ACTIVE_RUN_ID,
                _ACTIVE_RUN_ID,
            ],
        )

    unresolved = manifest.get("unresolved") or []
    if isinstance(unresolved, list):
        for item in unresolved:
            if not isinstance(item, dict):
                continue
            duck.execute(
                f"INSERT INTO {quote_ident(CATALOG_SCHEMA)}.unresolved_accounts "
                "(account_name, data_dir, platform, version, reason, run_id) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                [
                    as_string(item.get("account")),
                    as_string(item.get("data_dir")),
                    as_string(item.get("platform")),
                    as_optional_int(item.get("version")),
                    safe_error(item.get("reason") or ""),
                    _ACTIVE_RUN_ID,
                ],
            )

    raw_errors = manifest.get("errors") or []
    if not isinstance(raw_errors, list):
        raw_errors = [raw_errors]
    for error in raw_errors:
        record_error(duck, "manifest_stage", error)
    raw_warnings = manifest.get("warnings") or []
    if not isinstance(raw_warnings, list):
        raw_warnings = [raw_warnings]
    for warning in raw_warnings:
        record_warning(duck, "manifest_stage", warning)


def check_sqlite_file(database: DatabaseSpec) -> None:
    path = database.staged_path
    if database.stage_status.casefold() != "ok":
        raise ExportError(
            f"database was not staged successfully: {database.relative_path or database.source_path}: "
            f"{database.stage_error or database.stage_status}"
        )
    if path is None or not path.is_file():
        raise ExportError(f"staged database does not exist: {path}")
    try:
        with path.open("rb") as source:
            header = source.read(16)
    except OSError as exc:
        raise ExportError(f"cannot read staged database {path}: {safe_error(exc)}") from exc
    if header != b"SQLite format 3\x00":
        raise ExportError(f"staged file is not a decrypted SQLite database: {path}")


def file_sha256(path: Path) -> tuple[int, str]:
    before = path.stat()
    digest = hashlib.sha256()
    digest.update(b"wechat-sqlite-snapshot-v1\x00")
    digest.update(f"8:snapshot:true:{before.st_size}:".encode("ascii"))
    with path.open("rb") as source:
        while chunk := source.read(8 * 1024 * 1024):
            digest.update(chunk)
    after = path.stat()
    if before.st_size != after.st_size or before.st_mtime_ns != after.st_mtime_ns:
        raise ExportError(f"file changed while it was being fingerprinted: {path}")
    return after.st_size, digest.hexdigest()


def verify_staged_snapshot(database: DatabaseSpec) -> DatabaseSpec:
    check_sqlite_file(database)
    assert database.staged_path is not None
    size, digest = file_sha256(database.staged_path)
    if database.snapshot_size is not None and database.snapshot_size != size:
        raise ExportError(
            f"staged snapshot size mismatch for {database.relative_path}: "
            f"manifest={database.snapshot_size}, actual={size}"
        )
    if database.snapshot_sha256 and database.snapshot_sha256 != digest:
        raise ExportError(
            f"staged snapshot fingerprint mismatch for {database.relative_path}"
        )
    return replace(database, snapshot_size=size, snapshot_sha256=digest)


def process_database(
    duck: duckdb.DuckDBPyConnection,
    database: DatabaseSpec,
    sqlite_extension_available: bool,
    allow_partial: bool,
    verify_snapshot: bool = True,
) -> list[ImportedObject]:
    label = database.relative_path or database.source_path or str(database.staged_path)
    print(f"Importing [{database.account.account_name or database.account.account_id}] {label}", flush=True)
    try:
        database = (
            verify_staged_snapshot(database) if verify_snapshot else database
        )
        if not verify_snapshot:
            check_sqlite_file(database)
    except Exception as exc:
        duck.execute(
            f"UPDATE {quote_ident(CATALOG_SCHEMA)}.database_files "
            "SET import_status='error', import_error=? WHERE database_id=?",
            [safe_error(exc), database.database_id],
        )
        record_error(duck, "database_stage", exc, database.account.account_id, database.database_id)
        if not allow_partial:
            raise
        return []

    sqlite_connection: sqlite3.Connection | None = None
    attached_alias: str | None = None
    imported_objects: list[ImportedObject] = []
    database_error = ""
    try:
        sqlite_connection = open_sqlite(database.staged_path)  # type: ignore[arg-type]
        verification_warning = verify_sqlite(sqlite_connection)
        if verification_warning:
            record_warning(
                duck,
                "sqlite_integrity",
                verification_warning,
                database.account.account_id,
                database.database_id,
            )
        objects, skipped_objects = introspect_sqlite(sqlite_connection)
        for skipped in skipped_objects:
            insert_skipped_object(duck, database, skipped)
        if sqlite_extension_available:
            attached_alias = "sqlite_" + database.database_id
            try:
                duck.execute(
                    f"ATTACH {sql_string(str(database.staged_path))} AS {quote_ident(attached_alias)} "
                    "(TYPE SQLITE, READ_ONLY)"
                )
            except Exception as exc:
                record_warning(
                    duck,
                    "sqlite_attach",
                    exc,
                    database.account.account_id,
                    database.database_id,
                )
                attached_alias = None

        for source in objects:
            raw_table = raw_table_name(database.relative_path or database.source_path, source.name)
            try:
                imported = import_one_object(
                    duck, sqlite_connection, attached_alias, database, source
                )
                imported_objects.append(imported)
                if imported.import_method == "sqlite3_fallback_after_extension_error":
                    record_warning(
                        duck,
                        "sqlite_object_fallback",
                        "DuckDB's sqlite scanner could not import this object; sqlite3 fallback succeeded",
                        database.account.account_id,
                        database.database_id,
                        source.name,
                    )
            except Exception as exc:
                database_error = safe_error(exc)
                insert_failed_object(duck, database, source, raw_table, exc)
                if not allow_partial:
                    raise
        source_rows = sum(item.source_rows for item in imported_objects)
        imported_rows = sum(item.imported_rows for item in imported_objects)
        duck.execute(
            f"""
            UPDATE {quote_ident(CATALOG_SCHEMA)}.database_files
            SET import_status=?, imported_objects=?, source_rows=?, imported_rows=?, import_error=?,
                snapshot_size=?, snapshot_sha256=?
            WHERE database_id=?
            """,
            [
                "partial" if database_error else "ok",
                len(imported_objects),
                source_rows,
                imported_rows,
                database_error or None,
                database.snapshot_size,
                database.snapshot_sha256 or None,
                database.database_id,
            ],
        )
        return imported_objects
    except Exception as exc:
        duck.execute(
            f"UPDATE {quote_ident(CATALOG_SCHEMA)}.database_files "
            "SET import_status='error', import_error=? WHERE database_id=?",
            [safe_error(exc), database.database_id],
        )
        record_error(
            duck,
            "database_import",
            exc,
            database.account.account_id,
            database.database_id,
        )
        if not allow_partial:
            raise
        return imported_objects
    finally:
        if attached_alias is not None:
            try:
                duck.execute(f"DETACH {quote_ident(attached_alias)}")
            except Exception:
                pass
        if sqlite_connection is not None:
            sqlite_connection.close()


def parse_source_columns(value: str) -> tuple[SourceColumn, ...]:
    try:
        raw = json.loads(value)
    except json.JSONDecodeError as exc:
        raise ExportError(f"invalid source_columns_json in baseline: {safe_error(exc)}") from exc
    if not isinstance(raw, list):
        raise ExportError("invalid source_columns_json in baseline: expected an array")
    columns: list[SourceColumn] = []
    for index, item in enumerate(raw):
        if not isinstance(item, dict):
            raise ExportError("invalid source_columns_json in baseline: expected objects")
        columns.append(
            SourceColumn(
                ordinal=as_optional_int(item.get("ordinal")) or index,
                name=as_string(item.get("name")),
                declared_type=as_string(item.get("declared_type")),
                not_null=bool(item.get("not_null", False)),
                default_sql=(
                    None if item.get("default_sql") is None else str(item.get("default_sql"))
                ),
                primary_key_position=as_optional_int(item.get("primary_key_position")) or 0,
            )
        )
    return tuple(columns)


def load_current_imported_objects(
    duck: duckdb.DuckDBPyConnection,
    incoming_databases: dict[str, DatabaseSpec],
    account_ids: set[str] | None = None,
) -> list[ImportedObject]:
    accounts: dict[str, AccountSpec] = {}
    for row in duck.execute(
        f"SELECT account_id, account_name, platform, version, full_version, data_dir, "
        f"stage_dir, running, key_source, resolved, manifest_status, raw_schema "
        f"FROM {quote_ident(CATALOG_SCHEMA)}.accounts"
    ).fetchall():
        account = AccountSpec(
            account_id=str(row[0]),
            account_name=as_string(row[1]),
            platform=as_string(row[2]),
            version=as_optional_int(row[3]),
            full_version=as_string(row[4]),
            data_dir=as_string(row[5]),
            stage_dir=as_string(row[6]),
            running=row[7] if isinstance(row[7], bool) else None,
            key_source=as_string(row[8]),
            resolved=bool(row[9]),
            status=as_string(row[10]),
            errors=(),
            raw_schema=as_string(row[11]),
        )
        accounts[account.account_id] = account

    databases: dict[str, DatabaseSpec] = {}
    for row in duck.execute(
        f"SELECT database_id, account_id, source_path, relative_path, staged_path, "
        "source_size, source_modified_at, source_sha256, snapshot_size, snapshot_sha256, "
        "auxiliary_sha256, stage_mode, stage_status, stage_error "
        f"FROM {quote_ident(CATALOG_SCHEMA)}.database_files WHERE present=TRUE"
    ).fetchall():
        database_id = str(row[0])
        if database_id in incoming_databases:
            databases[database_id] = incoming_databases[database_id]
            continue
        account = accounts.get(str(row[1]))
        if account is None:
            raise ExportError(f"baseline database {database_id} references a missing account")
        staged_path = None if row[4] is None or not str(row[4]) else Path(str(row[4]))
        databases[database_id] = DatabaseSpec(
            database_id=database_id,
            account=account,
            source_path=as_string(row[2]),
            relative_path=as_string(row[3]),
            staged_path=staged_path,
            source_size=as_optional_int(row[5]),
            source_modified_at=as_string(row[6]),
            source_sha256=as_string(row[7]),
            snapshot_size=as_optional_int(row[8]),
            snapshot_sha256=as_string(row[9]),
            auxiliary_sha256=as_string(row[10]),
            mode=as_string(row[11]),
            stage_status=as_string(row[12]),
            stage_error=as_string(row[13]),
        )

    parameters: list[Any] = []
    account_filter = ""
    if account_ids:
        placeholders = ", ".join("?" for _ in account_ids)
        account_filter = f" AND account_id IN ({placeholders})"
        parameters.extend(sorted(account_ids))
    result: list[ImportedObject] = []
    object_rows = duck.execute(
        f"SELECT object_id, database_id, source_type, source_name, original_ddl, "
        "source_columns_json, raw_table, source_rows, imported_rows, import_method "
        f"FROM {quote_ident(CATALOG_SCHEMA)}.objects "
        f"WHERE import_status='ok'{account_filter} ORDER BY object_id",
        parameters,
    ).fetchall()
    for row in object_rows:
        database = databases.get(str(row[1]))
        if database is None:
            raise ExportError(f"baseline object {row[0]} references a missing database")
        source = SourceObject(
            object_type=as_string(row[2]),
            name=as_string(row[3]),
            original_ddl=None if row[4] is None else str(row[4]),
            columns=parse_source_columns(as_string(row[5])),
        )
        result.append(
            ImportedObject(
                object_id=str(row[0]),
                database=database,
                source=source,
                raw_table=as_string(row[6]),
                source_rows=int(row[7]),
                imported_rows=int(row[8]),
                import_method=as_string(row[9]),
            )
        )
    return result


def persistent_view_is_valid(
    duck: duckdb.DuckDBPyConnection, schema_name: str, view_name: str
) -> bool:
    try:
        duck.execute(
            f"SELECT * FROM {quote_ident(schema_name)}.{quote_ident(view_name)} LIMIT 0"
        )
    except duckdb.Error:
        return False
    return True


def snapshot_valid_persistent_views(
    duck: duckdb.DuckDBPyConnection,
) -> tuple[PersistentViewSnapshot, ...]:
    """Capture only same-database persistent views that currently bind."""
    result: list[PersistentViewSnapshot] = []
    rows = duck.execute(
        "SELECT schema_name, view_name, sql, comment FROM duckdb_views() "
        "WHERE database_name=current_database() AND NOT internal AND NOT temporary "
        "AND sql IS NOT NULL ORDER BY schema_name, view_name"
    ).fetchall()
    for schema_name, view_name, create_sql, comment in rows:
        schema = str(schema_name)
        name = str(view_name)
        if not persistent_view_is_valid(duck, schema, name):
            continue
        column_comments = tuple(
            (str(column_name), str(column_comment))
            for column_name, column_comment in duck.execute(
                "SELECT column_name, comment FROM duckdb_columns() "
                "WHERE database_name=current_database() AND schema_name=? "
                "AND table_name=? AND comment IS NOT NULL ORDER BY column_index",
                [schema, name],
            ).fetchall()
        )
        result.append(
            PersistentViewSnapshot(
                schema_name=schema,
                view_name=name,
                create_sql=str(create_sql),
                comment=None if comment is None else str(comment),
                column_comments=column_comments,
            )
        )
    return tuple(result)


def refresh_invalidated_persistent_views(
    duck: duckdb.DuckDBPyConnection,
    before_upgrade: Sequence[PersistentViewSnapshot],
) -> int:
    """Refresh views invalidated by a contact-column expansion.

    DuckDB 1.2 binds ``SELECT *`` views to the original result shape.  Adding a
    contact column can therefore invalidate a direct view and an arbitrary
    chain above it.  Previously broken and still-valid views are left alone;
    only views that bound before the upgrade and fail afterwards are eligible.
    Repeated passes let upstream views recover before their dependants.
    """
    pending = [
        view
        for view in before_upgrade
        if not persistent_view_is_valid(duck, view.schema_name, view.view_name)
    ]
    if not pending:
        return 0

    refreshed: list[PersistentViewSnapshot] = []
    last_errors: dict[tuple[str, str], str] = {}
    original_schema = str(duck.execute("SELECT current_schema()").fetchone()[0])
    try:
        while pending:
            next_pending: list[PersistentViewSnapshot] = []
            progress = False
            for view in pending:
                if persistent_view_is_valid(duck, view.schema_name, view.view_name):
                    progress = True
                    continue
                replacement_sql, replacements = re.subn(
                    r"^\s*CREATE\s+VIEW\s+",
                    "CREATE OR REPLACE VIEW ",
                    view.create_sql,
                    count=1,
                    flags=re.IGNORECASE,
                )
                if replacements != 1:
                    last_errors[(view.schema_name, view.view_name)] = (
                        "catalog SQL is not a CREATE VIEW statement"
                    )
                    next_pending.append(view)
                    continue
                try:
                    duck.execute(f"SET schema {sql_string(view.schema_name)}")
                    duck.execute(replacement_sql)
                except duckdb.Error as exc:
                    last_errors[(view.schema_name, view.view_name)] = safe_error(exc)
                    next_pending.append(view)
                    continue
                if persistent_view_is_valid(duck, view.schema_name, view.view_name):
                    refreshed.append(view)
                    progress = True
                else:
                    last_errors[(view.schema_name, view.view_name)] = (
                        "view remained invalid after CREATE OR REPLACE"
                    )
                    next_pending.append(view)
            if not next_pending:
                break
            if not progress:
                details = "; ".join(
                    f"{schema}.{name}: {last_errors.get((schema, name), 'unknown error')}"
                    for schema, name in (
                        (view.schema_name, view.view_name) for view in next_pending
                    )
                )
                raise ExportError(
                    "contact schema upgrade could not refresh invalidated view(s): "
                    + details
                )
            pending = next_pending
    finally:
        duck.execute(f"SET schema {sql_string(original_schema)}")

    # CREATE OR REPLACE clears comments in DuckDB 1.2.  Restore comments only
    # on views that this migration actually replaced.
    for view in refreshed:
        qualified = f"{quote_ident(view.schema_name)}.{quote_ident(view.view_name)}"
        if view.comment is not None:
            duck.execute(f"COMMENT ON VIEW {qualified} IS {sql_string(view.comment)}")
        for column_name, comment in view.column_comments:
            duck.execute(
                f"COMMENT ON COLUMN {qualified}.{quote_ident(column_name)} "
                f"IS {sql_string(comment)}"
            )
    return len(refreshed)


def rebuild_contacts_from_catalog(duck: duckdb.DuckDBPyConnection) -> int:
    """Rebuild contacts and Windows-v3 tags before applying a delta.

    This also upgrades exports made before the canonical contact/tag tables
    existed. Rebuilding on every delta keeps the compatibility path idempotent
    and makes partition-health checks independent of the baseline exporter.
    """
    if table_exists(duck, CHATLOG_SCHEMA, "contacts"):
        legacy_columns = CONTACT_COLUMNS - CONTACT_EXTRA_BUF_CONTACT_COLUMNS
        missing = legacy_columns - table_columns(duck, CHATLOG_SCHEMA, "contacts")
        if missing:
            raise ExportError(
                "baseline chatlog.contacts has an incompatible schema; "
                "missing legacy column(s): " + ", ".join(sorted(missing))
            )
        missing_profile_columns = [
            (column, definition)
            for column, definition in CONTACT_EXTRA_BUF_COLUMN_DEFINITIONS
            if column.casefold()
            not in table_columns(duck, CHATLOG_SCHEMA, "contacts")
        ]
        views_before_upgrade = (
            snapshot_valid_persistent_views(duck)
            if missing_profile_columns
            else ()
        )
        for column, definition in missing_profile_columns:
            add_column_if_missing(
                duck, CHATLOG_SCHEMA, "contacts", column, definition
            )
        refresh_invalidated_persistent_views(duck, views_before_upgrade)
        validate_contacts_table_schema(duck)
        duck.execute(f"DELETE FROM {quote_ident(CHATLOG_SCHEMA)}.contacts")
    else:
        create_contacts_table(duck)
    definition_exists = table_exists(
        duck, CHATLOG_SCHEMA, "contact_tag_definitions"
    )
    assignment_exists = table_exists(duck, CHATLOG_SCHEMA, "contact_tags")
    if definition_exists != assignment_exists:
        raise ExportError(
            "baseline has only one of chatlog.contact_tag_definitions and "
            "chatlog.contact_tags"
        )
    if definition_exists:
        validate_contact_tag_table_schemas(duck)
        duck.execute(
            f"DELETE FROM {quote_ident(CHATLOG_SCHEMA)}.contact_tag_definitions"
        )
        duck.execute(f"DELETE FROM {quote_ident(CHATLOG_SCHEMA)}.contact_tags")
    else:
        create_contact_tag_tables(duck)
    imported_objects = load_current_imported_objects(duck, {})
    project_contact_objects(duck, imported_objects, False)
    project_contact_tag_objects(duck, imported_objects, False)
    duck.execute(
        f"ALTER TABLE {quote_ident(CHATLOG_SCHEMA)}.contacts ALTER COLUMN "
        f"{quote_ident('extra_buf_parse_status')} SET NOT NULL"
    )
    return int(
        duck.execute(
            f"SELECT count(*) FROM {quote_ident(CHATLOG_SCHEMA)}.contacts"
        ).fetchone()[0]
    )


def database_partition_is_healthy(
    duck: duckdb.DuckDBPyConnection, database_id: str
) -> bool:
    database_columns = table_columns(duck, CATALOG_SCHEMA, "database_files")
    present_filter = " AND d.present=TRUE" if "present" in database_columns else ""
    status = duck.execute(
        f"SELECT d.import_status, d.imported_objects, d.source_rows, d.imported_rows, "
        "d.stage_mode, d.relative_path, a.version "
        f"FROM {quote_ident(CATALOG_SCHEMA)}.database_files d "
        f"JOIN {quote_ident(CATALOG_SCHEMA)}.accounts a ON a.account_id=d.account_id "
        f"WHERE d.database_id=?{present_filter}",
        [database_id],
    ).fetchone()
    if status is None or status[0] != "ok":
        return False
    objects = duck.execute(
        f"SELECT raw_schema, raw_table, source_rows, imported_rows, source_name, "
        "source_columns_json "
        f"FROM {quote_ident(CATALOG_SCHEMA)}.objects "
        "WHERE database_id=? AND import_status='ok' ORDER BY object_id",
        [database_id],
    ).fetchall()
    if len(objects) != int(status[1]):
        return False
    if sum(int(row[2]) for row in objects) != int(status[2]):
        return False
    if sum(int(row[3]) for row in objects) != int(status[3]):
        return False
    for (
        raw_schema,
        raw_table,
        _source_rows,
        imported_rows,
        _source_name,
        _source_columns_json,
    ) in objects:
        if not table_exists(duck, str(raw_schema), str(raw_table)):
            return False
        actual_rows = int(
            duck.execute(
                f"SELECT count(*) FROM {quote_ident(str(raw_schema))}."
                f"{quote_ident(str(raw_table))}"
            ).fetchone()[0]
        )
        if actual_rows != int(imported_rows):
            return False

    relative_name = Path(as_string(status[5]).replace("\\", "/")).name
    version = as_optional_int(status[6])
    expected_messages = 0
    expected_contacts = 0
    expected_tag_definitions = 0
    expected_tags = 0
    for (
        raw_schema,
        raw_table,
        _source_rows,
        imported_rows,
        source_name,
        source_columns_json,
    ) in objects:
        folded = as_string(source_name).casefold()
        basename = relative_name.casefold()
        is_message = (
            (folded == "msg" and V3_MESSAGE_DB.fullmatch(relative_name) is not None)
            or (folded == "publicmsg" and basename == "publicmsg.db")
            or (
                folded in {"chatcrmsg", "chatmsg"}
                and basename
                in {"openimmsg.db", "customerservice.db", "chatmsg.db", "bizchatmsg.db"}
            )
            or (
                version == 4
                and V4_MESSAGE_TABLE.fullmatch(as_string(source_name)) is not None
                and V4_MESSAGE_DB.fullmatch(relative_name) is not None
            )
        )
        if is_message:
            expected_messages += int(imported_rows)
        contact_kind, contact_required = contact_kind_for(
            as_string(source_name), relative_name
        )
        try:
            contact_columns = {
                column.name.casefold(): column.name
                for column in parse_source_columns(as_string(source_columns_json))
            }
        except ExportError:
            return False
        if contact_kind is not None and contact_required <= set(contact_columns):
            expected_contacts += int(imported_rows)
        tag_role = contact_tag_role_for(as_string(source_name), relative_name)
        if tag_role == "definition":
            if {"labelid", "labelname"} <= set(contact_columns):
                expected_tag_definitions += int(imported_rows)
            else:
                return False
        elif (
            tag_role == "contact"
            and "username" in contact_columns
            and "labelidlist" in contact_columns
        ):
            expected_tags += count_nonblank_contact_tag_tokens(
                duck,
                as_string(raw_schema),
                as_string(raw_table),
                contact_columns["labelidlist"],
            )

    if as_string(status[4]) == "decrypted_phone_backup_index":
        for table in (
            "backup_archive_files",
            "backup_text_segments",
            "backup_message_records",
        ):
            if not table_exists(duck, CHATLOG_SCHEMA, table):
                return False
        backup_records = int(
            duck.execute(
                f"SELECT count(*) FROM {quote_ident(CHATLOG_SCHEMA)}.backup_message_records "
                "WHERE database_id=?",
                [database_id],
            ).fetchone()[0]
        )
        expected_messages += backup_records
        expected_segments = sum(
            int(row[3])
            for row in objects
            if as_string(row[4]).casefold() == "msgsegments"
        )
        actual_segments = int(
            duck.execute(
                f"SELECT count(*) FROM {quote_ident(CHATLOG_SCHEMA)}.backup_text_segments "
                "WHERE database_id=?",
                [database_id],
            ).fetchone()[0]
        )
        if actual_segments != expected_segments:
            return False
        dangling_records = int(
            duck.execute(
                f"SELECT count(*) FROM {quote_ident(CHATLOG_SCHEMA)}.backup_message_records r "
                f"LEFT JOIN {quote_ident(CHATLOG_SCHEMA)}.backup_text_segments s "
                "ON s.database_id=r.database_id AND s.segment_key=r.segment_key "
                "WHERE r.database_id=? AND s.segment_key IS NULL",
                [database_id],
            ).fetchone()[0]
        )
        mismatched_segment_counts = len(
            duck.execute(
                f"SELECT count(*) FROM {quote_ident(CHATLOG_SCHEMA)}.backup_text_segments s "
                f"LEFT JOIN {quote_ident(CHATLOG_SCHEMA)}.backup_message_records r "
                "ON r.database_id=s.database_id AND r.segment_key=s.segment_key "
                "WHERE s.database_id=? GROUP BY s.segment_key, s.message_count "
                "HAVING count(r.source_message_key)<>s.message_count",
                [database_id],
            ).fetchall()
        )
        missing_archive_links = int(
            duck.execute(
                f"SELECT count(*) FROM {quote_ident(CHATLOG_SCHEMA)}.backup_text_segments s "
                f"LEFT JOIN {quote_ident(CHATLOG_SCHEMA)}.backup_archive_files f "
                "ON f.database_id=s.database_id AND f.payload_kind='text' "
                "AND lower(f.source_name)=lower(s.source_file) "
                "WHERE s.database_id=? AND f.archive_file_key IS NULL",
                [database_id],
            ).fetchone()[0]
        )
        if dangling_records or mismatched_segment_counts or missing_archive_links:
            return False
    if version == 4:
        for table in ("v4_talker_map", "v4_sender_map"):
            if not table_exists(duck, CHATLOG_SCHEMA, table):
                return False
    actual_messages = int(
        duck.execute(
            f"SELECT count(*) FROM {quote_ident(CHATLOG_SCHEMA)}.messages "
            "WHERE database_id=?",
            [database_id],
        ).fetchone()[0]
    )
    if actual_messages != expected_messages:
        return False
    if not table_exists(duck, CHATLOG_SCHEMA, "contacts"):
        return False
    actual_contacts = int(
        duck.execute(
            f"SELECT count(*) FROM {quote_ident(CHATLOG_SCHEMA)}.contacts "
            "WHERE database_id=?",
            [database_id],
        ).fetchone()[0]
    )
    if actual_contacts != expected_contacts:
        return False
    if not table_exists(duck, CHATLOG_SCHEMA, "contact_tag_definitions"):
        return False
    if not table_exists(duck, CHATLOG_SCHEMA, "contact_tags"):
        return False
    actual_tag_definitions = int(
        duck.execute(
            f"SELECT count(*) FROM {quote_ident(CHATLOG_SCHEMA)}.contact_tag_definitions "
            "WHERE database_id=?",
            [database_id],
        ).fetchone()[0]
    )
    actual_tags = int(
        duck.execute(
            f"SELECT count(*) FROM {quote_ident(CHATLOG_SCHEMA)}.contact_tags "
            "WHERE database_id=?",
            [database_id],
        ).fetchone()[0]
    )
    return (
        actual_tag_definitions == expected_tag_definitions
        and actual_tags == expected_tags
    )


def drop_database_partition(duck: duckdb.DuckDBPyConnection, database_id: str) -> None:
    for raw_schema, raw_table in duck.execute(
        f"SELECT raw_schema, raw_table FROM {quote_ident(CATALOG_SCHEMA)}.objects "
        "WHERE database_id=? AND import_status='ok'",
        [database_id],
    ).fetchall():
        duck.execute(
            f"DROP TABLE IF EXISTS {quote_ident(str(raw_schema))}.{quote_ident(str(raw_table))}"
        )
    duck.execute(
        f"DELETE FROM {quote_ident(CATALOG_SCHEMA)}.objects WHERE database_id=?",
        [database_id],
    )
    if table_exists(duck, CHATLOG_SCHEMA, "messages"):
        duck.execute(
            f"DELETE FROM {quote_ident(CHATLOG_SCHEMA)}.messages WHERE database_id=?",
            [database_id],
        )
    if table_exists(duck, CHATLOG_SCHEMA, "contacts"):
        duck.execute(
            f"DELETE FROM {quote_ident(CHATLOG_SCHEMA)}.contacts WHERE database_id=?",
            [database_id],
        )
    for table in ("contact_tag_definitions", "contact_tags"):
        if table_exists(duck, CHATLOG_SCHEMA, table):
            duck.execute(
                f"DELETE FROM {quote_ident(CHATLOG_SCHEMA)}.{quote_ident(table)} "
                "WHERE database_id=?",
                [database_id],
            )
    for table in ("backup_archive_files", "backup_text_segments", "backup_message_records"):
        if table_exists(duck, CHATLOG_SCHEMA, table):
            duck.execute(
                f"DELETE FROM {quote_ident(CHATLOG_SCHEMA)}.{quote_ident(table)} "
                "WHERE database_id=?",
                [database_id],
            )
    if table_exists(duck, CHATLOG_SCHEMA, "v4_sender_map"):
        duck.execute(
            f"DELETE FROM {quote_ident(CHATLOG_SCHEMA)}.v4_sender_map WHERE database_id=?",
            [database_id],
        )


def replace_account_catalog(duck: duckdb.DuckDBPyConnection, account: AccountSpec) -> None:
    duck.execute(f"CREATE SCHEMA IF NOT EXISTS {quote_ident(account.raw_schema)}")
    duck.execute(
        f"DELETE FROM {quote_ident(CATALOG_SCHEMA)}.accounts WHERE account_id=?",
        [account.account_id],
    )
    duck.execute(
        f"INSERT INTO {quote_ident(CATALOG_SCHEMA)}.accounts "
        "(account_id, account_name, platform, version, full_version, data_dir, stage_dir, "
        "running, key_source, resolved, manifest_status, raw_schema) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        [
            account.account_id,
            account.account_name,
            account.platform,
            account.version,
            account.full_version,
            account.data_dir,
            account.stage_dir,
            account.running,
            account.key_source,
            account.resolved,
            account.status,
            account.raw_schema,
        ],
    )
    for error in account.errors:
        record_error(duck, "account_stage", error, account.account_id)


def replace_database_catalog(
    duck: duckdb.DuckDBPyConnection,
    database: DatabaseSpec,
    run_id: str,
    first_seen_run_id: str | None,
) -> None:
    duck.execute(
        f"DELETE FROM {quote_ident(CATALOG_SCHEMA)}.database_files WHERE database_id=?",
        [database.database_id],
    )
    duck.execute(
        f"""
        INSERT INTO {quote_ident(CATALOG_SCHEMA)}.database_files (
            database_id, account_id, source_path, relative_path, staged_path,
            source_size, source_modified_at, stage_mode, stage_status, stage_error,
            import_status, imported_objects, source_rows, imported_rows, import_error,
            source_sha256, snapshot_size, snapshot_sha256, auxiliary_sha256,
            first_seen_run_id, last_seen_run_id, last_changed_run_id, present
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', 0, 0, 0, NULL,
                  ?, ?, ?, ?, ?, ?, ?, TRUE)
        """,
        [
            database.database_id,
            database.account.account_id,
            database.source_path,
            database.relative_path,
            None if database.staged_path is None else str(database.staged_path),
            database.source_size,
            database.source_modified_at,
            database.mode,
            database.stage_status,
            database.stage_error or None,
            database.source_sha256 or None,
            database.snapshot_size,
            database.snapshot_sha256 or None,
            database.auxiliary_sha256 or None,
            first_seen_run_id or run_id,
            run_id,
            run_id,
        ],
    )


def update_reused_database(
    duck: duckdb.DuckDBPyConnection, database: DatabaseSpec, run_id: str
) -> None:
    duck.execute(
        f"""
        UPDATE {quote_ident(CATALOG_SCHEMA)}.database_files
        SET account_id=?, source_path=?, relative_path=?, staged_path=?, source_size=?,
            source_modified_at=?, stage_mode=?, stage_status=?, stage_error=?,
            source_sha256=?, snapshot_size=coalesce(?, snapshot_size),
            snapshot_sha256=coalesce(nullif(?, ''), snapshot_sha256),
            auxiliary_sha256=?, last_seen_run_id=?, present=TRUE
        WHERE database_id=?
        """,
        [
            database.account.account_id,
            database.source_path,
            database.relative_path,
            None if database.staged_path is None else str(database.staged_path),
            database.source_size,
            database.source_modified_at,
            database.mode,
            database.stage_status,
            database.stage_error or None,
            database.source_sha256 or None,
            database.snapshot_size,
            database.snapshot_sha256,
            database.auxiliary_sha256 or None,
            run_id,
            database.database_id,
        ],
    )


def mark_reused_database_stale(
    duck: duckdb.DuckDBPyConnection, database: DatabaseSpec, run_id: str
) -> None:
    """Retain the last good partition when a partial delta cannot refresh it."""
    duck.execute(
        f"""
        UPDATE {quote_ident(CATALOG_SCHEMA)}.database_files
        SET account_id=?, source_path=?, relative_path=?, source_size=?,
            source_modified_at=?, stage_mode=?, stage_status=?, stage_error=?,
            last_seen_run_id=?, present=TRUE
        WHERE database_id=?
        """,
        [
            database.account.account_id,
            database.source_path,
            database.relative_path,
            database.source_size,
            database.source_modified_at,
            database.mode,
            database.stage_status,
            database.stage_error or "delta refresh failed; retained last good partition",
            run_id,
            database.database_id,
        ],
    )


def insert_manifest_issues(duck: duckdb.DuckDBPyConnection, manifest: dict[str, Any]) -> None:
    unresolved = manifest.get("unresolved") or []
    if isinstance(unresolved, list):
        for item in unresolved:
            if not isinstance(item, dict):
                continue
            duck.execute(
                f"INSERT INTO {quote_ident(CATALOG_SCHEMA)}.unresolved_accounts "
                "(account_name, data_dir, platform, version, reason, run_id) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                [
                    as_string(item.get("account")),
                    as_string(item.get("data_dir")),
                    as_string(item.get("platform")),
                    as_optional_int(item.get("version")),
                    safe_error(item.get("reason") or ""),
                    _ACTIVE_RUN_ID,
                ],
            )
    raw_errors = manifest.get("errors") or []
    if not isinstance(raw_errors, list):
        raw_errors = [raw_errors]
    for error in raw_errors:
        record_error(duck, "manifest_stage", error)
    raw_warnings = manifest.get("warnings") or []
    if not isinstance(raw_warnings, list):
        raw_warnings = [raw_warnings]
    for warning in raw_warnings:
        record_warning(duck, "manifest_stage", warning)


def canonical_local_path(value: str) -> str:
    return os.path.normcase(os.path.abspath(os.path.normpath(value))).casefold()


def same_local_file(left: str | Path, right: str | Path) -> bool:
    try:
        return os.path.samefile(left, right)
    except OSError:
        return canonical_local_path(str(left)) == canonical_local_path(str(right))


def validate_delta_account_identity(
    duck: duckdb.DuckDBPyConnection, accounts: Sequence[AccountSpec]
) -> None:
    existing = [
        (as_string(row[0]), as_string(row[1]), as_string(row[2]))
        for row in duck.execute(
            f"SELECT account_id, account_name, data_dir "
            f"FROM {quote_ident(CATALOG_SCHEMA)}.accounts"
        ).fetchall()
    ]
    existing_ids = {row[0] for row in existing}
    existing_by_path = {
        canonical_local_path(data_dir): account_id
        for account_id, _account_name, data_dir in existing
        if data_dir.strip()
    }
    existing_names: dict[str, list[tuple[str, str]]] = {}
    for account_id, account_name, data_dir in existing:
        if account_name.strip():
            existing_names.setdefault(account_name.casefold(), []).append(
                (account_id, data_dir)
            )

    for account in accounts:
        if not account.data_dir.strip():
            raise ExportError(
                f"delta account {account.account_id!r} has no source data directory"
            )
        path_identity = canonical_local_path(account.data_dir)
        prior_id = existing_by_path.get(path_identity)
        if prior_id is not None and prior_id != account.account_id:
            raise ExportError(
                f"delta account identity mismatch for {account.data_dir}: "
                f"baseline id={prior_id!r}, staged id={account.account_id!r}"
            )
        if account.account_id in existing_ids:
            continue
        same_name = existing_names.get(account.account_name.casefold(), [])
        if len(same_name) == 1:
            old_id, old_data_dir = same_name[0]
            raise ExportError(
                f"account {account.account_name!r} may have moved from {old_data_dir!r} "
                f"to {account.data_dir!r}; refusing to duplicate baseline account {old_id!r}. "
                "Create a new full export to rebase a moved account."
            )


def apply_delta(
    duck: duckdb.DuckDBPyConnection,
    manifest: dict[str, Any],
    accounts: Sequence[AccountSpec],
    databases: Sequence[DatabaseSpec],
    backup_key: bytes | None,
    sqlite_extension_available: bool,
    allow_partial: bool,
    run_id: str,
    baseline_schema_version: int,
) -> dict[str, int]:
    create_backup_message_tables(duck)
    rebuild_contacts_from_catalog(duck)
    if baseline_schema_version < 7:
        # Reproject only legacy v3 messages from retained raw tables. No live
        # SQLite is needed, and keys/rows outside these partitions survive.
        for imported in load_current_imported_objects(duck, {}):
            kind, _required = canonical_kind(imported)
            if kind is not None and kind.startswith("v3_"):
                duck.execute(
                    f"DELETE FROM {quote_ident(CHATLOG_SCHEMA)}.messages "
                    "WHERE database_id=? AND source_object=?",
                    [imported.database.database_id, imported.source.name],
                )
                insert_v3_messages(duck, imported, kind)
    validate_delta_account_identity(duck, accounts)
    old_account_versions = {
        str(account_id): as_optional_int(version)
        for account_id, version in duck.execute(
            f"SELECT account_id, version FROM {quote_ident(CATALOG_SCHEMA)}.accounts"
        ).fetchall()
    }
    for account in accounts:
        replace_account_catalog(duck, account)
    insert_manifest_issues(duck, manifest)

    existing = {
        str(row[0]): {
            "account_id": str(row[1]),
            "snapshot_sha256": as_string(row[2]),
            "auxiliary_sha256": as_string(row[3]),
            "source_sha256": as_string(row[4]),
            "first_seen_run_id": as_string(row[5]),
        }
        for row in duck.execute(
            f"SELECT database_id, account_id, snapshot_sha256, auxiliary_sha256, "
            "source_sha256, first_seen_run_id "
            f"FROM {quote_ident(CATALOG_SCHEMA)}.database_files WHERE present=TRUE"
        ).fetchall()
    }
    incoming: dict[str, DatabaseSpec] = {}
    changed: list[DatabaseSpec] = []
    reused: list[DatabaseSpec] = []
    stale_reused: list[DatabaseSpec] = []
    added_ids: set[str] = set()
    changed_ids: set[str] = set()

    for raw_database in databases:
        database = raw_database
        incoming[database.database_id] = database
        prior = existing.get(database.database_id)
        status = database.stage_status.casefold()
        if database.legacy_phone_bootstrap and (
            status != "unchanged"
            or database.mode != "decrypted_phone_backup_index"
            or baseline_schema_version != 1
        ):
            raise ExportError(
                "legacy phone bootstrap marker is only valid for an unchanged "
                "Backup.db from an original v1 export"
            )
        if (
            database.mode == "decrypted_phone_backup_index"
            and status in {"ok", "unchanged"}
            and not database.auxiliary_sha256
        ):
            raise ExportError(
                f"phone-backup manifest entry lacks an auxiliary fingerprint: "
                f"{database.relative_path}"
            )
        version_changed = (
            database.account.account_id in old_account_versions
            and old_account_versions[database.account.account_id] != database.account.version
        )
        if status == "unchanged":
            if prior is None:
                raise ExportError(
                    f"manifest marked unknown database unchanged: {database.relative_path}"
                )
            if version_changed:
                raise ExportError(
                    f"account version changed but {database.relative_path} was not staged"
                )
            if database.legacy_phone_bootstrap:
                if any(
                    prior[field]
                    for field in (
                        "source_sha256",
                        "snapshot_sha256",
                        "auxiliary_sha256",
                    )
                ):
                    raise ExportError(
                        f"legacy bootstrap marker was supplied for an already fingerprinted "
                        f"database: {database.relative_path}"
                    )
                proof = _legacy_phone_bootstrap_fingerprints(
                    duck, database.database_id
                )
                if (
                    not same_local_file(
                        database.source_path, as_string(proof["source_path"])
                    )
                    or database.source_sha256 != proof["source_sha256"]
                    or database.snapshot_size != proof["snapshot_size"]
                    or database.snapshot_sha256 != proof["snapshot_sha256"]
                    or database.auxiliary_sha256 != proof["auxiliary_sha256"]
                ):
                    raise ExportError(
                        f"legacy phone-backup proof changed after staging: "
                        f"{database.relative_path}"
                    )
                record_warning(
                    duck,
                    "legacy_phone_bootstrap",
                    "Reused a v1 phone-backup partition after exact Backup.db metadata, "
                    "NTFS ChangeTime cutoff, archive inventory, and stored "
                    "ciphertext-segment verification; the v1 export did not retain "
                    "a prior Backup.db ciphertext digest.",
                    database.account.account_id,
                    database.database_id,
                )
                reused.append(database)
                continue
            if not database.source_sha256 or database.source_sha256 != prior["source_sha256"]:
                raise ExportError(
                    f"unchanged source fingerprint does not match baseline: {database.relative_path}"
                )
            if database.auxiliary_sha256 != prior["auxiliary_sha256"]:
                raise ExportError(
                    f"unchanged auxiliary fingerprint does not match baseline: {database.relative_path}"
                )
            if (
                not database.snapshot_sha256
                or database.snapshot_sha256 != prior["snapshot_sha256"]
                or not database_partition_is_healthy(duck, database.database_id)
            ):
                raise ExportError(
                    f"baseline partition cannot be safely reused: {database.relative_path}"
                )
            reused.append(database)
            continue
        if status != "ok":
            error = ExportError(
                f"database was not staged successfully: {database.relative_path}: "
                f"{database.stage_error or database.stage_status}"
            )
            record_error(
                duck,
                "database_stage",
                error,
                database.account.account_id,
                database.database_id,
            )
            if not allow_partial:
                raise error
            if prior is not None and database_partition_is_healthy(duck, database.database_id):
                stale_reused.append(database)
            continue

        database = verify_staged_snapshot(database)
        incoming[database.database_id] = database
        same_snapshot = bool(
            prior
            and not version_changed
            and prior["snapshot_sha256"]
            and prior["snapshot_sha256"] == database.snapshot_sha256
            and prior["auxiliary_sha256"] == database.auxiliary_sha256
            and database_partition_is_healthy(duck, database.database_id)
        )
        if same_snapshot:
            reused.append(database)
        else:
            changed.append(database)
            if prior is None:
                added_ids.add(database.database_id)
            else:
                changed_ids.add(database.database_id)

    incoming_ids = set(incoming)
    removable_accounts = {
        account.account_id
        for account in accounts
        if account.resolved and account.status.casefold() == "complete"
    }
    removed_ids: set[str] = set()
    if manifest.get("status") == "complete":
        removed_ids = {
            database_id
            for database_id, prior in existing.items()
            if prior["account_id"] in removable_accounts and database_id not in incoming_ids
        }

    impacted_v4_accounts = {
        database.account.account_id
        for database in changed
        if database.account.version == 4
    }
    stale_v4_accounts = {
        database.account.account_id
        for database in stale_reused
        if database.account.version == 4
    }
    for database_id in removed_ids:
        prior_account = existing[database_id]["account_id"]
        if old_account_versions.get(prior_account) == 4:
            impacted_v4_accounts.add(prior_account)
    unsafe_v4_accounts = impacted_v4_accounts & stale_v4_accounts
    if unsafe_v4_accounts:
        raise ExportError(
            "cannot partially refresh a v4 account when another one of its databases "
            "failed staging: " + ", ".join(sorted(unsafe_v4_accounts))
        )
    downgraded_v4_accounts = {
        account.account_id
        for account in accounts
        if old_account_versions.get(account.account_id) == 4 and account.version != 4
    }

    for database_id in sorted(changed_ids | added_ids | removed_ids):
        if database_id in existing:
            drop_database_partition(duck, database_id)

    for database_id in sorted(removed_ids):
        duck.execute(
            f"UPDATE {quote_ident(CATALOG_SCHEMA)}.database_files "
            "SET present=FALSE, import_status='removed', stage_status='not_seen', "
            "last_changed_run_id=? WHERE database_id=?",
            [run_id, database_id],
        )

    for database in reused:
        if database.database_id in existing:
            update_reused_database(duck, database, run_id)
    for database in stale_reused:
        mark_reused_database_stale(duck, database, run_id)

    imported_changed: list[ImportedObject] = []
    for database in changed:
        first_seen = (
            existing.get(database.database_id, {}).get("first_seen_run_id")
            if database.database_id in existing
            else None
        )
        replace_database_catalog(duck, database, run_id, as_string(first_seen))
        imported_changed.extend(
            process_database(
                duck,
                database,
                sqlite_extension_available,
                False,
                verify_snapshot=False,
            )
        )

    changed_backup_databases = [
        database
        for database in changed
        if database.mode == "decrypted_phone_backup_index"
    ]
    backup_rows = import_phone_backup_messages(
        duck, changed_backup_databases, backup_key, False
    )

    for account_id in sorted(downgraded_v4_accounts):
        if table_exists(duck, CHATLOG_SCHEMA, "v4_talker_map"):
            duck.execute(
                f"DELETE FROM {quote_ident(CHATLOG_SCHEMA)}.v4_talker_map "
                "WHERE account_id=?",
                [account_id],
            )
        if table_exists(duck, CHATLOG_SCHEMA, "v4_sender_map"):
            duck.execute(
                f"DELETE FROM {quote_ident(CHATLOG_SCHEMA)}.v4_sender_map "
                "WHERE account_id=?",
                [account_id],
            )

    project_contact_objects(duck, imported_changed, False)
    project_contact_tag_objects(duck, imported_changed, False)

    changed_direct_messages = [
        item
        for item in imported_changed
        if not (
            canonical_kind(item)[0] == "v4_msg"
            and item.database.account.account_id in impacted_v4_accounts
        )
    ]
    project_message_objects(duck, changed_direct_messages, False)

    if impacted_v4_accounts:
        placeholders = ", ".join("?" for _ in impacted_v4_accounts)
        duck.execute(
            f"DELETE FROM {quote_ident(CHATLOG_SCHEMA)}.messages "
            f"WHERE account_id IN ({placeholders}) AND source_kind='v4_msg'",
            sorted(impacted_v4_accounts),
        )
        all_v4_objects = load_current_imported_objects(
            duck, incoming, impacted_v4_accounts
        )
        create_v4_maps(duck, all_v4_objects, impacted_v4_accounts)
        project_message_objects(
            duck,
            [item for item in all_v4_objects if canonical_kind(item)[0] == "v4_msg"],
            False,
        )

    project_phone_backup_messages(
        duck, [database.database_id for database in changed_backup_databases]
    )
    # Semantic v7 also corrects unchanged canonical rows; old status/peer
    # heuristics cannot survive a no-op Delta after the adapter is upgraded.
    if baseline_schema_version < 7:
        refresh_identity_directions(duck)

    duplicate_messages = int(
        duck.execute(
            f"SELECT count(*) - count(DISTINCT source_message_key) "
            f"FROM {quote_ident(CHATLOG_SCHEMA)}.messages "
            "WHERE source_message_key IS NOT NULL"
        ).fetchone()[0]
    )
    if duplicate_messages:
        raise ExportError(
            f"delta produced {duplicate_messages} duplicate canonical message key(s)"
        )
    dangling = int(
        duck.execute(
            f"SELECT count(*) FROM {quote_ident(CHATLOG_SCHEMA)}.messages m "
            f"LEFT JOIN {quote_ident(CATALOG_SCHEMA)}.database_files d "
            "ON d.database_id=m.database_id AND d.present=TRUE "
            "WHERE d.database_id IS NULL"
        ).fetchone()[0]
    )
    if dangling:
        raise ExportError(f"delta produced {dangling} message row(s) for absent databases")

    return {
        "added": len(added_ids),
        "changed": len(changed_ids),
        "removed": len(removed_ids),
        "reused": len(reused) + len(stale_reused),
        "objects": len(imported_changed),
        "raw_rows": sum(item.imported_rows for item in imported_changed),
        "backup_rows": backup_rows,
    }


def remove_partial(path: Path) -> None:
    for candidate in (path, Path(str(path) + ".wal")):
        try:
            if candidate.is_file():
                candidate.unlink()
        except OSError:
            pass


def reject_duckdb_wal(path: Path, label: str) -> None:
    wal_path = Path(str(path) + ".wal")
    if wal_path.exists():
        raise ExportError(
            f"{label} has an existing DuckDB WAL and may be open or uncheckpointed: "
            f"{wal_path}"
        )


def file_state(path: Path) -> tuple[int, int]:
    try:
        value = path.stat()
    except OSError as exc:
        raise ExportError(f"cannot inspect {path}: {safe_error(exc)}") from exc
    if not path.is_file():
        raise ExportError(f"expected a regular DuckDB file: {path}")
    return value.st_size, value.st_mtime_ns


def latest_completed_run(
    connection: duckdb.DuckDBPyConnection,
) -> tuple[str, bool]:
    row = connection.execute(
        f"SELECT run_id, partial FROM {quote_ident(CATALOG_SCHEMA)}.runs "
        "WHERE completed=TRUE "
        "ORDER BY completed_at DESC NULLS LAST, imported_at DESC LIMIT 1"
    ).fetchone()
    if row is None or not row[0]:
        raise ExportError("baseline has no completed export run")
    return str(row[0]), bool(row[1])


def validate_read_only_baseline(
    connection: duckdb.DuckDBPyConnection,
) -> tuple[str, bool]:
    required = ("runs", "accounts", "database_files", "objects", "errors", "warnings")
    missing = [
        name for name in required if not table_exists(connection, CATALOG_SCHEMA, name)
    ]
    if missing or not table_exists(connection, CHATLOG_SCHEMA, "messages"):
        details = ", ".join(missing + (["chatlog.messages"] if not table_exists(connection, CHATLOG_SCHEMA, "messages") else []))
        raise ExportError(
            "baseline is not a compatible WeChat export; missing table(s): " + details
        )
    if table_exists(connection, CATALOG_SCHEMA, "meta"):
        rows = connection.execute(
            f"SELECT schema_version FROM {quote_ident(CATALOG_SCHEMA)}.meta"
        ).fetchall()
        if len(rows) != 1:
            raise ExportError("baseline export_catalog.meta must contain exactly one row")
        version = int(rows[0][0])
        if version > EXPORT_SCHEMA_VERSION:
            raise ExportError(
                f"baseline schema version {version} is newer than this exporter "
                f"(version {EXPORT_SCHEMA_VERSION})"
            )
    return latest_completed_run(connection)


def _baseline_expression(columns: set[str], name: str, fallback: str) -> str:
    return f"d.{quote_ident(name)}" if name.casefold() in columns else fallback


def _rfc3339_nano(timestamp_ns: int) -> str:
    seconds, nanoseconds = divmod(timestamp_ns, 1_000_000_000)
    prefix = datetime.fromtimestamp(seconds, timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%S"
    )
    fraction = f"{nanoseconds:09d}".rstrip("0")
    return prefix + (f".{fraction}" if fraction else "") + "Z"


def _legacy_regular_file_state(path: Path) -> tuple[os.stat_result, tuple[int, ...]]:
    try:
        stat = path.lstat()
    except OSError as exc:
        raise ExportError(f"legacy phone-backup input is unavailable: {path}: {safe_error(exc)}") from exc
    reparse_flag = getattr(stat, "st_file_attributes", 0) & getattr(
        os, "FILE_ATTRIBUTE_REPARSE_POINT", 0
    )
    if path.is_symlink() or reparse_flag or not path.is_file():
        raise ExportError(
            f"legacy phone-backup input is not a regular non-reparse file: {path}"
        )
    state = (
        int(stat.st_size),
        int(stat.st_mtime_ns),
        int(stat.st_mode),
        int(stat.st_dev),
        int(stat.st_ino),
    )
    return stat, state


def _legacy_windows_change_time_ns(source: Any) -> int:
    """Return NTFS ChangeTime for an open file, failing closed off Windows."""
    if os.name != "nt":
        raise ExportError(
            "legacy phone-backup reuse requires Windows file ChangeTime evidence"
        )

    import ctypes
    import msvcrt
    from ctypes import wintypes

    class FileBasicInfo(ctypes.Structure):
        _fields_ = (
            ("creation_time", ctypes.c_longlong),
            ("last_access_time", ctypes.c_longlong),
            ("last_write_time", ctypes.c_longlong),
            ("change_time", ctypes.c_longlong),
            ("file_attributes", wintypes.DWORD),
        )

    get_file_information = ctypes.WinDLL(
        "kernel32", use_last_error=True
    ).GetFileInformationByHandleEx
    get_file_information.argtypes = (
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
    )
    get_file_information.restype = wintypes.BOOL
    information = FileBasicInfo()
    handle = wintypes.HANDLE(msvcrt.get_osfhandle(source.fileno()))
    get_volume_information = ctypes.WinDLL(
        "kernel32", use_last_error=True
    ).GetVolumeInformationByHandleW
    get_volume_information.argtypes = (
        wintypes.HANDLE,
        wintypes.LPWSTR,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPWSTR,
        wintypes.DWORD,
    )
    get_volume_information.restype = wintypes.BOOL
    filesystem = ctypes.create_unicode_buffer(32)
    if not get_volume_information(
        handle,
        None,
        0,
        None,
        None,
        None,
        filesystem,
        len(filesystem),
    ):
        raise ExportError(
            "cannot identify the filesystem for legacy phone-backup evidence: "
            + safe_error(ctypes.WinError(ctypes.get_last_error()))
        )
    if filesystem.value.casefold() != "ntfs":
        raise ExportError(
            "legacy phone-backup reuse requires NTFS ChangeTime evidence"
        )
    if not get_file_information(
        handle, 0, ctypes.byref(information), ctypes.sizeof(information)
    ):
        raise ExportError(
            "cannot read Windows ChangeTime for legacy phone-backup evidence: "
            + safe_error(ctypes.WinError(ctypes.get_last_error()))
        )

    # Windows timestamps are 100-nanosecond ticks since 1601-01-01 UTC.
    unix_epoch_ticks = 116_444_736_000_000_000
    if information.change_time < unix_epoch_ticks:
        raise ExportError("legacy phone-backup input has an invalid Windows ChangeTime")
    return (int(information.change_time) - unix_epoch_ticks) * 100


def _legacy_phone_bootstrap_fingerprints(
    connection: duckdb.DuckDBPyConnection, database_id: str
) -> dict[str, Any]:
    """Prove a v1 phone partition still matches its live encrypted bundle.

    A v1 catalog has no ciphertext digest for Backup.db.  This migration is
    therefore deliberately limited to an exact main-file metadata match plus
    exact archive inventory metadata and every text segment ciphertext digest
    retained by the original export.  General SQLite databases never use this
    compatibility path.
    """

    row = connection.execute(
        f"SELECT d.source_path, d.relative_path, d.source_size, "
        "d.source_modified_at, d.stage_mode, d.import_status, a.data_dir "
        f"FROM {quote_ident(CATALOG_SCHEMA)}.database_files d "
        f"JOIN {quote_ident(CATALOG_SCHEMA)}.accounts a "
        "ON a.account_id=d.account_id WHERE d.database_id=?",
        [database_id],
    ).fetchone()
    if row is None:
        raise ExportError(f"legacy phone-backup database is missing: {database_id}")
    cutoff_row = connection.execute(
        f"SELECT manifest_generated_at, epoch_ns(imported_at) "
        f"FROM {quote_ident(CATALOG_SCHEMA)}.runs "
        "WHERE completed=TRUE "
        "ORDER BY completed_at DESC, imported_at DESC LIMIT 1"
    ).fetchone()
    if cutoff_row is None or not as_string(cutoff_row[0]).strip():
        raise ExportError("legacy phone-backup export has no staging-time cutoff")
    try:
        generated_at = datetime.fromisoformat(
            as_string(cutoff_row[0]).strip().replace("Z", "+00:00")
        )
        if generated_at.tzinfo is None:
            raise ValueError("timestamp has no timezone")
        generated_at = generated_at.astimezone(timezone.utc)
        epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
        elapsed = generated_at - epoch
        generated_ns = (
            (elapsed.days * 86_400 + elapsed.seconds) * 1_000_000_000
            + elapsed.microseconds * 1_000
        )
        imported_ns = int(cutoff_row[1])
    except (OverflowError, TypeError, ValueError) as exc:
        raise ExportError("legacy phone-backup staging-time cutoff is invalid") from exc
    legacy_cutoff_ns = min(generated_ns, imported_ns)
    if legacy_cutoff_ns <= 0:
        raise ExportError("legacy phone-backup staging-time cutoff is invalid")
    source_path = Path(as_string(row[0])).resolve()
    relative_path = as_string(row[1]).replace("\\", "/").lstrip("/")
    source_size = as_optional_int(row[2])
    source_modified_at = as_string(row[3])
    mode = as_string(row[4])
    import_status = as_string(row[5]).casefold()
    data_dir = Path(as_string(row[6])).resolve()
    relative = Path(relative_path)
    if (
        mode != "decrypted_phone_backup_index"
        or import_status != "ok"
        or not re.fullmatch(r"BackupFiles/.+/Backup\.db", relative_path, re.IGNORECASE)
        or relative.is_absolute()
        or ".." in relative.parts
    ):
        raise ExportError("legacy compatibility proof is limited to an imported Backup.db")
    expected_source = (data_dir / relative).resolve()
    if not same_local_file(source_path, expected_source):
        raise ExportError("legacy Backup.db source path no longer matches its account")
    if source_size is None or source_size <= 0 or not source_modified_at:
        raise ExportError("legacy Backup.db catalog metadata is incomplete")
    if os.path.lexists(str(source_path) + "-wal"):
        raise ExportError("legacy Backup.db has a WAL and cannot be reused without its key")
    source_stat, source_state = _legacy_regular_file_state(source_path)
    if source_state[0] != source_size or _rfc3339_nano(source_state[1]) != source_modified_at:
        raise ExportError("legacy Backup.db size or modification time changed")
    if not database_partition_is_healthy(connection, database_id):
        raise ExportError("legacy phone-backup DuckDB partition is not healthy")

    source_digest = hashlib.sha256()
    source_digest.update(b"wechat-database-source-v1\x00")
    source_digest.update(f"4:main:true:{source_state[0]}:".encode("ascii"))
    try:
        with source_path.open("rb") as source:
            source_change_time = _legacy_windows_change_time_ns(source)
            if source_change_time > legacy_cutoff_ns:
                raise ExportError(
                    "legacy Backup.db changed after the baseline export completed"
                )
            if tuple(
                int(value)
                for value in (
                    os.fstat(source.fileno()).st_size,
                    os.fstat(source.fileno()).st_mtime_ns,
                    os.fstat(source.fileno()).st_mode,
                    os.fstat(source.fileno()).st_dev,
                    os.fstat(source.fileno()).st_ino,
                )
            ) != source_state:
                raise ExportError("legacy Backup.db changed while it was opened")
            while chunk := source.read(8 * 1024 * 1024):
                source_digest.update(chunk)
            opened_after = os.fstat(source.fileno())
            if _legacy_windows_change_time_ns(source) != source_change_time:
                raise ExportError(
                    "legacy Backup.db ChangeTime changed while it was fingerprinted"
                )
    except OSError as exc:
        raise ExportError(f"cannot fingerprint legacy Backup.db: {safe_error(exc)}") from exc
    _, source_after = _legacy_regular_file_state(source_path)
    opened_after_state = tuple(
        int(value)
        for value in (
            opened_after.st_size,
            opened_after.st_mtime_ns,
            opened_after.st_mode,
            opened_after.st_dev,
            opened_after.st_ino,
        )
    )
    if opened_after_state != source_state or source_after != source_state:
        raise ExportError("legacy Backup.db changed while it was fingerprinted")
    if os.path.lexists(str(source_path) + "-wal"):
        raise ExportError("legacy Backup.db acquired a WAL while it was fingerprinted")
    source_digest.update(b"3:wal:false:0:")
    source_sha256 = source_digest.hexdigest()

    required_tables = (
        "backup_archive_files",
        "backup_text_segments",
        "backup_message_records",
    )
    if any(
        not table_exists(connection, CHATLOG_SCHEMA, table)
        for table in required_tables
    ):
        raise ExportError("legacy phone-backup evidence tables are incomplete")
    archive_rows = connection.execute(
        f"SELECT source_name, payload_kind, source_size, source_modified_ns, "
        "indexed_segments, indexed_bytes, unindexed_bytes "
        f"FROM {quote_ident(CHATLOG_SCHEMA)}.backup_archive_files "
        "WHERE database_id=? ORDER BY lower(source_name), source_name",
        [database_id],
    ).fetchall()
    if not archive_rows:
        raise ExportError("legacy phone-backup archive inventory is empty")
    expected_archives: dict[str, tuple[Any, ...]] = {}
    for archive_row in archive_rows:
        name = as_string(archive_row[0])
        identity = name.casefold()
        if (
            not name
            or Path(name).name != name
            or "/" in name
            or "\\" in name
            or identity in expected_archives
        ):
            raise ExportError("legacy phone-backup archive inventory is invalid")
        expected_archives[identity] = (
            name,
            as_string(archive_row[1]).casefold(),
            int(archive_row[2]),
            int(archive_row[3]),
            int(archive_row[4]),
            int(archive_row[5]),
            int(archive_row[6]),
        )

    bundle_root = source_path.parent

    def inventory() -> list[tuple[str, str, Path, tuple[int, ...]]]:
        entries: list[tuple[str, str, Path, tuple[int, ...]]] = []
        seen: set[str] = set()
        try:
            directory_entries = list(os.scandir(bundle_root))
        except OSError as exc:
            raise ExportError(
                f"cannot inventory legacy phone-backup bundle: {safe_error(exc)}"
            ) from exc
        for entry in directory_entries:
            upper = entry.name.upper()
            if upper.startswith("BAK_") and upper.endswith("_TEXT"):
                kind = "text"
            elif upper.startswith("BAK_") and upper.endswith("_MEDIA"):
                kind = "media"
            else:
                continue
            identity = entry.name.casefold()
            if identity in seen:
                raise ExportError("legacy phone-backup bundle has duplicate archive names")
            seen.add(identity)
            path = Path(entry.path)
            _, state = _legacy_regular_file_state(path)
            entries.append((entry.name, kind, path, state))
        entries.sort(key=lambda item: (item[0].casefold(), item[0]))
        return entries

    before_inventory = inventory()
    if {item[0].casefold() for item in before_inventory} != set(expected_archives):
        raise ExportError("legacy phone-backup archive inventory changed")

    auxiliary_digest = hashlib.sha256()
    auxiliary_digest.update(b"wechat-phone-backup-auxiliary-v1\x00")
    for name, kind, path, state in before_inventory:
        expected = expected_archives[name.casefold()]
        if (
            expected[0] != name
            or expected[1] != kind
            or expected[2] != state[0]
            or expected[3] != state[1]
            or expected[5] + expected[6] != state[0]
        ):
            raise ExportError(f"legacy phone-backup archive changed: {name}")
        encoded_name = name.encode("utf-8")
        encoded_kind = kind.encode("ascii")
        auxiliary_digest.update(
            f"{len(encoded_name)}:".encode("ascii")
            + encoded_name
            + f":{len(encoded_kind)}:".encode("ascii")
            + encoded_kind
            + f":{state[0]}:{state[1]}:".encode("ascii")
        )
        if kind != "text":
            continue
        auxiliary_digest.update(f"12:text-content:true:{state[0]}:".encode("ascii"))
        segments = connection.execute(
            f"SELECT source_file, source_offset, encrypted_length, ciphertext_sha256 "
            f"FROM {quote_ident(CHATLOG_SCHEMA)}.backup_text_segments "
            "WHERE database_id=? AND lower(source_file)=lower(?) "
            "ORDER BY source_offset, segment_key",
            [database_id, name],
        ).fetchall()
        if len(segments) != expected[4] or sum(int(item[2]) for item in segments) != expected[5]:
            raise ExportError(f"legacy phone-backup segment inventory is inconsistent: {name}")
        cursor = 0

        def consume(source: Any, length: int, segment_digest: Any | None = None) -> None:
            remaining = length
            while remaining:
                chunk = source.read(min(8 * 1024 * 1024, remaining))
                if not chunk:
                    raise ExportError(f"legacy phone-backup archive ended early: {name}")
                auxiliary_digest.update(chunk)
                if segment_digest is not None:
                    segment_digest.update(chunk)
                remaining -= len(chunk)

        try:
            with path.open("rb") as source:
                archive_change_time = _legacy_windows_change_time_ns(source)
                if archive_change_time > legacy_cutoff_ns:
                    raise ExportError(
                        f"legacy phone-backup archive changed after export: {name}"
                    )
                opened = os.fstat(source.fileno())
                opened_state = tuple(
                    int(value)
                    for value in (
                        opened.st_size,
                        opened.st_mtime_ns,
                        opened.st_mode,
                        opened.st_dev,
                        opened.st_ino,
                    )
                )
                if opened_state != state:
                    raise ExportError(f"legacy phone-backup archive changed: {name}")
                for raw_source_file, raw_offset, raw_length, raw_digest in segments:
                    if as_string(raw_source_file) != name:
                        raise ExportError(f"legacy phone-backup segment filename changed: {name}")
                    offset = int(raw_offset)
                    length = int(raw_length)
                    expected_digest = as_string(raw_digest).lower()
                    if (
                        offset < cursor
                        or length <= 0
                        or offset + length > state[0]
                        or not re.fullmatch(r"[0-9a-f]{64}", expected_digest)
                    ):
                        raise ExportError(f"legacy phone-backup segment metadata is invalid: {name}")
                    consume(source, offset - cursor)
                    segment_digest = hashlib.sha256()
                    consume(source, length, segment_digest)
                    if segment_digest.hexdigest() != expected_digest:
                        raise ExportError(f"legacy phone-backup segment changed: {name}@{offset}")
                    cursor = offset + length
                consume(source, state[0] - cursor)
                opened_after = os.fstat(source.fileno())
                if _legacy_windows_change_time_ns(source) != archive_change_time:
                    raise ExportError(
                        f"legacy phone-backup archive ChangeTime changed: {name}"
                    )
        except OSError as exc:
            raise ExportError(
                f"cannot validate legacy phone-backup archive {name}: {safe_error(exc)}"
            ) from exc
        _, after_state = _legacy_regular_file_state(path)
        if (
            tuple(
                int(value)
                for value in (
                    opened_after.st_size,
                    opened_after.st_mtime_ns,
                    opened_after.st_mode,
                    opened_after.st_dev,
                    opened_after.st_ino,
                )
            )
            != state
            or after_state != state
        ):
            raise ExportError(f"legacy phone-backup archive changed: {name}")

    if inventory() != before_inventory:
        raise ExportError("legacy phone-backup bundle changed while it was validated")
    auxiliary_sha256 = auxiliary_digest.hexdigest()
    snapshot_digest = hashlib.sha256()
    snapshot_digest.update(b"wechat-legacy-phone-partition-v1\x00")
    snapshot_digest.update(database_id.encode("ascii"))
    snapshot_digest.update(b"\x00" + source_sha256.encode("ascii"))
    snapshot_digest.update(b"\x00" + auxiliary_sha256.encode("ascii"))
    return {
        "source_path": str(source_path),
        "source_sha256": source_sha256,
        "snapshot_size": source_size,
        "snapshot_sha256": snapshot_digest.hexdigest(),
        "auxiliary_sha256": auxiliary_sha256,
        "legacy_phone_bootstrap": True,
    }


def build_delta_baseline(base_path: Path) -> dict[str, Any]:
    """Read the reusable source fingerprints without modifying the DuckDB."""
    base_path = base_path.resolve()
    reject_duckdb_wal(base_path, "baseline")
    before = file_state(base_path)
    connection: duckdb.DuckDBPyConnection | None = None
    try:
        connection = duckdb.connect(str(base_path), read_only=True)
        connection.execute("SET TimeZone='UTC'")
        base_run_id, base_partial = validate_read_only_baseline(connection)
        if base_partial:
            raise ExportError(
                "the latest completed baseline run is partial; create a complete export "
                "before using delta mode"
            )
        database_columns = table_columns(connection, CATALOG_SCHEMA, "database_files")
        fingerprint_columns = {
            "source_sha256",
            "snapshot_size",
            "snapshot_sha256",
            "auxiliary_sha256",
        }
        legacy_catalog = (
            not table_exists(connection, CATALOG_SCHEMA, "meta")
            and fingerprint_columns.isdisjoint(database_columns)
        )
        present = _baseline_expression(database_columns, "present", "TRUE")
        source_sha256 = _baseline_expression(database_columns, "source_sha256", "NULL")
        snapshot_size = _baseline_expression(database_columns, "snapshot_size", "NULL")
        snapshot_sha256 = _baseline_expression(database_columns, "snapshot_sha256", "NULL")
        auxiliary_sha256 = _baseline_expression(database_columns, "auxiliary_sha256", "NULL")
        rows = connection.execute(
            f"""
            SELECT a.account_id, a.data_dir, a.version, d.relative_path, d.import_status,
                   {source_sha256}, {snapshot_size}, {snapshot_sha256},
                   {auxiliary_sha256}, d.database_id, d.stage_mode
            FROM {quote_ident(CATALOG_SCHEMA)}.accounts AS a
            LEFT JOIN {quote_ident(CATALOG_SCHEMA)}.database_files AS d
              ON d.account_id=a.account_id AND {present}
            ORDER BY a.account_id, lower(coalesce(d.relative_path, '')), d.relative_path
            """
        ).fetchall()
        legacy_phone_bootstraps: dict[str, dict[str, Any]] = {}
        if legacy_catalog:
            for row in rows:
                database_id = as_string(row[9])
                if (
                    database_id
                    and as_string(row[4]).casefold() == "ok"
                    and as_string(row[10]) == "decrypted_phone_backup_index"
                    and not any(as_string(row[index]) for index in (5, 7, 8))
                ):
                    try:
                        legacy_phone_bootstraps[database_id] = (
                            _legacy_phone_bootstrap_fingerprints(
                                connection, database_id
                            )
                        )
                    except (ExportError, OSError, ValueError, duckdb.Error):
                        # The normal staging path will require BackupKeyFile.  A
                        # failed compatibility proof must never become reuse.
                        continue
    except duckdb.Error as exc:
        raise ExportError(f"cannot read delta baseline {base_path}: {safe_error(exc)}") from exc
    finally:
        if connection is not None:
            connection.close()
    reject_duckdb_wal(base_path, "baseline")
    after = file_state(base_path)
    if before != after:
        raise ExportError(f"baseline changed while its catalog was being read: {base_path}")

    accounts_by_id: dict[str, dict[str, Any]] = {}
    digest_pattern = re.compile(r"^[0-9a-f]{64}$")
    for row in rows:
        account_id = as_string(row[0]).strip()
        data_dir = as_string(row[1]).strip()
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", account_id):
            raise ExportError(f"baseline contains an unsafe account id: {account_id!r}")
        if not data_dir:
            raise ExportError(f"baseline account {account_id!r} has no data_dir")
        account = accounts_by_id.setdefault(
            account_id,
            {
                "id": account_id,
                "data_dir": data_dir,
                "version": as_optional_int(row[2]) or 0,
                "files": [],
            },
        )
        if account["data_dir"] != data_dir:
            raise ExportError(f"baseline account {account_id!r} has conflicting data directories")
        if row[3] is None:
            continue
        relative_path = as_string(row[3]).replace("\\", "/").lstrip("/")
        if not relative_path:
            raise ExportError(f"baseline account {account_id!r} contains an empty relative path")
        reusable = as_string(row[4]).casefold() == "ok"
        source_digest = as_string(row[5]).lower() if reusable else ""
        snapshot_digest = as_string(row[7]).lower() if reusable else ""
        auxiliary_digest = as_string(row[8]).lower() if reusable else ""
        snapshot_bytes = (as_optional_int(row[6]) or 0) if reusable else 0
        legacy_bootstrap = legacy_phone_bootstraps.get(as_string(row[9]))
        if reusable and legacy_bootstrap is not None:
            source_digest = as_string(legacy_bootstrap["source_sha256"])
            snapshot_bytes = int(legacy_bootstrap["snapshot_size"])
            snapshot_digest = as_string(legacy_bootstrap["snapshot_sha256"])
            auxiliary_digest = as_string(legacy_bootstrap["auxiliary_sha256"])
        for label, digest in (
            ("source_sha256", source_digest),
            ("snapshot_sha256", snapshot_digest),
            ("auxiliary_sha256", auxiliary_digest),
        ):
            if digest and not digest_pattern.fullmatch(digest):
                raise ExportError(
                    f"baseline {label} is invalid for {account_id}/{relative_path}"
                )
        account["files"].append(
            {
                "relative_path": relative_path,
                "source_sha256": source_digest,
                "snapshot_size": snapshot_bytes,
                "snapshot_sha256": snapshot_digest,
                "auxiliary_sha256": auxiliary_digest,
                "legacy_phone_bootstrap": legacy_bootstrap is not None,
            }
        )

    accounts = sorted(accounts_by_id.values(), key=lambda item: item["id"])
    for account in accounts:
        account["files"].sort(
            key=lambda item: (item["relative_path"].casefold(), item["relative_path"])
        )
    core: dict[str, Any] = {
        "format_version": STAGING_MANIFEST_FORMAT_VERSION,
        "base_run_id": base_run_id,
        "base_partial": base_partial,
        "accounts": accounts,
    }
    canonical = json.dumps(
        core, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    core["catalog_sha256"] = hashlib.sha256(canonical).hexdigest()
    core["base_file_size"] = after[0]
    core["base_file_modified_ns"] = after[1]
    return core


def write_delta_baseline(base_path: Path, destination: Path) -> dict[str, Any]:
    payload = build_delta_baseline(base_path)
    destination = destination.resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(
        destination.name + f".partial-{os.getpid()}-{uuid.uuid4().hex[:8]}"
    )
    try:
        temporary.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        os.replace(temporary, destination)
    finally:
        try:
            if temporary.is_file():
                temporary.unlink()
        except OSError:
            pass
    return payload


def copy_baseline(base_path: Path, partial_path: Path) -> tuple[tuple[int, int], str]:
    reject_duckdb_wal(base_path, "baseline")
    before = file_state(base_path)
    connection: duckdb.DuckDBPyConnection | None = None
    try:
        connection = duckdb.connect(str(base_path), read_only=True)
        base_run_id, base_partial = validate_read_only_baseline(connection)
        if base_partial:
            raise ExportError(
                "the latest completed baseline run is partial; create a complete export "
                "before using delta mode"
            )
    finally:
        if connection is not None:
            connection.close()
    try:
        shutil.copyfile(base_path, partial_path)
    except OSError as exc:
        raise ExportError(f"cannot copy delta baseline: {safe_error(exc)}") from exc
    reject_duckdb_wal(base_path, "baseline")
    after = file_state(base_path)
    if before != after:
        raise ExportError(f"baseline changed while it was being copied: {base_path}")
    if file_state(partial_path)[0] != before[0]:
        raise ExportError("delta baseline copy has the wrong size")
    return before, base_run_id


def assert_baseline_unchanged(
    base_path: Path, expected_state: tuple[int, int], expected_run_id: str
) -> None:
    reject_duckdb_wal(base_path, "baseline")
    if file_state(base_path) != expected_state:
        raise ExportError("baseline changed while the delta export was running")
    connection: duckdb.DuckDBPyConnection | None = None
    try:
        connection = duckdb.connect(str(base_path), read_only=True)
        current_run_id, _partial = validate_read_only_baseline(connection)
    finally:
        if connection is not None:
            connection.close()
    if current_run_id != expected_run_id:
        raise ExportError("baseline completed-run identity changed during delta export")


def expected_contact_rows(duck: duckdb.DuckDBPyConnection) -> int:
    expected = 0
    for imported in load_current_imported_objects(duck, {}):
        kind, required = canonical_contact_kind(imported)
        if kind is None:
            continue
        if required <= set(column_lookup(imported.source)):
            expected += imported.imported_rows
    return expected


def expected_contact_tag_rows(
    duck: duckdb.DuckDBPyConnection,
) -> tuple[int, int]:
    expected_definitions = 0
    expected_tags = 0
    for imported in load_current_imported_objects(duck, {}):
        role = windows_v3_contact_tag_role(imported)
        columns = column_lookup(imported.source)
        if role == "definition":
            if {"labelid", "labelname"} <= set(columns):
                expected_definitions += imported.imported_rows
        elif (
            role == "contact"
            and "username" in columns
            and "labelidlist" in columns
        ):
            expected_tags += count_nonblank_contact_tag_tokens(
                duck,
                imported.database.account.raw_schema,
                imported.raw_table,
                columns["labelidlist"],
            )
    return expected_definitions, expected_tags


def validate_export(duck: duckdb.DuckDBPyConnection) -> None:
    mismatched = int(
        duck.execute(
            f"SELECT count(*) FROM {quote_ident(CATALOG_SCHEMA)}.database_files "
            "WHERE present=TRUE AND import_status='ok' AND source_rows<>imported_rows"
        ).fetchone()[0]
    )
    if mismatched:
        raise ExportError(f"{mismatched} database partition(s) have row-count mismatches")
    duplicate_messages = int(
        duck.execute(
            f"SELECT count(*) - count(DISTINCT source_message_key) "
            f"FROM {quote_ident(CHATLOG_SCHEMA)}.messages "
            "WHERE source_message_key IS NOT NULL"
        ).fetchone()[0]
    )
    if duplicate_messages:
        raise ExportError(
            f"export contains {duplicate_messages} duplicate canonical message key(s)"
        )
    dangling = int(
        duck.execute(
            f"SELECT count(*) FROM {quote_ident(CHATLOG_SCHEMA)}.messages m "
            f"LEFT JOIN {quote_ident(CATALOG_SCHEMA)}.database_files d "
            "ON d.database_id=m.database_id AND d.present=TRUE "
            "WHERE d.database_id IS NULL"
        ).fetchone()[0]
    )
    if dangling:
        raise ExportError(f"export contains {dangling} canonical row(s) for absent databases")
    if not table_exists(duck, CHATLOG_SCHEMA, "contacts"):
        raise ExportError("export is missing chatlog.contacts")
    validate_contacts_table_schema(duck)
    actual_contacts = int(
        duck.execute(
            f"SELECT count(*) FROM {quote_ident(CHATLOG_SCHEMA)}.contacts"
        ).fetchone()[0]
    )
    projected_contacts = expected_contact_rows(duck)
    if actual_contacts != projected_contacts:
        raise ExportError(
            "canonical contact row-count mismatch: "
            f"raw={projected_contacts}, projected={actual_contacts}"
        )
    duplicate_contacts = int(
        duck.execute(
            f"SELECT count(*) - count(DISTINCT source_contact_key) "
            f"FROM {quote_ident(CHATLOG_SCHEMA)}.contacts"
        ).fetchone()[0]
    )
    if duplicate_contacts:
        raise ExportError(
            f"export contains {duplicate_contacts} duplicate canonical contact key(s)"
        )
    dangling_contacts = int(
        duck.execute(
            f"SELECT count(*) FROM {quote_ident(CHATLOG_SCHEMA)}.contacts c "
            f"LEFT JOIN {quote_ident(CATALOG_SCHEMA)}.database_files d "
            "ON d.database_id=c.database_id AND d.present=TRUE "
            "WHERE d.database_id IS NULL"
        ).fetchone()[0]
    )
    if dangling_contacts:
        raise ExportError(
            f"export contains {dangling_contacts} contact row(s) for absent databases"
        )
    invalid_contact_profiles = int(
        duck.execute(
            f"SELECT count(*) FROM {quote_ident(CHATLOG_SCHEMA)}.contacts "
            "WHERE extra_buf_parse_status IS NULL "
            "OR (source_kind='windows_v3_contact' AND ("
            "extra_buf_parse_status NOT IN "
            "('ok', 'not_present', 'not_available', 'malformed') "
            "OR (extra_buf_parse_status IN "
            "('not_present', 'not_available', 'malformed') AND ("
            "signature IS NOT NULL OR add_scene IS NOT NULL OR country IS NOT NULL "
            "OR add_scene_enum IS NOT NULL OR add_scene_string IS NOT NULL "
            "OR province IS NOT NULL OR city IS NOT NULL)) "
            "OR (extra_buf_parse_status='malformed') "
            "<> (extra_buf_parse_warning IS NOT NULL))) "
            "OR (source_kind<>'windows_v3_contact' AND ("
            "extra_buf_parse_status<>'not_applicable' "
            "OR signature IS NOT NULL OR add_scene IS NOT NULL OR country IS NOT NULL "
            "OR add_scene_enum IS NOT NULL OR add_scene_string IS NOT NULL "
            "OR province IS NOT NULL OR city IS NOT NULL "
            "OR extra_buf_parse_warning IS NOT NULL))"
        ).fetchone()[0]
    )
    if invalid_contact_profiles:
        raise ExportError(
            f"export contains {invalid_contact_profiles} inconsistent contact "
            "ExtraBuf profile row(s)"
        )
    invalid_add_scenes = 0
    for add_scene, add_scene_enum, add_scene_string in duck.execute(
        f"SELECT add_scene, add_scene_enum, add_scene_string "
        f"FROM {quote_ident(CHATLOG_SCHEMA)}.contacts"
    ).fetchall():
        normalized = None if add_scene is None else int(add_scene)
        expected_enum, expected_string = contact_add_scene_values(normalized)
        if (add_scene_enum, add_scene_string) != (expected_enum, expected_string):
            invalid_add_scenes += 1
    if invalid_add_scenes:
        raise ExportError(
            f"export contains {invalid_add_scenes} inconsistent contact "
            "add-scene enum/string row(s)"
        )
    for table in ("contact_tag_definitions", "contact_tags"):
        if not table_exists(duck, CHATLOG_SCHEMA, table):
            raise ExportError(f"export is missing chatlog.{table}")
    validate_contact_tag_table_schemas(duck)
    expected_tag_definitions, expected_tags = expected_contact_tag_rows(duck)
    actual_tag_definitions = int(
        duck.execute(
            f"SELECT count(*) FROM {quote_ident(CHATLOG_SCHEMA)}.contact_tag_definitions"
        ).fetchone()[0]
    )
    actual_tags = int(
        duck.execute(
            f"SELECT count(*) FROM {quote_ident(CHATLOG_SCHEMA)}.contact_tags"
        ).fetchone()[0]
    )
    if actual_tag_definitions != expected_tag_definitions:
        raise ExportError(
            "canonical contact-tag definition row-count mismatch: "
            f"raw={expected_tag_definitions}, projected={actual_tag_definitions}"
        )
    if actual_tags != expected_tags:
        raise ExportError(
            "canonical contact-tag assignment row-count mismatch: "
            f"raw={expected_tags}, projected={actual_tags}"
        )
    for table, key in (
        ("contact_tag_definitions", "source_label_key"),
        ("contact_tags", "source_tag_key"),
    ):
        duplicate_keys = int(
            duck.execute(
                f"SELECT count(*) - count(DISTINCT {quote_ident(key)}) "
                f"FROM {quote_ident(CHATLOG_SCHEMA)}.{quote_ident(table)}"
            ).fetchone()[0]
        )
        if duplicate_keys:
            raise ExportError(
                f"export contains {duplicate_keys} duplicate chatlog.{table} key(s)"
            )
    dangling_tag_databases = int(
        duck.execute(
            f"SELECT count(*) FROM ("
            f"SELECT database_id FROM {quote_ident(CHATLOG_SCHEMA)}.contact_tag_definitions "
            f"UNION ALL SELECT database_id FROM {quote_ident(CHATLOG_SCHEMA)}.contact_tags"
            ") t LEFT JOIN "
            f"{quote_ident(CATALOG_SCHEMA)}.database_files d "
            "ON d.database_id=t.database_id AND d.present=TRUE "
            "WHERE d.database_id IS NULL"
        ).fetchone()[0]
    )
    if dangling_tag_databases:
        raise ExportError(
            f"export contains {dangling_tag_databases} contact-tag row(s) "
            "for absent databases"
        )
    dangling_tag_contacts = int(
        duck.execute(
            f"SELECT count(*) FROM {quote_ident(CHATLOG_SCHEMA)}.contact_tags t "
            f"LEFT JOIN {quote_ident(CHATLOG_SCHEMA)}.contacts c "
            "ON c.source_contact_key=t.source_contact_key "
            "WHERE c.source_contact_key IS NULL"
        ).fetchone()[0]
    )
    if dangling_tag_contacts:
        raise ExportError(
            f"export contains {dangling_tag_contacts} contact-tag assignment(s) "
            "without a canonical contact"
        )
    inconsistent_tag_resolutions = int(
        duck.execute(
            f"SELECT count(*) FROM {quote_ident(CHATLOG_SCHEMA)}.contact_tags t "
            f"LEFT JOIN {quote_ident(CHATLOG_SCHEMA)}.contact_tag_definitions d "
            "ON d.source_label_key=t.label_definition_key "
            "AND d.database_id=t.database_id "
            "WHERE t.tag_ordinal < 1 "
            "OR t.resolved <> (t.label_definition_key IS NOT NULL) "
            "OR (t.resolved AND t.definition_match_count <> 1) "
            "OR (NOT t.resolved AND t.definition_match_count = 1) "
            "OR (t.label_definition_key IS NOT NULL AND d.source_label_key IS NULL) "
            "OR (t.label_definition_key IS NOT NULL "
            "AND d.label_id IS DISTINCT FROM t.label_id)"
        ).fetchone()[0]
    )
    if inconsistent_tag_resolutions:
        raise ExportError(
            f"export contains {inconsistent_tag_resolutions} inconsistent "
            "contact-tag resolution row(s)"
        )


def export(
    manifest_path: Path,
    output_path: Path,
    backup_key_path: Path | None = None,
    base_path: Path | None = None,
    config_path: Path | None = None,
) -> dict[str, int | bool | str]:
    global _ACTIVE_RUN_ID
    manifest_path = manifest_path.resolve()
    output_path = output_path.resolve()
    base_path = None if base_path is None else base_path.resolve()
    mode = "delta" if base_path is not None else "full"
    if base_path is not None and base_path == output_path:
        raise ExportError("delta working output must be different from its baseline")
    manifest = read_manifest(manifest_path)
    if (
        base_path is not None
        and manifest.get("format_version") != STAGING_MANIFEST_FORMAT_VERSION
    ):
        raise ExportError("delta export requires a version 2 staging manifest")
    backup_key = read_backup_key(backup_key_path, config_path)
    allow_partial = bool(manifest.get("allow_partial", False))
    accounts, databases = parse_specs(manifest, manifest_path)
    if not accounts and not allow_partial:
        raise ExportError("manifest contains no accounts")
    if manifest.get("status") != "complete" and not allow_partial:
        raise ExportError(
            f"manifest status is {manifest.get('status')!r}; rerun staging or opt into partial export"
        )
    if not databases and not allow_partial:
        raise ExportError("manifest contains no staged database files")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    reject_duckdb_wal(output_path, "target")
    partial_path = output_path.with_name(
        output_path.name + f".partial-{os.getpid()}-{uuid.uuid4().hex[:8]}"
    )
    remove_partial(partial_path)
    duck: duckdb.DuckDBPyConnection | None = None
    baseline_state: tuple[int, int] | None = None
    base_run_id: str | None = None
    baseline_schema_version = EXPORT_SCHEMA_VERSION
    run_id = str(uuid.uuid4())
    _ACTIVE_RUN_ID = run_id
    try:
        if base_path is not None:
            baseline_state, base_run_id = copy_baseline(base_path, partial_path)
        duck = duckdb.connect(str(partial_path))
        duck.execute("SET TimeZone='UTC'")
        if base_path is None:
            create_catalog(duck)
        else:
            baseline_schema_version = migrate_catalog(duck)
            copied_run_id, _copied_partial = latest_completed_run(duck)
            if copied_run_id != base_run_id:
                raise ExportError("copied baseline completed-run identity does not match source")
        sqlite_extension_available, sqlite_extension_error = try_load_sqlite_extension(duck)
        duck.execute(
            f"""
            INSERT INTO {quote_ident(CATALOG_SCHEMA)}.runs (
                run_id, manifest_path, manifest_format_version,
                manifest_generated_at, manifest_status, allow_partial, imported_at,
                completed_at, completed, partial, sqlite_extension_available,
                sqlite_extension_error, imported_accounts, imported_databases,
                imported_objects, imported_rows, message_rows, contact_rows,
                contact_tag_definition_rows, contact_tag_rows, error_count,
                export_mode, base_run_id, added_databases, changed_databases,
                removed_databases, reused_databases
            ) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, FALSE, FALSE, ?, ?,
                      0, 0, 0, 0, 0, 0, 0, 0, 0, ?, ?, 0, 0, 0, 0)
            """,
            [
                run_id,
                str(manifest_path),
                int(manifest.get("format_version", 0)),
                as_string(manifest.get("generated_at")),
                as_string(manifest.get("status")),
                allow_partial,
                datetime.now(timezone.utc),
                sqlite_extension_available,
                sqlite_extension_error or None,
                mode,
                base_run_id,
            ],
        )
        if sqlite_extension_error:
            record_warning(duck, "sqlite_extension", sqlite_extension_error)

        if base_path is None:
            insert_manifest_catalog(duck, manifest, accounts, databases)
            imported_objects: list[ImportedObject] = []
            for database in databases:
                imported_objects.extend(
                    process_database(
                        duck, database, sqlite_extension_available, allow_partial
                    )
                )
            build_messages(duck, imported_objects, allow_partial)
            build_contacts(duck, imported_objects, allow_partial)
            import_phone_backup_messages(duck, databases, backup_key, allow_partial)
            project_phone_backup_messages(
                duck,
                [
                    database.database_id
                    for database in databases
                    if database.mode == "decrypted_phone_backup_index"
                    and database.stage_status.casefold() == "ok"
                ],
            )
            delta_stats = {
                "added": len(databases),
                "changed": 0,
                "removed": 0,
                "reused": 0,
            }
        else:
            delta_stats = apply_delta(
                duck,
                manifest,
                accounts,
                databases,
                backup_key,
                sqlite_extension_available,
                allow_partial,
                run_id,
                baseline_schema_version,
            )

        record_contact_extra_buf_warnings(duck)
        validate_export(duck)
        message_rows = int(
            duck.execute(
                f"SELECT count(*) FROM {quote_ident(CHATLOG_SCHEMA)}.messages"
            ).fetchone()[0]
        )
        contact_rows = int(
            duck.execute(
                f"SELECT count(*) FROM {quote_ident(CHATLOG_SCHEMA)}.contacts"
            ).fetchone()[0]
        )
        contact_tag_definition_rows = int(
            duck.execute(
                f"SELECT count(*) FROM "
                f"{quote_ident(CHATLOG_SCHEMA)}.contact_tag_definitions"
            ).fetchone()[0]
        )
        contact_tag_rows = int(
            duck.execute(
                f"SELECT count(*) FROM {quote_ident(CHATLOG_SCHEMA)}.contact_tags"
            ).fetchone()[0]
        )
        backup_message_rows = int(
            duck.execute(
                f"SELECT count(*) FROM {quote_ident(CHATLOG_SCHEMA)}.backup_message_records"
            ).fetchone()[0]
        )
        error_count = int(
            duck.execute(
                f"SELECT count(*) FROM {quote_ident(CATALOG_SCHEMA)}.errors WHERE run_id=?",
                [run_id],
            ).fetchone()[0]
        )
        imported_database_count = int(
            duck.execute(
                f"SELECT count(*) FROM {quote_ident(CATALOG_SCHEMA)}.database_files "
                "WHERE present=TRUE AND import_status IN ('ok', 'partial')"
            ).fetchone()[0]
        )
        imported_account_count = int(
            duck.execute(
                f"SELECT count(*) FROM {quote_ident(CATALOG_SCHEMA)}.accounts"
            ).fetchone()[0]
        )
        imported_object_count, imported_rows = duck.execute(
            f"SELECT count(*), coalesce(sum(imported_rows), 0) "
            f"FROM {quote_ident(CATALOG_SCHEMA)}.objects WHERE import_status='ok'"
        ).fetchone()
        imported_object_count = int(imported_object_count)
        imported_rows = int(imported_rows)
        partial = error_count > 0 or manifest.get("status") != "complete"
        if partial and not allow_partial:
            raise ExportError(f"export encountered {error_count} error(s)")
        duck.execute(
            f"""
            UPDATE {quote_ident(CATALOG_SCHEMA)}.runs
            SET completed_at=?, completed=TRUE, partial=?, imported_accounts=?,
                imported_databases=?, imported_objects=?, imported_rows=?, message_rows=?,
                contact_rows=?, contact_tag_definition_rows=?, contact_tag_rows=?,
                error_count=?, added_databases=?, changed_databases=?,
                removed_databases=?, reused_databases=?
            WHERE run_id=?
            """,
            [
                datetime.now(timezone.utc),
                partial,
                imported_account_count,
                imported_database_count,
                imported_object_count,
                imported_rows,
                message_rows,
                contact_rows,
                contact_tag_definition_rows,
                contact_tag_rows,
                error_count,
                delta_stats["added"],
                delta_stats["changed"],
                delta_stats["removed"],
                delta_stats["reused"],
                run_id,
            ],
        )
        duck.execute("CHECKPOINT")
        duck.close()
        duck = None
        partial_wal = Path(str(partial_path) + ".wal")
        if partial_wal.exists():
            raise ExportError(f"DuckDB WAL remained after checkpoint and close: {partial_wal}")
        if base_path is not None:
            assert baseline_state is not None and base_run_id is not None
            assert_baseline_unchanged(base_path, baseline_state, base_run_id)
        os.replace(partial_path, output_path)
        return {
            "mode": mode,
            "accounts": imported_account_count,
            "databases": imported_database_count,
            "objects": imported_object_count,
            "raw_rows": imported_rows,
            "message_rows": message_rows,
            "contact_rows": contact_rows,
            "contact_tag_definition_rows": contact_tag_definition_rows,
            "contact_tag_rows": contact_tag_rows,
            "backup_message_rows": backup_message_rows,
            "errors": error_count,
            "partial": partial,
            "sqlite_extension": sqlite_extension_available,
            "output": str(output_path),
            "added": delta_stats["added"],
            "changed": delta_stats["changed"],
            "removed": delta_stats["removed"],
            "reused": delta_stats["reused"],
        }
    except Exception:
        if duck is not None:
            try:
                duck.close()
            except Exception:
                pass
        remove_partial(partial_path)
        raise
    finally:
        _ACTIVE_RUN_ID = None


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Load a key-free staged WeChat export manifest into DuckDB."
    )
    parser.add_argument("--manifest", type=Path, help="Path to the staging manifest JSON")
    parser.add_argument("--output", type=Path, help="Target DuckDB file")
    parser.add_argument(
        "--base", type=Path, help="Existing WeChat DuckDB to use as a delta baseline"
    )
    parser.add_argument(
        "--write-baseline",
        type=Path,
        help="Write a version 2 delta-staging baseline JSON and exit",
    )
    parser.add_argument(
        "--backup-key-file",
        type=Path,
        help="Ephemeral file containing the separately recovered BackupFiles key",
    )
    parser.add_argument(
        "--config",
        type=Path,
        help="Central chatlog.json used as a fallback for the cached BackupFiles key",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.write_baseline is not None:
            if args.base is None:
                parser.error("--write-baseline requires --base")
            if args.manifest is not None or args.output is not None:
                parser.error("--write-baseline cannot be combined with --manifest or --output")
            payload = write_delta_baseline(args.base, args.write_baseline)
            print(
                f"Wrote delta baseline for run {payload['base_run_id']} to "
                f"{args.write_baseline.resolve()}"
            )
            return 0
        if args.manifest is None or args.output is None:
            parser.error("--manifest and --output are required for an export")
        summary = export(
            args.manifest,
            args.output,
            args.backup_key_file,
            args.base,
            args.config,
        )
    except Exception as exc:
        print(f"export failed: {safe_error(exc)}", file=sys.stderr)
        return 1
    qualifier = "partial " if summary["partial"] else ""
    print(
        f"Created {qualifier}{summary['mode']} WeChat DuckDB export at {summary['output']}\n"
        f"  accounts: {summary['accounts']}\n"
        f"  databases: {summary['databases']}\n"
        f"  SQLite objects: {summary['objects']} ({summary['raw_rows']} rows)\n"
        f"  chatlog.messages: {summary['message_rows']} rows\n"
        f"  chatlog.contacts: {summary['contact_rows']} rows\n"
        f"  chatlog.contact_tag_definitions: "
        f"{summary['contact_tag_definition_rows']} rows\n"
        f"  chatlog.contact_tags: {summary['contact_tag_rows']} rows\n"
        f"  phone-backup messages: {summary['backup_message_rows']} rows\n"
        f"  catalogued errors: {summary['errors']}\n"
        f"  databases added/changed/removed/reused: "
        f"{summary['added']}/{summary['changed']}/{summary['removed']}/{summary['reused']}\n"
        f"  DuckDB sqlite extension used: {summary['sqlite_extension']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

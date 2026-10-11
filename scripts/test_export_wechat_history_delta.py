"""Bounded integration checks for the copy-on-write WeChat delta exporter."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
import struct
import subprocess
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import duckdb
from Crypto.Cipher import AES

from export_wechat_history import (
    CONTACT_ADD_SCENES,
    EXPORT_SCHEMA_VERSION,
    AccountSpec,
    DatabaseSpec,
    ImportedObject,
    SourceColumn,
    SourceObject,
    ExportError,
    create_catalog,
    create_contacts_table,
    create_messages_table,
    create_backup_message_tables,
    insert_contacts,
    insert_v4_messages,
    insert_v3_messages,
    parse_specs,
    project_phone_backup_messages,
    contact_add_scene_values,
    export,
    parse_contact_extra_buf,
    phone_backup_auxiliary_sha256,
    read_backup_key,
    validate_export,
    write_delta_baseline,
)


def file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def source_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    size = path.stat().st_size
    digest.update(b"wechat-database-source-v1\x00")
    digest.update(f"4:main:true:{size}:".encode("ascii"))
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    digest.update(b"3:wal:false:0:")
    return digest.hexdigest()


def snapshot_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    size = path.stat().st_size
    digest.update(b"wechat-sqlite-snapshot-v1\x00")
    digest.update(f"8:snapshot:true:{size}:".encode("ascii"))
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def rfc3339_ns(timestamp_ns: int) -> str:
    seconds, nanoseconds = divmod(timestamp_ns, 1_000_000_000)
    value = datetime.fromtimestamp(seconds, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
    if nanoseconds:
        value += f".{nanoseconds:09d}".rstrip("0")
    return value + "Z"


def create_message_database(path: Path) -> None:
    connection = sqlite3.connect(path)
    try:
        connection.execute(
            """
            CREATE TABLE MSG (
                localId INTEGER PRIMARY KEY,
                msgSvrId INTEGER,
                Type INTEGER,
                isSender INTEGER,
                createTime INTEGER,
                strTalker TEXT,
                strContent TEXT
            )
            """
        )
        connection.executemany(
            "INSERT INTO MSG VALUES (?, ?, ?, ?, ?, ?, ?)",
            [
                (1, 101, 1, 0, 1700000001, "alice", "one"),
                (2, 102, 1, 1, 1700000002, "alice", "two"),
                (3, 103, 1, 0, 1700000003, "room@chatroom", "three"),
            ],
        )
        connection.commit()
    finally:
        connection.close()


def mutate_message_database(path: Path) -> None:
    connection = sqlite3.connect(path)
    try:
        connection.execute("ALTER TABLE MSG ADD COLUMN note TEXT")
        connection.execute(
            "UPDATE MSG SET strContent='ONE', note='edited' WHERE localId=1"
        )
        connection.execute("DELETE FROM MSG WHERE localId=2")
        connection.execute(
            "INSERT INTO MSG VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (4, 104, 1, 1, 1700000004, "bob", "four", "added"),
        )
        connection.commit()
    finally:
        connection.close()


def create_v4_message_database(path: Path, content: bytes = b"before") -> None:
    connection = sqlite3.connect(path)
    try:
        connection.execute(
            """
            CREATE TABLE Msg_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa (
                local_id INTEGER PRIMARY KEY,
                server_id INTEGER,
                local_type INTEGER,
                sort_seq INTEGER,
                real_sender_id INTEGER,
                create_time INTEGER,
                message_content BLOB,
                packed_info_data BLOB,
                status INTEGER
            )
            """
        )
        connection.execute(
            "INSERT INTO Msg_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa VALUES "
            "(1, 9001, 1, 10, 0, 1700000100, ?, ?, 2)",
            (content, b"packed"),
        )
        connection.commit()
    finally:
        connection.close()


def extra_buf_int32(field_id: str, value: int) -> bytes:
    return bytes.fromhex(field_id) + b"\x04" + struct.pack("<i", value)


def extra_buf_utf16(field_id: str, value: str) -> bytes:
    payload = (value + "\x00").encode("utf-16-le")
    return bytes.fromhex(field_id) + b"\x18" + struct.pack("<I", len(payload)) + payload


def contact_extra_buf(
    signature: str,
    add_scene: int,
    country: str,
    province: str,
    city: str,
) -> bytes:
    return b"".join(
        (
            extra_buf_int32("ddf32683", 2),
            extra_buf_utf16("46cf10c4", signature),
            extra_buf_utf16("a4d9024a", country),
            extra_buf_utf16("e2eaa8d1", province),
            extra_buf_utf16("1d025bbf", city),
            extra_buf_int32("4d6c4570", add_scene),
            bytes.fromhex("16791c90") + b"\x17\x02\x00\x00\x00\x0a\x00",
            bytes.fromhex("c9477ac6") + b"\x02\x01",
            bytes.fromhex("57a7b5a8") + b"\x05" + bytes(range(8)),
        )
    )


def malformed_contact_extra_buf() -> bytes:
    return bytes.fromhex("46cf10c4") + b"\x18\x08\x00\x00\x00x"


def create_windows_v3_contact_database(path: Path, description: str = "long note") -> None:
    connection = sqlite3.connect(path)
    try:
        connection.execute(
            """
            CREATE TABLE Contact (
                UserName TEXT,
                Alias TEXT,
                Remark TEXT,
                NickName TEXT,
                Reserved1 INTEGER,
                Reserved6 TEXT,
                LabelIDList TEXT,
                ExtraBuf BLOB
            )
            """
        )
        connection.executemany(
            "INSERT INTO Contact VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (
                    "alice",
                    "alice-id",
                    "Alice short",
                    "Alice nick",
                    1,
                    description,
                    " 3, ,5,3,999,bad",
                    contact_extra_buf(
                        "碰巧遇到你", 30, "HK", "Kowloon", "Yau Tsim Mong"
                    ),
                ),
                (
                    "duplicate",
                    "first",
                    "First",
                    "Duplicate one",
                    1,
                    "one",
                    "5",
                    malformed_contact_extra_buf(),
                ),
                (
                    "duplicate",
                    "second",
                    "Second",
                    "Duplicate two",
                    0,
                    "two",
                    "",
                    None,
                ),
                (
                    None,
                    "no-user",
                    "No user",
                    "Anonymous",
                    0,
                    "anonymous note",
                    None,
                    contact_extra_buf("", -1, "", "", ""),
                ),
            ],
        )
        connection.execute("CREATE TABLE ContactLabel (LabelId TEXT, LabelName TEXT)")
        connection.executemany(
            "INSERT INTO ContactLabel VALUES (?, ?)",
            [
                ("3", "Shanghai"),
                ("5", "Family"),
                ("7", "Unused"),
                ("5", "Family duplicate"),
                (None, "No ID"),
                ("bad", "Malformed ID"),
            ],
        )
        connection.commit()
    finally:
        connection.close()


def create_v4_contact_database(path: Path) -> None:
    connection = sqlite3.connect(path)
    try:
        connection.execute(
            """
            CREATE TABLE contact (
                username TEXT,
                local_type INTEGER,
                alias TEXT,
                remark TEXT,
                nick_name TEXT,
                description TEXT,
                flag INTEGER,
                verify_flag INTEGER,
                delete_flag INTEGER
            )
            """
        )
        connection.executemany(
            "INSERT INTO contact VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                ("v4-friend", 1, "v4-id", "V4 short", "V4 nick", "V4 long", 3, 0, 0),
                ("v4-member", 3, "", "", "Member", "Member note", 0, 0, 0),
            ],
        )
        connection.commit()
    finally:
        connection.close()


def create_darwin_v3_contact_database(path: Path) -> None:
    connection = sqlite3.connect(path)
    try:
        connection.execute(
            """
            CREATE TABLE WCContact (
                m_nsUsrName TEXT,
                nickname TEXT,
                m_nsRemark TEXT,
                m_nsAliasName TEXT
            )
            """
        )
        connection.execute(
            "INSERT INTO WCContact VALUES (?, ?, ?, ?)",
            ("darwin-user", "Darwin nick", "Darwin short", "darwin-id"),
        )
        connection.commit()
    finally:
        connection.close()


def protobuf_varint(value: int) -> bytes:
    result = bytearray()
    while value >= 0x80:
        result.append((value & 0x7F) | 0x80)
        value >>= 7
    result.append(value)
    return bytes(result)


def protobuf_bytes(field_number: int, value: bytes) -> bytes:
    return (
        protobuf_varint((field_number << 3) | 2)
        + protobuf_varint(len(value))
        + value
    )


def backup_message_record(content: str, server_id: int) -> bytes:
    def embedded(value: str) -> bytes:
        return protobuf_bytes(1, value.encode("utf-8"))

    return b"".join(
        (
            protobuf_varint(1 << 3),
            protobuf_varint(1),
            protobuf_bytes(3, embedded("sender")),
            protobuf_bytes(4, embedded("recipient")),
            protobuf_bytes(5, embedded(content)),
            protobuf_varint(7 << 3),
            protobuf_varint(1700000200),
            protobuf_varint(16 << 3),
            protobuf_varint(server_id),
            protobuf_varint(17 << 3),
            protobuf_varint(7),
            protobuf_varint(18 << 3),
            protobuf_varint(8),
        )
    )


def encrypted_backup_segment(content: str, server_id: int, key: bytes) -> bytes:
    record = backup_message_record(content, server_id)
    root = protobuf_bytes(2, record)
    padding = 16 - (len(root) % 16)
    return AES.new(key, AES.MODE_ECB).encrypt(root + bytes((padding,)) * padding)


def manifest_for(
    database: Path,
    manifest_path: Path,
    *,
    status: str = "ok",
    staged_path: Path | None = None,
    source_digest: str | None = None,
    snapshot_digest: str | None = None,
    data_dir: Path | None = None,
    relative_path: str = "Msg/MSG0.db",
    account_version: int = 3,
    platform: str = "windows",
    mode: str = "copied_plaintext",
    auxiliary_digest: str = "",
) -> Path:
    source_fingerprint = source_sha256(database)
    snapshot_fingerprint = snapshot_sha256(database)
    payload = {
        "format_version": 2,
        "generated_at": datetime.now(timezone.utc).isoformat().replace(
            "+00:00", "Z"
        ),
        "status": "complete",
        "allow_partial": False,
        "accounts": [
            {
                "id": "fixture_account",
                "account": "fixture",
                "platform": platform,
                "version": account_version,
                "full_version": f"{account_version}.fixture",
                "data_dir": str(data_dir if data_dir is not None else database.parent),
                "stage_dir": str(database.parent),
                "running": False,
                "key_source": "fixture",
                "resolved": True,
                "status": "complete",
                "errors": [],
                "files": [
                    {
                        "source_path": str(database),
                        "relative_path": relative_path,
                        "staged_path": (
                            str(staged_path if staged_path is not None else database)
                            if status == "ok"
                            else ""
                        ),
                        "source_size": database.stat().st_size,
                        "source_modified_at": rfc3339_ns(database.stat().st_mtime_ns),
                        "source_sha256": source_digest or source_fingerprint,
                        "snapshot_size": database.stat().st_size,
                        "snapshot_sha256": snapshot_digest or snapshot_fingerprint,
                        "auxiliary_sha256": auxiliary_digest,
                        "mode": mode,
                        "status": status,
                        "error": "",
                    }
                ],
            }
        ],
        "unresolved": [],
        "warnings": [],
    }
    manifest_path.write_text(json.dumps(payload), encoding="utf-8")
    return manifest_path


def message_rows(path: Path) -> list[tuple[object, ...]]:
    connection = duckdb.connect(str(path), read_only=True)
    try:
        return connection.execute(
            "SELECT source_local_id, server_id, talker_id, is_self, raw_content "
            "FROM chatlog.messages ORDER BY source_local_id"
        ).fetchall()
    finally:
        connection.close()


def contact_rows(path: Path) -> list[tuple[object, ...]]:
    connection = duckdb.connect(str(path), read_only=True)
    try:
        return connection.execute(
            "SELECT source_kind, source_relative_path, source_contact_key, source_rowid, "
            "user_name, alias, remark, nickname, description, is_friend, signature, "
            "add_scene, country, province, city, extra_buf_parse_status, "
            "extra_buf_parse_warning, add_scene_enum, add_scene_string "
            "FROM chatlog.contacts ORDER BY source_kind, source_rowid"
        ).fetchall()
    finally:
        connection.close()


def contact_tag_definition_rows(path: Path) -> list[tuple[object, ...]]:
    connection = duckdb.connect(str(path), read_only=True)
    try:
        return connection.execute(
            "SELECT source_label_key, source_rowid, raw_label_id, label_id_text, "
            "label_id, label_name FROM chatlog.contact_tag_definitions "
            "ORDER BY source_rowid"
        ).fetchall()
    finally:
        connection.close()


def contact_tag_rows(path: Path) -> list[tuple[object, ...]]:
    connection = duckdb.connect(str(path), read_only=True)
    try:
        return connection.execute(
            "SELECT c.user_name, t.source_tag_key, t.tag_ordinal, t.raw_label_id, "
            "t.label_id_text, t.label_id, t.label_definition_key, t.label_name, "
            "t.definition_match_count, t.resolved "
            "FROM chatlog.contact_tags t "
            "JOIN chatlog.contacts c USING (source_contact_key) "
            "ORDER BY t.source_contact_rowid, t.tag_ordinal"
        ).fetchall()
    finally:
        connection.close()


def raw_shape_and_rows(path: Path) -> tuple[list[tuple[object, ...]], list[tuple[object, ...]]]:
    connection = duckdb.connect(str(path), read_only=True)
    try:
        raw_schema, raw_table = connection.execute(
            "SELECT raw_schema, raw_table FROM export_catalog.objects "
            "WHERE source_name='MSG' AND import_status='ok'"
        ).fetchone()
        qualified = f'"{raw_schema}"."{raw_table}"'
        shape = connection.execute(f"DESCRIBE {qualified}").fetchall()
        rows = connection.execute(f"SELECT * FROM {qualified} ORDER BY localId").fetchall()
        return shape, rows
    finally:
        connection.close()


def downgrade_to_legacy(path: Path) -> None:
    connection = duckdb.connect(str(path))
    try:
        connection.execute("DROP TABLE export_catalog.meta")
        for column in (
            "export_mode",
            "base_run_id",
            "added_databases",
            "changed_databases",
            "removed_databases",
            "reused_databases",
        ):
            connection.execute(f'ALTER TABLE export_catalog.runs DROP COLUMN "{column}"')
        for column in (
            "source_sha256",
            "snapshot_size",
            "snapshot_sha256",
            "auxiliary_sha256",
            "first_seen_run_id",
            "last_seen_run_id",
            "last_changed_run_id",
            "present",
        ):
            connection.execute(
                f'ALTER TABLE export_catalog.database_files DROP COLUMN "{column}"'
            )
        connection.execute("ALTER TABLE export_catalog.errors DROP COLUMN run_id")
        connection.execute("ALTER TABLE export_catalog.warnings DROP COLUMN run_id")
        connection.execute(
            "ALTER TABLE export_catalog.unresolved_accounts DROP COLUMN run_id"
        )
        connection.execute("CHECKPOINT")
    finally:
        connection.close()


class BackupKeyResolutionTest(unittest.TestCase):
    def test_explicit_key_wins_without_reading_malformed_cache(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wechat-backup-key-resolution-") as raw_root:
            root = Path(raw_root)
            explicit_key = bytes.fromhex("cd" * 32)
            explicit_path = root / "explicit-key.txt"
            explicit_path.write_text("  " + explicit_key.hex().upper() + "\n", encoding="ascii")
            config_path = root / "chatlog.json"
            config_path.write_text('{"backup_key":', encoding="utf-8")

            self.assertEqual(
                read_backup_key(explicit_path, config_path),
                explicit_key,
            )

    def test_cached_key_is_used_when_explicit_key_is_absent(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wechat-backup-key-cache-") as raw_root:
            root = Path(raw_root)
            cached_key = bytes.fromhex("ab" * 32)
            config_path = root / "chatlog.json"
            config_path.write_text(
                json.dumps(
                    {
                        "sentinel": {"keep": True},
                        "backup_key": cached_key.hex().upper(),
                        "history": [],
                    }
                ),
                encoding="utf-8",
            )

            self.assertEqual(read_backup_key(None, config_path), cached_key)

    def test_absent_or_empty_cached_key_permits_live_recovery(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wechat-backup-key-empty-") as raw_root:
            root = Path(raw_root)
            config_path = root / "chatlog.json"
            for document in ({"history": []}, {"backup_key": "", "history": []}):
                with self.subTest(document=document):
                    config_path.write_text(json.dumps(document), encoding="utf-8")
                    self.assertIsNone(read_backup_key(None, config_path))

    def test_malformed_or_invalid_cache_errors_do_not_disclose_values(self) -> None:
        secret_marker = "LEAK-ME-NEVER-" + "7" * 64
        cases = {
            "malformed json": '{"backup_key":"' + secret_marker + '"',
            "wrong field type": json.dumps({"backup_key": {"secret": secret_marker}}),
            "invalid hexadecimal": json.dumps({"backup_key": secret_marker}),
            "wrong length": json.dumps({"backup_key": "ab"}),
        }
        with tempfile.TemporaryDirectory(prefix="wechat-backup-key-invalid-") as raw_root:
            config_path = Path(raw_root) / "chatlog.json"
            for name, content in cases.items():
                with self.subTest(name=name):
                    config_path.write_text(content, encoding="utf-8")
                    with self.assertRaises(ExportError) as raised:
                        read_backup_key(None, config_path)
                    diagnostic = str(raised.exception)
                    self.assertNotIn(secret_marker, diagnostic)
                    self.assertTrue(
                        "backup_key" in diagnostic
                        or "backup key" in diagnostic
                        or "chatlog.json" in diagnostic,
                        diagnostic,
                    )

    def test_invalid_explicit_key_does_not_fall_back_or_leak(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wechat-backup-key-override-") as raw_root:
            root = Path(raw_root)
            invalid_secret = "NOT-HEX-SECRET-" + "x" * 64
            explicit_path = root / "explicit-key.txt"
            explicit_path.write_text(invalid_secret, encoding="ascii")
            config_path = root / "chatlog.json"
            config_path.write_text(
                json.dumps({"backup_key": "ab" * 32}), encoding="utf-8"
            )

            with self.assertRaises(ExportError) as raised:
                read_backup_key(explicit_path, config_path)
            self.assertNotIn(invalid_secret, str(raised.exception))


class RawQualificationTest(unittest.TestCase):
    """In-memory source evidence only; no live SQLite, key, or network reads."""

    @staticmethod
    def source(duck, relative, kind, columns, rows, account_name="self-user"):
        account = AccountSpec(
            "self-user_pathhash", account_name, "windows", 4, "fixture", "", "",
            False, "fixture", True, "complete", (), "raw_fixture",
        )
        database = DatabaseSpec(
            "fixture-db", account, "", relative, None, None, "", "", None, "",
            "", "copied_plaintext", "ok", "",
        )
        source = SourceObject("table", kind, None, tuple(
            SourceColumn(index, name, declaration, False, None, 0)
            for index, (name, declaration) in enumerate(columns)
        ))
        duck.execute("CREATE SCHEMA IF NOT EXISTS raw_fixture")
        duck.execute("DROP TABLE IF EXISTS raw_fixture.source")
        duck.execute("CREATE TABLE raw_fixture.source (" + ",".join(
            '"' + name + '" ' + declaration for name, declaration in columns
        ) + ")")
        duck.executemany("INSERT INTO raw_fixture.source VALUES (" + ",".join("?" for _ in columns) + ")", rows)
        return ImportedObject("fixture-object", database, source, "source", len(rows), len(rows), "fixture")

    def test_friend_eligibility_requires_positive_source_flags(self):
        with duckdb.connect(":memory:") as duck:
            create_catalog(duck)
            create_contacts_table(duck)
            imported = self.source(duck, "contact/contact.db", "contact", [
                ("username", "VARCHAR"), ("local_type", "BIGINT"),
                ("flag", "BIGINT"), ("verify_flag", "BIGINT"), ("delete_flag", "BIGINT"),
            ], [
                ("friend-both", 1, 3, 0, 0), ("friend-bit1", 1, 1, 0, 0),
                ("friend-bit2", 1, 2, 0, 0), ("stranger", 1, 0, 0, 0),
                ("missing", 1, None, 0, 0), ("invalid", 1, -1, 0, 0),
                ("group-member", 3, 3, 0, 0), ("room@chatroom", 2, 3, 0, 0),
                ("gh_official", 1, 3, 0, 0), ("verified-account", 1, 3, 8, 0),
                ("deleted", 1, 3, 0, 1), ("unknown-verify", 1, 3, None, 0),
                ("unknown-delete", 1, 3, 0, None),
            ])
            insert_contacts(duck, imported, "v4_contact")
            self.assertEqual(dict(duck.execute("SELECT user_name,is_friend FROM chatlog.contacts").fetchall()), {
                "friend-both": True, "friend-bit1": True, "friend-bit2": True,
                "stranger": False, "missing": None, "invalid": None,
                "group-member": False, "room@chatroom": False, "gh_official": False,
                "verified-account": False, "deleted": False,
                "unknown-verify": None, "unknown-delete": None,
            })

    def test_unverified_flags_and_darwin_contacts_remain_unknown(self):
        with duckdb.connect(":memory:") as duck:
            create_catalog(duck)
            create_contacts_table(duck)
            imported = self.source(duck, "MicroMsg.db", "Contact", [
                ("UserName", "VARCHAR"), ("Reserved1", "VARCHAR"),
            ], [("friend", "1"), ("member", "0"), ("unverified", "9"),
                ("malformed", "1.0"), ("room@chatroom", "1")])
            insert_contacts(duck, imported, "windows_v3_contact")
            self.assertEqual(dict(duck.execute("SELECT user_name,is_friend FROM chatlog.contacts").fetchall()), {
                "friend": True, "member": False, "unverified": None,
                "malformed": None, "room@chatroom": False,
            })
            duck.execute("DELETE FROM chatlog.contacts")
            imported = self.source(duck, "contact.db", "contact", [
                ("username", "VARCHAR"), ("local_type", "BIGINT"), ("remark", "VARCHAR"),
            ], [("unverified-v4", 1, "existing remark"), ("enterprise", 5, "")])
            insert_contacts(duck, imported, "v4_contact")
            self.assertEqual(duck.execute("SELECT is_friend FROM chatlog.contacts").fetchall(), [(None,), (None,)])
            duck.execute("DELETE FROM chatlog.contacts")
            imported = self.source(duck, "wccontact_new2.db", "WCContact", [
                ("m_nsUsrName", "VARCHAR"), ("nickname", "VARCHAR"),
            ], [("unverified-darwin", "synthetic")])
            insert_contacts(duck, imported, "darwin_v3_contact")
            self.assertEqual(duck.execute("SELECT is_friend FROM chatlog.contacts").fetchall(), [(None,)])

    def test_live_and_phone_direction_use_account_name_and_peer_evidence(self):
        with duckdb.connect(":memory:") as duck:
            create_catalog(duck)
            create_messages_table(duck)
            peer_hash = hashlib.md5(b"peer", usedforsecurity=False).hexdigest()
            imported = self.source(duck, "message/message_0.db", "Msg_" + peer_hash, [
                ("local_id", "BIGINT"), ("server_id", "BIGINT"), ("local_type", "BIGINT"),
                ("sort_seq", "BIGINT"), ("real_sender_id", "BIGINT"), ("create_time", "BIGINT"),
                ("message_content", "BLOB"), ("packed_info_data", "BLOB"), ("status", "BIGINT"),
            ], [(index, index, 1, index, index, 1700000000, b"synthetic", b"", status)
                for index, status in enumerate([4, 2, 2, 2, 2], start=1)])
            duck.execute("CREATE TABLE chatlog.v4_talker_map(account_id VARCHAR,talker_hash VARCHAR,user_name VARCHAR)")
            duck.execute("INSERT INTO chatlog.v4_talker_map VALUES (?,?,?)", [imported.database.account.account_id, peer_hash, "peer"])
            duck.execute("CREATE TABLE chatlog.v4_sender_map(account_id VARCHAR,database_id VARCHAR,source_rowid BIGINT,user_name VARCHAR)")
            senders = ["self-user", "peer", "unknown-user", None, "self-user_pathhash"]
            duck.executemany("INSERT INTO chatlog.v4_sender_map VALUES (?,?,?,?)", [
                (imported.database.account.account_id, imported.database.database_id, index, sender)
                for index, sender in enumerate(senders, start=1)
            ])
            insert_v4_messages(duck, imported)
            self.assertEqual(duck.execute("SELECT is_self FROM chatlog.messages ORDER BY source_local_id").fetchall(),
                [(True,), (False,), (None,), (None,), (None,)])
            duck.execute("DELETE FROM chatlog.messages")
            create_backup_message_tables(duck)
            duck.execute("INSERT INTO export_catalog.accounts(account_id,account_name,resolved,raw_schema) VALUES (?,?,true,'raw_fixture')", [imported.database.account.account_id, "self-user"])
            duck.execute("INSERT INTO export_catalog.database_files(database_id,account_id,import_status,imported_objects,source_rows,imported_rows,present) VALUES (?,?,'ok',0,0,0,true)", [imported.database.database_id, imported.database.account.account_id])
            duck.executemany("INSERT INTO chatlog.backup_message_records(source_message_key,account_id,database_id,segment_key,message_ordinal,record_offset,record_length,talker_id,sender_id,raw_record) VALUES (?,?,?,'fixture',?,0,0,'peer',?,?)", [
                (str(index), imported.database.account.account_id, imported.database.database_id, index, sender, b"synthetic")
                for index, sender in enumerate(senders, start=1)
            ])
            project_phone_backup_messages(duck, [imported.database.database_id])
            self.assertEqual(duck.execute("SELECT is_self FROM chatlog.messages ORDER BY source_message_key").fetchall(),
                [(True,), (False,), (None,), (None,), (None,)])

    def test_catalog_account_id_is_never_a_fallback_sender_username(self):
        accounts, _ = parse_specs({"accounts": [{"id": "self-user_pathhash", "files": []}]}, Path("synthetic-manifest.json"))
        self.assertEqual(accounts[0].account_id, "self-user_pathhash")
        self.assertEqual(accounts[0].account_name, "")

    def test_v3_direction_only_accepts_documented_binary_sender_flag(self):
        with duckdb.connect(":memory:") as duck:
            create_catalog(duck)
            create_messages_table(duck)
            imported = self.source(duck, "Msg/MSG0.db", "MSG", [
                ("localId", "BIGINT"), ("msgSvrId", "BIGINT"), ("Type", "BIGINT"),
                ("isSender", "VARCHAR"), ("createTime", "BIGINT"),
                ("strTalker", "VARCHAR"), ("strContent", "VARCHAR"),
            ], [(index, index, 1, flag, 1700000000, "peer", "synthetic")
                for index, flag in enumerate(["0", "1", "9", "1.0", None], start=1)])
            insert_v3_messages(duck, imported, "v3_msg")
            self.assertEqual(duck.execute("SELECT is_self FROM chatlog.messages ORDER BY source_local_id").fetchall(),
                [(False,), (True,), (None,), (None,), (None,)])

    def test_delta_corrects_direction_without_reimporting_unchanged_raw_sources(self):
        with tempfile.TemporaryDirectory(prefix="wechat-direction-upgrade-") as raw_root:
            root = Path(raw_root)
            database, baseline, updated = root / "message_0.db", root / "base.duckdb", root / "delta.duckdb"
            create_v4_message_database(database)
            connection = sqlite3.connect(database)
            try:
                connection.execute("CREATE TABLE Name2Id(user_name TEXT)")
                connection.execute("INSERT INTO Name2Id(rowid,user_name) VALUES (0,'fixture')")
                connection.commit()
            finally:
                connection.close()
            with patch("export_wechat_history.try_load_sqlite_extension", return_value=(False, None)):
                export(manifest_for(database, root / "full.json", relative_path="message/message_0.db", account_version=4), baseline)
                with duckdb.connect(str(baseline)) as duck:
                    duck.execute("UPDATE chatlog.messages SET is_self=false")
                    duck.execute("UPDATE export_catalog.meta SET schema_version=6")
                    duck.execute("CHECKPOINT")
                summary = export(manifest_for(database, root / "delta.json", status="unchanged", relative_path="message/message_0.db", account_version=4), updated, base_path=baseline)
            self.assertEqual(summary["reused"], 1)
            self.assertEqual(summary["changed"], 0)
            with duckdb.connect(str(updated), read_only=True) as duck:
                self.assertEqual(duck.execute("SELECT is_self FROM chatlog.messages").fetchall(), [(True,)])
            with duckdb.connect(str(baseline), read_only=True) as duck:
                self.assertEqual(duck.execute("SELECT is_self FROM chatlog.messages").fetchall(), [(False,)])

    def test_changed_v4_partition_retains_sender_ids_when_unchanged_staging_is_gone(self):
        with tempfile.TemporaryDirectory(prefix="wechat-retained-sender-") as raw_root:
            root = Path(raw_root)
            databases = [root / "message_0.db", root / "message_1.db"]
            peer_hash = hashlib.md5(b"peer", usedforsecurity=False).hexdigest()
            table = "Msg_" + peer_hash
            for index, database in enumerate(databases):
                create_v4_message_database(database)
                connection = sqlite3.connect(database)
                try:
                    connection.execute("ALTER TABLE Msg_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa RENAME TO " + table)
                    connection.execute("CREATE TABLE Name2Id(user_name TEXT)")
                    connection.executemany("INSERT INTO Name2Id(rowid,user_name) VALUES (?,?)", [(17 + index * 24, "fixture"), (18 + index * 24, "peer")])
                    connection.execute("UPDATE " + table + " SET real_sender_id=?", [17 if index == 0 else 42])
                    connection.commit()
                finally:
                    connection.close()

            def combined_manifest(name, unchanged=False):
                payloads = [json.loads(manifest_for(database, root / f"{name}-{index}.json", status="unchanged" if unchanged and index == 0 else "ok", relative_path=f"message/message_{index}.db", account_version=4, data_dir=root).read_text()) for index, database in enumerate(databases)]
                payloads[0]["accounts"][0]["files"].extend(payloads[1]["accounts"][0]["files"])
                path = root / (name + ".json")
                path.write_text(json.dumps(payloads[0]), encoding="utf8")
                return path

            baseline, updated = root / "base.duckdb", root / "delta.duckdb"
            with patch("export_wechat_history.try_load_sqlite_extension", return_value=(False, None)):
                export(combined_manifest("full"), baseline)
                with duckdb.connect(str(baseline)) as duck:
                    raw_schema, raw_table = duck.execute("SELECT o.raw_schema,o.raw_table FROM export_catalog.objects o JOIN export_catalog.database_files d ON d.database_id=o.database_id WHERE d.relative_path='message/message_0.db' AND lower(o.source_name)='name2id'").fetchone()
                    qualified = '"' + raw_schema + '"."' + raw_table + '"'
                    self.assertEqual(duck.execute("SELECT __chatlog_sqlite_rowid,user_name FROM " + qualified + " ORDER BY __chatlog_sqlite_rowid").fetchall(), [(17, "fixture"), (18, "peer")])
                    duck.execute("ALTER TABLE " + qualified + " DROP COLUMN __chatlog_sqlite_rowid")
                    duck.execute("UPDATE export_catalog.meta SET schema_version=6")
                    duck.execute("CHECKPOINT")
                connection = sqlite3.connect(databases[1])
                try:
                    connection.execute("INSERT INTO " + table + " VALUES (2,9002,1,11,41,1700000100,?, ?,4)", [b"same-second late synthetic", b""])
                    connection.commit()
                finally:
                    connection.close()
                delta_manifest = combined_manifest("delta", unchanged=True)
                databases[0].unlink()
                before = file_digest(baseline)
                summary = export(delta_manifest, updated, base_path=baseline)
                self.assertEqual(file_digest(baseline), before)
                bad_baseline = root / "invalid-map.duckdb"
                shutil.copy2(baseline, bad_baseline)
                with duckdb.connect(str(bad_baseline)) as duck:
                    duck.execute("UPDATE chatlog.v4_sender_map SET source_rowid=0 WHERE database_id IN (SELECT database_id FROM export_catalog.database_files WHERE relative_path='message/message_0.db')")
                    duck.execute("CHECKPOINT")
                invalid_before, failed_output = file_digest(bad_baseline), root / "rejected.duckdb"
                with self.assertRaisesRegex(ExportError, "retained sender map"):
                    export(delta_manifest, failed_output, base_path=bad_baseline)
                self.assertEqual(file_digest(bad_baseline), invalid_before)
                self.assertFalse(failed_output.exists())
            self.assertEqual((summary["reused"], summary["changed"]), (1, 1))
            with duckdb.connect(str(updated), read_only=True) as duck:
                rows = duck.execute("SELECT source_relative_path,source_local_id,sender_id,is_self FROM chatlog.messages ORDER BY source_relative_path,source_local_id").fetchall()
                self.assertEqual(rows, [("message/message_0.db", 1, "fixture", True), ("message/message_1.db", 1, "peer", False), ("message/message_1.db", 2, "fixture", True)])
                self.assertEqual(duck.execute("SELECT count(DISTINCT source_message_key) FROM chatlog.messages").fetchone()[0], 3)

    def test_empty_v4_name2id_keeps_integral_provenance_without_guessing_sender(self):
        with tempfile.TemporaryDirectory(prefix="wechat-empty-sender-") as raw_root:
            root = Path(raw_root)
            database, output = root / "message_0.db", root / "history.duckdb"
            create_v4_message_database(database)
            connection = sqlite3.connect(database)
            try:
                connection.execute("CREATE TABLE Name2Id(user_name TEXT)")
                connection.commit()
            finally:
                connection.close()
            with patch("export_wechat_history.try_load_sqlite_extension", return_value=(False, None)):
                export(manifest_for(database, root / "manifest.json", relative_path="message/message_0.db", account_version=4), output)
            with duckdb.connect(str(output), read_only=True) as duck:
                self.assertEqual(duck.execute("SELECT is_self FROM chatlog.messages").fetchall(), [(None,)])


class DeltaExportIntegrationTest(unittest.TestCase):
    def test_contact_add_scene_enum_and_string_mapping(self) -> None:
        expected = {
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
        self.assertEqual(CONTACT_ADD_SCENES, expected)
        for code, values in expected.items():
            with self.subTest(code=code):
                self.assertEqual(contact_add_scene_values(code), values)
        self.assertEqual(
            contact_add_scene_values(-7),
            ("FRIENDSHIP_SCENE_TYPE_UNKNOWN_-7", "Unknown (-7)"),
        )
        self.assertEqual(
            contact_add_scene_values(2_147_483_647),
            (
                "FRIENDSHIP_SCENE_TYPE_UNKNOWN_2147483647",
                "Unknown (2147483647)",
            ),
        )
        self.assertEqual(contact_add_scene_values(None), (None, None))

    def test_contact_extra_buf_duplicate_target_is_malformed(self) -> None:
        profile = parse_contact_extra_buf(
            contact_extra_buf("first", 30, "HK", "Kowloon", "Mong Kok")
            + extra_buf_utf16("46cf10c4", "second")
        )
        self.assertEqual(profile.parse_status, "malformed")
        self.assertIn("duplicate target field 46cf10c4", profile.parse_warning or "")
        self.assertEqual(
            (
                profile.signature,
                profile.add_scene,
                profile.add_scene_enum,
                profile.add_scene_string,
                profile.country,
                profile.province,
                profile.city,
            ),
            (None, None, None, None, None, None, None),
        )

    def test_validation_rejects_inconsistent_add_scene_strings(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="wechat-contact-add-scene-validation-test-"
        ) as raw_root:
            root = Path(raw_root)
            database = root / "MicroMsg.db"
            create_windows_v3_contact_database(database)
            output = root / "history.duckdb"
            export(
                manifest_for(
                    database,
                    root / "manifest.json",
                    data_dir=root,
                    relative_path="Msg/MicroMsg.db",
                ),
                output,
            )
            connection = duckdb.connect(str(output))
            try:
                connection.execute(
                    "UPDATE chatlog.contacts SET add_scene_string='wrong' "
                    "WHERE user_name='alice'"
                )
                with self.assertRaisesRegex(
                    ExportError, "inconsistent contact add-scene enum/string"
                ):
                    validate_export(connection)
            finally:
                connection.close()

    def test_canonical_contacts_preserve_short_and_long_remarks(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wechat-contact-full-test-") as raw_root:
            root = Path(raw_root)
            cases = (
                (
                    "windows-v3",
                    "Msg/MicroMsg.db",
                    3,
                    "windows",
                    create_windows_v3_contact_database,
                    4,
                ),
                (
                    "v4",
                    "db_storage/contact/contact.db",
                    4,
                    "windows",
                    create_v4_contact_database,
                    2,
                ),
                (
                    "darwin-v3",
                    "wccontact_new2.db",
                    3,
                    "darwin",
                    create_darwin_v3_contact_database,
                    1,
                ),
            )
            for name, relative_path, version, platform, create_database, expected_count in cases:
                with self.subTest(name=name):
                    case_root = root / name
                    database = case_root / Path(relative_path).name
                    database.parent.mkdir(parents=True)
                    create_database(database)
                    output = case_root / "history.duckdb"
                    summary = export(
                        manifest_for(
                            database,
                            case_root / "manifest.json",
                            data_dir=case_root,
                            relative_path=relative_path,
                            account_version=version,
                            platform=platform,
                        ),
                        output,
                    )
                    self.assertEqual(summary["contact_rows"], expected_count)
                    self.assertEqual(summary["errors"], 0)
                    expected_definition_count = 6 if name == "windows-v3" else 0
                    expected_tag_count = 6 if name == "windows-v3" else 0
                    self.assertEqual(
                        summary["contact_tag_definition_rows"],
                        expected_definition_count,
                    )
                    self.assertEqual(summary["contact_tag_rows"], expected_tag_count)
                    rows = contact_rows(output)
                    self.assertEqual(len(rows), expected_count)
                    self.assertEqual(len({row[2] for row in rows}), expected_count)
                    self.assertEqual(len({row[3] for row in rows}), expected_count)

                    connection = duckdb.connect(str(output), read_only=True)
                    try:
                        self.assertEqual(
                            connection.execute(
                                "SELECT contact_rows, contact_tag_definition_rows, "
                                "contact_tag_rows FROM export_catalog.runs "
                                "WHERE completed ORDER BY completed_at DESC LIMIT 1"
                            ).fetchone(),
                            (
                                expected_count,
                                expected_definition_count,
                                expected_tag_count,
                            ),
                        )
                    finally:
                        connection.close()

                    if name == "windows-v3":
                        alice = next(row for row in rows if row[4] == "alice")
                        self.assertEqual(alice[0], "windows_v3_contact")
                        self.assertEqual(alice[1], "Msg/MicroMsg.db")
                        self.assertEqual(alice[6], "Alice short")
                        self.assertEqual(alice[8], "long note")
                        self.assertIs(alice[9], True)
                        self.assertEqual(
                            alice[10:16],
                            (
                                "碰巧遇到你",
                                30,
                                "HK",
                                "Kowloon",
                                "Yau Tsim Mong",
                                "ok",
                            ),
                        )
                        self.assertIsNone(alice[16])
                        self.assertEqual(
                            alice[17:],
                            (
                                "FRIENDSHIP_SCENE_TYPE_QRCODE",
                                "Scan QR Code",
                            ),
                        )
                        duplicate_rows = [row for row in rows if row[4] == "duplicate"]
                        self.assertEqual(len(duplicate_rows), 2)
                        self.assertEqual({row[8] for row in duplicate_rows}, {"one", "two"})
                        malformed = next(row for row in duplicate_rows if row[5] == "first")
                        self.assertEqual(malformed[10:15], (None, None, None, None, None))
                        self.assertEqual(malformed[15], "malformed")
                        self.assertIn("extends past the end", malformed[16])
                        self.assertEqual(malformed[17:], (None, None))
                        absent = next(row for row in duplicate_rows if row[5] == "second")
                        self.assertEqual(absent[10:15], (None, None, None, None, None))
                        self.assertEqual(absent[15:17], ("not_present", None))
                        self.assertEqual(absent[17:], (None, None))
                        anonymous = next(row for row in rows if row[4] is None)
                        self.assertEqual(anonymous[8], "anonymous note")
                        self.assertEqual(
                            anonymous[10:16], ("", -1, "", "", "", "ok")
                        )
                        self.assertIsNone(anonymous[16])
                        self.assertEqual(
                            anonymous[17:],
                            (
                                "FRIENDSHIP_SCENE_TYPE_UNKNOWN_-1",
                                "Unknown (-1)",
                            ),
                        )
                        definitions = contact_tag_definition_rows(output)
                        self.assertEqual(len(definitions), 6)
                        self.assertEqual(
                            [(row[2], row[3], row[4], row[5]) for row in definitions],
                            [
                                ("3", "3", 3, "Shanghai"),
                                ("5", "5", 5, "Family"),
                                ("7", "7", 7, "Unused"),
                                ("5", "5", 5, "Family duplicate"),
                                (None, None, None, "No ID"),
                                ("bad", "bad", None, "Malformed ID"),
                            ],
                        )
                        tags = contact_tag_rows(output)
                        self.assertEqual(len(tags), 6)
                        self.assertEqual(
                            [(row[0], row[2], row[3], row[4], row[5]) for row in tags],
                            [
                                ("alice", 1, " 3", "3", 3),
                                ("alice", 3, "5", "5", 5),
                                ("alice", 4, "3", "3", 3),
                                ("alice", 5, "999", "999", 999),
                                ("alice", 6, "bad", "bad", None),
                                ("duplicate", 1, "5", "5", 5),
                            ],
                        )
                        self.assertEqual(tags[0][7:], ("Shanghai", 1, True))
                        self.assertEqual(tags[2][7:], ("Shanghai", 1, True))
                        for ambiguous in (tags[1], tags[5]):
                            self.assertIsNone(ambiguous[6])
                            self.assertIsNone(ambiguous[7])
                            self.assertEqual(ambiguous[8], 2)
                            self.assertIs(ambiguous[9], False)
                        for unknown in (tags[3], tags[4]):
                            self.assertIsNone(unknown[6])
                            self.assertIsNone(unknown[7])
                            self.assertEqual(unknown[8], 0)
                            self.assertIs(unknown[9], False)
                        connection = duckdb.connect(str(output), read_only=True)
                        try:
                            warnings = connection.execute(
                                "SELECT message FROM export_catalog.warnings "
                                "WHERE scope='contact_extra_buf'"
                            ).fetchall()
                            self.assertEqual(len(warnings), 1)
                            self.assertIn("1 Contact.ExtraBuf row(s)", warnings[0][0])
                            raw_schema, raw_table = connection.execute(
                                "SELECT raw_schema, raw_table "
                                "FROM export_catalog.objects "
                                "WHERE source_name='Contact' AND import_status='ok'"
                            ).fetchone()
                            self.assertEqual(
                                connection.execute(
                                    f'SELECT ExtraBuf FROM "{raw_schema}".'
                                    f'"{raw_table}" WHERE Alias=\'first\''
                                ).fetchone()[0],
                                malformed_contact_extra_buf(),
                            )
                        finally:
                            connection.close()
                    elif name == "v4":
                        friend = next(row for row in rows if row[4] == "v4-friend")
                        member = next(row for row in rows if row[4] == "v4-member")
                        self.assertEqual(friend[0], "v4_contact")
                        self.assertEqual(friend[6], "V4 short")
                        self.assertEqual(friend[8], "V4 long")
                        self.assertIs(friend[9], True)
                        self.assertIs(member[9], False)
                        self.assertEqual(friend[10:16], (None, None, None, None, None, "not_applicable"))
                        self.assertIsNone(friend[16])
                        self.assertEqual(friend[17:], (None, None))
                        self.assertEqual(member[10:16], (None, None, None, None, None, "not_applicable"))
                        self.assertIsNone(member[16])
                        self.assertEqual(member[17:], (None, None))
                        self.assertEqual(contact_tag_definition_rows(output), [])
                        self.assertEqual(contact_tag_rows(output), [])
                    else:
                        self.assertEqual(rows[0][0], "darwin_v3_contact")
                        self.assertEqual(rows[0][6], "Darwin short")
                        self.assertIsNone(rows[0][8])
                        self.assertIsNone(rows[0][9])
                        self.assertEqual(
                            rows[0][10:16],
                            (None, None, None, None, None, "not_applicable"),
                        )
                        self.assertIsNone(rows[0][16])
                        self.assertEqual(rows[0][17:], (None, None))
                        self.assertEqual(contact_tag_definition_rows(output), [])
                        self.assertEqual(contact_tag_rows(output), [])

    def test_windows_v3_contact_tags_survive_missing_definition_table(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="wechat-contact-tags-no-definitions-test-"
        ) as raw_root:
            root = Path(raw_root)
            database = root / "MicroMsg.db"
            create_windows_v3_contact_database(database)
            connection = sqlite3.connect(database)
            try:
                connection.execute("DROP TABLE ContactLabel")
                connection.execute("ALTER TABLE Contact DROP COLUMN ExtraBuf")
                connection.commit()
            finally:
                connection.close()
            output = root / "history.duckdb"
            summary = export(
                manifest_for(
                    database,
                    root / "manifest.json",
                    data_dir=root,
                    relative_path="Msg/MicroMsg.db",
                ),
                output,
            )
            self.assertEqual(summary["contact_tag_definition_rows"], 0)
            self.assertEqual(summary["contact_tag_rows"], 6)
            self.assertEqual(contact_tag_definition_rows(output), [])
            self.assertTrue(
                all(
                    row[10:15] == (None, None, None, None, None)
                    and row[15:17] == ("not_available", None)
                    and row[17:] == (None, None)
                    for row in contact_rows(output)
                )
            )
            tags = contact_tag_rows(output)
            self.assertEqual(len(tags), 6)
            self.assertTrue(
                all(
                    row[6] is None
                    and row[7] is None
                    and row[8] == 0
                    and row[9] is False
                    for row in tags
                )
            )

    def test_delta_upgrades_schema_v4_contact_profiles_in_place(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="wechat-contact-schema-v4-to-v6-test-"
        ) as raw_root:
            root = Path(raw_root)
            database = root / "MicroMsg.db"
            create_windows_v3_contact_database(database)
            initial = root / "initial.duckdb"
            export(
                manifest_for(
                    database,
                    root / "initial.json",
                    data_dir=root,
                    relative_path="Msg/MicroMsg.db",
                ),
                initial,
            )

            schema_v4 = root / "schema-v4.duckdb"
            shutil.copyfile(initial, schema_v4)
            connection = duckdb.connect(str(schema_v4))
            try:
                for column in (
                    "signature",
                    "add_scene",
                    "add_scene_enum",
                    "add_scene_string",
                    "country",
                    "province",
                    "city",
                    "extra_buf_parse_status",
                    "extra_buf_parse_warning",
                ):
                    connection.execute(
                        f'ALTER TABLE chatlog.contacts DROP COLUMN "{column}"'
                    )
                connection.execute(
                    "CREATE VIEW chatlog.contact_name_view AS "
                    "SELECT user_name FROM chatlog.contacts"
                )
                connection.execute("UPDATE export_catalog.meta SET schema_version=4")
                connection.execute("CHECKPOINT")
            finally:
                connection.close()

            baseline = write_delta_baseline(
                schema_v4, root / "schema-v4-baseline.json"
            )
            fingerprint = baseline["accounts"][0]["files"][0]
            upgraded = root / "upgraded.duckdb"
            summary = export(
                manifest_for(
                    database,
                    root / "upgrade.json",
                    status="unchanged",
                    source_digest=fingerprint["source_sha256"],
                    snapshot_digest=fingerprint["snapshot_sha256"],
                    data_dir=root,
                    relative_path="Msg/MicroMsg.db",
                ),
                upgraded,
                base_path=schema_v4,
            )
            self.assertEqual(summary["reused"], 1)
            self.assertEqual(contact_rows(upgraded), contact_rows(initial))
            connection = duckdb.connect(str(upgraded), read_only=True)
            try:
                self.assertEqual(
                    connection.execute(
                        "SELECT schema_version FROM export_catalog.meta"
                    ).fetchone()[0],
                    EXPORT_SCHEMA_VERSION,
                )
                self.assertEqual(
                    connection.execute(
                        "SELECT count(*) FROM chatlog.contact_name_view"
                    ).fetchone()[0],
                    4,
                )
                self.assertEqual(
                    connection.execute(
                        "SELECT is_nullable FROM information_schema.columns "
                        "WHERE table_schema='chatlog' AND table_name='contacts' "
                        "AND column_name='extra_buf_parse_status'"
                    ).fetchone()[0],
                    "NO",
                )
            finally:
                connection.close()

    def test_delta_upgrades_schema_v5_add_scene_strings_in_place(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="wechat-contact-schema-v5-to-v6-test-"
        ) as raw_root:
            root = Path(raw_root)
            database = root / "MicroMsg.db"
            create_windows_v3_contact_database(database)
            current = root / "current.duckdb"
            export(
                manifest_for(
                    database,
                    root / "current.json",
                    data_dir=root,
                    relative_path="Msg/MicroMsg.db",
                ),
                current,
            )

            schema_v5 = root / "schema-v5.duckdb"
            shutil.copyfile(current, schema_v5)
            broken_view_csv = root / "broken-view.csv"
            broken_view_csv.write_text("value\n1\n", encoding="utf-8")
            connection = duckdb.connect(str(schema_v5))
            try:
                connection.execute(
                    'ALTER TABLE chatlog.contacts DROP COLUMN "add_scene_enum"'
                )
                connection.execute(
                    'ALTER TABLE chatlog.contacts DROP COLUMN "add_scene_string"'
                )
                connection.execute(
                    "CREATE VIEW chatlog.contact_scene_view AS "
                    "SELECT * FROM chatlog.contacts"
                )
                connection.execute(
                    "CREATE VIEW chatlog.contact_scene_chain_view AS "
                    "SELECT * FROM chatlog.contact_scene_view"
                )
                connection.execute(
                    "CREATE VIEW chatlog.unrelated_view AS SELECT 42 AS answer"
                )
                csv_sql = str(broken_view_csv).replace("'", "''")
                connection.execute(
                    "CREATE VIEW chatlog.preexisting_broken_view AS "
                    f"SELECT * FROM read_csv_auto('{csv_sql}')"
                )
                connection.execute(
                    "COMMENT ON VIEW chatlog.contact_scene_view "
                    "IS 'direct contact star view'"
                )
                connection.execute(
                    "COMMENT ON COLUMN chatlog.contact_scene_view.user_name "
                    "IS 'contact username'"
                )
                connection.execute(
                    "COMMENT ON VIEW chatlog.contact_scene_chain_view "
                    "IS 'indirect contact star view'"
                )
                connection.execute(
                    "COMMENT ON VIEW chatlog.unrelated_view IS 'unrelated view'"
                )
                connection.execute(
                    "COMMENT ON VIEW chatlog.preexisting_broken_view "
                    "IS 'already broken view'"
                )
                connection.execute("UPDATE export_catalog.meta SET schema_version=5")
                connection.execute("CHECKPOINT")
            finally:
                connection.close()
            broken_view_csv.unlink()

            baseline = write_delta_baseline(
                schema_v5, root / "schema-v5-baseline.json"
            )
            fingerprint = baseline["accounts"][0]["files"][0]
            upgraded = root / "upgraded.duckdb"
            summary = export(
                manifest_for(
                    database,
                    root / "upgrade.json",
                    status="unchanged",
                    source_digest=fingerprint["source_sha256"],
                    snapshot_digest=fingerprint["snapshot_sha256"],
                    data_dir=root,
                    relative_path="Msg/MicroMsg.db",
                ),
                upgraded,
                base_path=schema_v5,
            )
            self.assertEqual(summary["reused"], 1)
            self.assertEqual(contact_rows(upgraded), contact_rows(current))
            connection = duckdb.connect(str(upgraded), read_only=True)
            try:
                self.assertEqual(
                    connection.execute(
                        "SELECT schema_version FROM export_catalog.meta"
                    ).fetchone()[0],
                    EXPORT_SCHEMA_VERSION,
                )
                self.assertEqual(
                    connection.execute(
                        "SELECT count(*) FROM chatlog.contact_scene_view"
                    ).fetchone()[0],
                    4,
                )
                self.assertEqual(
                    connection.execute(
                        "SELECT count(*) FROM chatlog.contact_scene_chain_view"
                    ).fetchone()[0],
                    4,
                )
                for view_name in (
                    "contact_scene_view",
                    "contact_scene_chain_view",
                ):
                    columns = {
                        row[0]
                        for row in connection.execute(
                            f"DESCRIBE chatlog.{view_name}"
                        ).fetchall()
                    }
                    self.assertIn("add_scene_enum", columns)
                    self.assertIn("add_scene_string", columns)
                self.assertEqual(
                    connection.execute(
                        "SELECT view_name, comment FROM duckdb_views() "
                        "WHERE schema_name='chatlog' AND view_name IN "
                        "('contact_scene_view', 'contact_scene_chain_view') "
                        "ORDER BY view_name"
                    ).fetchall(),
                    [
                        ("contact_scene_chain_view", "indirect contact star view"),
                        ("contact_scene_view", "direct contact star view"),
                    ],
                )
                self.assertEqual(
                    connection.execute(
                        "SELECT comment FROM duckdb_columns() "
                        "WHERE schema_name='chatlog' "
                        "AND table_name='contact_scene_view' "
                        "AND column_name='user_name'"
                    ).fetchone()[0],
                    "contact username",
                )
                self.assertEqual(
                    connection.execute(
                        "SELECT answer FROM chatlog.unrelated_view"
                    ).fetchone()[0],
                    42,
                )
                self.assertEqual(
                    connection.execute(
                        "SELECT view_name, comment FROM duckdb_views() "
                        "WHERE schema_name='chatlog' AND view_name IN "
                        "('unrelated_view', 'preexisting_broken_view') "
                        "ORDER BY view_name"
                    ).fetchall(),
                    [
                        ("preexisting_broken_view", "already broken view"),
                        ("unrelated_view", "unrelated view"),
                    ],
                )
                self.assertEqual(
                    connection.execute(
                        "SELECT count(*) FROM duckdb_views() "
                        "WHERE schema_name='chatlog' "
                        "AND view_name='preexisting_broken_view'"
                    ).fetchone()[0],
                    1,
                )
                with self.assertRaises(duckdb.Error):
                    connection.execute(
                        "SELECT * FROM chatlog.preexisting_broken_view LIMIT 0"
                    )
                self.assertEqual(
                    connection.execute(
                        "SELECT add_scene, add_scene_enum, add_scene_string "
                        "FROM chatlog.contacts WHERE user_name='alice'"
                    ).fetchone(),
                    (
                        30,
                        "FRIENDSHIP_SCENE_TYPE_QRCODE",
                        "Scan QR Code",
                    ),
                )
                self.assertEqual(
                    connection.execute(
                        "SELECT add_scene, add_scene_enum, add_scene_string "
                        "FROM chatlog.contacts WHERE user_name IS NULL"
                    ).fetchone(),
                    (
                        -1,
                        "FRIENDSHIP_SCENE_TYPE_UNKNOWN_-1",
                        "Unknown (-1)",
                    ),
                )
                self.assertEqual(
                    connection.execute(
                        "SELECT add_scene_enum, add_scene_string "
                        "FROM chatlog.contacts WHERE alias='second'"
                    ).fetchone(),
                    (None, None),
                )
            finally:
                connection.close()

    def test_contact_delta_backfills_refreshes_and_removes_partitions(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wechat-contact-delta-test-") as raw_root:
            root = Path(raw_root)
            data_dir = root / "wechat-data"
            message_database = data_dir / "Msg" / "MSG0.db"
            contact_database = data_dir / "Msg" / "MicroMsg.db"
            message_database.parent.mkdir(parents=True)
            create_message_database(message_database)
            create_windows_v3_contact_database(contact_database, "before")

            def combined_manifest(
                destination: Path,
                specs: list[tuple[Path, str, str, str | None, str | None]],
            ) -> Path:
                payload: dict[str, object] | None = None
                files: list[dict[str, object]] = []
                for index, (database, relative, status, source_digest, snapshot_digest) in enumerate(
                    specs
                ):
                    fragment_path = root / f"{destination.stem}-{index}.json"
                    manifest_for(
                        database,
                        fragment_path,
                        status=status,
                        source_digest=source_digest,
                        snapshot_digest=snapshot_digest,
                        data_dir=data_dir,
                        relative_path=relative,
                    )
                    fragment = json.loads(fragment_path.read_text(encoding="utf-8"))
                    if payload is None:
                        payload = fragment
                    files.append(fragment["accounts"][0]["files"][0])
                assert payload is not None
                payload["accounts"][0]["files"] = files  # type: ignore[index]
                destination.write_text(json.dumps(payload), encoding="utf-8")
                return destination

            initial = root / "initial.duckdb"
            export(
                combined_manifest(
                    root / "initial.json",
                    [
                        (message_database, "Msg/MSG0.db", "ok", None, None),
                        (contact_database, "Msg/MicroMsg.db", "ok", None, None),
                    ],
                ),
                initial,
            )
            self.assertEqual(len(contact_rows(initial)), 4)
            self.assertEqual(len(contact_tag_definition_rows(initial)), 6)
            self.assertEqual(len(contact_tag_rows(initial)), 6)

            legacy = root / "legacy-schema-3.duckdb"
            shutil.copyfile(initial, legacy)
            connection = duckdb.connect(str(legacy))
            try:
                connection.execute("DROP TABLE chatlog.contacts")
                connection.execute("DROP TABLE chatlog.contact_tags")
                connection.execute("DROP TABLE chatlog.contact_tag_definitions")
                connection.execute("ALTER TABLE export_catalog.runs DROP COLUMN contact_rows")
                connection.execute(
                    "ALTER TABLE export_catalog.runs "
                    "DROP COLUMN contact_tag_definition_rows"
                )
                connection.execute(
                    "ALTER TABLE export_catalog.runs DROP COLUMN contact_tag_rows"
                )
                connection.execute("UPDATE export_catalog.meta SET schema_version=3")
                connection.execute("CHECKPOINT")
            finally:
                connection.close()
            legacy_baseline = write_delta_baseline(
                legacy, root / "legacy-contact-baseline.json"
            )
            legacy_fingerprints = {
                item["relative_path"]: item
                for item in legacy_baseline["accounts"][0]["files"]
            }
            backfilled = root / "backfilled.duckdb"
            backfill_summary = export(
                combined_manifest(
                    root / "backfill.json",
                    [
                        (
                            message_database,
                            "Msg/MSG0.db",
                            "unchanged",
                            legacy_fingerprints["Msg/MSG0.db"]["source_sha256"],
                            legacy_fingerprints["Msg/MSG0.db"]["snapshot_sha256"],
                        ),
                        (
                            contact_database,
                            "Msg/MicroMsg.db",
                            "unchanged",
                            legacy_fingerprints["Msg/MicroMsg.db"]["source_sha256"],
                            legacy_fingerprints["Msg/MicroMsg.db"]["snapshot_sha256"],
                        ),
                    ],
                ),
                backfilled,
                base_path=legacy,
            )
            self.assertEqual(backfill_summary["reused"], 2)
            self.assertEqual(backfill_summary["contact_rows"], 4)
            self.assertEqual(backfill_summary["contact_tag_definition_rows"], 6)
            self.assertEqual(backfill_summary["contact_tag_rows"], 6)
            self.assertEqual(contact_rows(backfilled), contact_rows(initial))
            self.assertEqual(
                contact_tag_definition_rows(backfilled),
                contact_tag_definition_rows(initial),
            )
            self.assertEqual(contact_tag_rows(backfilled), contact_tag_rows(initial))
            connection = duckdb.connect(str(backfilled), read_only=True)
            try:
                self.assertEqual(
                    connection.execute(
                        "SELECT schema_version FROM export_catalog.meta"
                    ).fetchone()[0],
                    EXPORT_SCHEMA_VERSION,
                )
                self.assertEqual(
                    connection.execute(
                        "SELECT contact_tag_definition_rows, contact_tag_rows "
                        "FROM export_catalog.runs WHERE completed "
                        "ORDER BY completed_at DESC LIMIT 1"
                    ).fetchone(),
                    (6, 6),
                )
            finally:
                connection.close()

            connection = sqlite3.connect(contact_database)
            try:
                connection.execute(
                    "UPDATE Contact SET Reserved6='after', LabelIDList='3, 7,999', "
                    "ExtraBuf=? WHERE UserName='alice'",
                    (
                        contact_extra_buf(
                            "Delta signature", 15, "CN", "Guangdong", "Shenzhen"
                        ),
                    ),
                )
                connection.execute(
                    "UPDATE ContactLabel SET LabelName='Shanghai updated' "
                    "WHERE LabelId='3'"
                )
                connection.commit()
            finally:
                connection.close()
            backfilled_baseline = write_delta_baseline(
                backfilled, root / "backfilled-baseline.json"
            )
            backfilled_fingerprints = {
                item["relative_path"]: item
                for item in backfilled_baseline["accounts"][0]["files"]
            }
            refreshed = root / "refreshed.duckdb"
            refresh_summary = export(
                combined_manifest(
                    root / "refresh.json",
                    [
                        (
                            message_database,
                            "Msg/MSG0.db",
                            "unchanged",
                            backfilled_fingerprints["Msg/MSG0.db"]["source_sha256"],
                            backfilled_fingerprints["Msg/MSG0.db"]["snapshot_sha256"],
                        ),
                        (contact_database, "Msg/MicroMsg.db", "ok", None, None),
                    ],
                ),
                refreshed,
                base_path=backfilled,
            )
            self.assertEqual(refresh_summary["changed"], 1)
            self.assertEqual(refresh_summary["reused"], 1)
            refreshed_rows = contact_rows(refreshed)
            self.assertEqual(
                next(row for row in refreshed_rows if row[4] == "alice")[8], "after"
            )
            self.assertEqual(
                next(row for row in refreshed_rows if row[4] == "alice")[10:16],
                (
                    "Delta signature",
                    15,
                    "CN",
                    "Guangdong",
                    "Shenzhen",
                    "ok",
                ),
            )
            self.assertEqual(
                next(row for row in refreshed_rows if row[4] == "alice")[17:],
                (
                    "FRIENDSHIP_SCENE_TYPE_PHONE",
                    "Phone Contacts",
                ),
            )
            self.assertEqual(
                next(
                    row
                    for row in refreshed_rows
                    if row[4] == "duplicate" and row[5] == "first"
                )[15],
                "malformed",
            )
            self.assertEqual(len({row[2] for row in refreshed_rows}), 4)
            self.assertEqual(refresh_summary["contact_tag_definition_rows"], 6)
            self.assertEqual(refresh_summary["contact_tag_rows"], 4)
            refreshed_definitions = contact_tag_definition_rows(refreshed)
            self.assertEqual(
                next(row for row in refreshed_definitions if row[4] == 3)[5],
                "Shanghai updated",
            )
            refreshed_tags = contact_tag_rows(refreshed)
            alice_tags = [row for row in refreshed_tags if row[0] == "alice"]
            self.assertEqual(
                [(row[2], row[4], row[7], row[9]) for row in alice_tags],
                [
                    (1, "3", "Shanghai updated", True),
                    (2, "7", "Unused", True),
                    (3, "999", None, False),
                ],
            )

            refreshed_baseline = write_delta_baseline(
                refreshed, root / "refreshed-baseline.json"
            )
            refreshed_fingerprints = {
                item["relative_path"]: item
                for item in refreshed_baseline["accounts"][0]["files"]
            }
            contact_database.unlink()
            removed = root / "removed.duckdb"
            removal_summary = export(
                combined_manifest(
                    root / "remove.json",
                    [
                        (
                            message_database,
                            "Msg/MSG0.db",
                            "unchanged",
                            refreshed_fingerprints["Msg/MSG0.db"]["source_sha256"],
                            refreshed_fingerprints["Msg/MSG0.db"]["snapshot_sha256"],
                        )
                    ],
                ),
                removed,
                base_path=refreshed,
            )
            self.assertEqual(removal_summary["removed"], 1)
            self.assertEqual(removal_summary["contact_rows"], 0)
            self.assertEqual(removal_summary["contact_tag_definition_rows"], 0)
            self.assertEqual(removal_summary["contact_tag_rows"], 0)
            self.assertEqual(contact_rows(removed), [])
            self.assertEqual(contact_tag_definition_rows(removed), [])
            self.assertEqual(contact_tag_rows(removed), [])

    def test_phone_backup_noop_without_key_and_whole_partition_refresh(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wechat-delta-phone-test-") as raw_root:
            root = Path(raw_root)
            bundle = root / "wechat-data" / "BackupFiles" / "device"
            bundle.mkdir(parents=True)
            index = bundle / "Backup.db"
            archive = bundle / "BAK_1_TEXT"
            key = bytes(range(32))
            key_path = root / "backup-key.txt"
            key_path.write_text(key.hex(), encoding="ascii")

            first_ciphertext = encrypted_backup_segment(
                "first", (1 << 64) - 5, key[:16]
            )
            archive.write_bytes(first_ciphertext)
            connection = sqlite3.connect(index)
            try:
                connection.execute(
                    """
                    CREATE TABLE MsgSegments (
                        talkerId INTEGER,
                        UsrName TEXT,
                        StartTime INTEGER,
                        EndTime INTEGER,
                        OffSet INTEGER,
                        Length INTEGER,
                        FilePath TEXT,
                        SegmentId TEXT
                    )
                    """
                )
                connection.execute(
                    "CREATE TABLE MsgFileSegment "
                    "(FileName TEXT, OffSet INTEGER, Length INTEGER)"
                )
                connection.execute(
                    "INSERT INTO MsgSegments VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (1, "alice", 1, 2, 0, len(first_ciphertext), "BAK_1_TEXT", "segment-1"),
                )
                connection.commit()
            finally:
                connection.close()

            def phone_manifest(
                path: Path,
                *,
                status: str = "ok",
                fingerprints: dict[str, object] | None = None,
            ) -> Path:
                return manifest_for(
                    index,
                    path,
                    status=status,
                    source_digest=(
                        None if fingerprints is None else str(fingerprints["source_sha256"])
                    ),
                    snapshot_digest=(
                        None if fingerprints is None else str(fingerprints["snapshot_sha256"])
                    ),
                    data_dir=root / "wechat-data",
                    relative_path="BackupFiles/device/Backup.db",
                    account_version=3,
                    mode="decrypted_phone_backup_index",
                    auxiliary_digest=(
                        phone_backup_auxiliary_sha256(bundle)
                        if fingerprints is None
                        else str(fingerprints["auxiliary_sha256"])
                    ),
                )

            initial = root / "initial.duckdb"
            export(phone_manifest(root / "phone-initial.json"), initial, key_path)
            initial_baseline = write_delta_baseline(
                initial, root / "phone-baseline.json"
            )
            fingerprints = initial_baseline["accounts"][0]["files"][0]

            project_root = Path(__file__).resolve().parent.parent
            go_executable = project_root / "go" / "bin" / "go.exe"
            if go_executable.is_file():
                config_path = root / "phone-chatlog.json"
                config_path.write_text(
                    json.dumps(
                        {
                            "history": [
                                {
                                    "account": "fixture",
                                    "platform": "windows",
                                    "version": 3,
                                    "full_version": "3.fixture",
                                    "data_dir": str(root / "wechat-data"),
                                    "data_key": "",
                                }
                            ]
                        }
                    ),
                    encoding="utf-8",
                )
                environment = os.environ.copy()
                environment["CGO_ENABLED"] = "0"

                def run_go_stage(
                    name: str, baseline_path: Path
                ) -> tuple[subprocess.CompletedProcess[str], Path]:
                    output_manifest = root / f"{name}.json"
                    result = subprocess.run(
                        [
                            str(go_executable),
                            "run",
                            str(project_root / "scripts" / "export_wechat_history.go"),
                            "--stage",
                            str(root / f"{name}-stage"),
                            "--manifest",
                            str(output_manifest),
                            "--config",
                            str(config_path),
                            "--baseline",
                            str(baseline_path),
                            "--configured-accounts-only",
                        ],
                        cwd=project_root,
                        env=environment,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        timeout=90,
                    )
                    return result, output_manifest

                result, go_manifest = run_go_stage(
                    "phone-go-noop", root / "phone-baseline.json"
                )
                if result.returncode:
                    self.fail(
                        "Go did not accept Python's phone-backup fingerprint as "
                        f"unchanged:\n{result.stdout}\n{result.stderr}"
                    )
                go_payload = json.loads(go_manifest.read_text(encoding="utf-8"))
                self.assertEqual(
                    go_payload["accounts"][0]["files"][0]["status"], "unchanged"
                )

                # A v1 export has no database fingerprint columns. Its phone-backup
                # partition can still be bootstrapped without the ephemeral key when
                # Backup.db metadata, archive inventory, and every stored ciphertext
                # segment still match the source bundle exactly.
                legacy = root / "phone-legacy.duckdb"
                shutil.copyfile(initial, legacy)
                downgrade_to_legacy(legacy)
                legacy_baseline_path = root / "phone-legacy-baseline.json"
                legacy_baseline = write_delta_baseline(
                    legacy, legacy_baseline_path
                )
                legacy_file = legacy_baseline["accounts"][0]["files"][0]
                self.assertTrue(legacy_file["legacy_phone_bootstrap"])
                self.assertRegex(str(legacy_file["source_sha256"]), r"^[0-9a-f]{64}$")
                self.assertRegex(str(legacy_file["snapshot_sha256"]), r"^[0-9a-f]{64}$")
                self.assertRegex(str(legacy_file["auxiliary_sha256"]), r"^[0-9a-f]{64}$")

                result, legacy_manifest = run_go_stage(
                    "phone-go-legacy-noop", legacy_baseline_path
                )
                if result.returncode:
                    self.fail(
                        "Go did not bootstrap an unchanged legacy phone backup "
                        f"without its key:\n{result.stdout}\n{result.stderr}"
                    )
                legacy_payload = json.loads(
                    legacy_manifest.read_text(encoding="utf-8")
                )
                self.assertEqual(
                    legacy_payload["accounts"][0]["files"][0]["status"],
                    "unchanged",
                )
                legacy_staged_file = legacy_payload["accounts"][0]["files"][0]
                for field in (
                    "source_sha256",
                    "snapshot_size",
                    "snapshot_sha256",
                    "auxiliary_sha256",
                    "legacy_phone_bootstrap",
                ):
                    self.assertEqual(legacy_staged_file[field], legacy_file[field])
                legacy_delta = root / "phone-legacy-delta.duckdb"
                legacy_summary = export(
                    legacy_manifest, legacy_delta, base_path=legacy
                )
                self.assertEqual(legacy_summary["reused"], 1)
                self.assertEqual(legacy_summary["backup_message_rows"], 1)

                # Matching only file size and mtime is insufficient. A same-size
                # ciphertext edit with its timestamp restored must invalidate the
                # legacy bootstrap and fall back to requiring the backup key.
                archive_state = archive.stat()
                tampered = bytearray(archive.read_bytes())
                tampered[0] ^= 0x01
                archive.write_bytes(tampered)
                os.utime(
                    archive,
                    ns=(archive_state.st_atime_ns, archive_state.st_mtime_ns),
                )
                tampered_baseline_path = root / "phone-legacy-tampered-baseline.json"
                tampered_baseline = write_delta_baseline(
                    legacy, tampered_baseline_path
                )
                tampered_file = tampered_baseline["accounts"][0]["files"][0]
                self.assertFalse(tampered_file["legacy_phone_bootstrap"])
                self.assertEqual(tampered_file["source_sha256"], "")
                self.assertEqual(tampered_file["snapshot_sha256"], "")
                self.assertEqual(tampered_file["auxiliary_sha256"], "")
                result, _tampered_manifest = run_go_stage(
                    "phone-go-legacy-tampered", tampered_baseline_path
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(
                    "backup-key-file", (result.stdout + result.stderr).lower()
                )
                archive.write_bytes(first_ciphertext)
                os.utime(
                    archive,
                    ns=(archive_state.st_atime_ns, archive_state.st_mtime_ns),
                )

                # Backup.db itself has no retained v1 ciphertext digest. On NTFS,
                # ChangeTime must therefore catch even a same-size edit whose mtime
                # is restored before a new baseline is generated.
                index_legacy = root / "phone-index-change-legacy.duckdb"
                export(
                    phone_manifest(root / "phone-index-change-full.json"),
                    index_legacy,
                    key_path,
                )
                downgrade_to_legacy(index_legacy)
                clean_index_baseline = write_delta_baseline(
                    index_legacy,
                    root / "phone-index-change-clean-baseline.json",
                )
                self.assertTrue(
                    clean_index_baseline["accounts"][0]["files"][0][
                        "legacy_phone_bootstrap"
                    ]
                )
                index_state = index.stat()
                original_index = index.read_bytes()
                tampered_index = bytearray(original_index)
                tampered_index[-1] ^= 0x01
                index.write_bytes(tampered_index)
                os.utime(
                    index,
                    ns=(index_state.st_atime_ns, index_state.st_mtime_ns),
                )
                changed_time_baseline_path = (
                    root / "phone-legacy-changed-time-baseline.json"
                )
                changed_time_baseline = write_delta_baseline(
                    index_legacy, changed_time_baseline_path
                )
                changed_time_file = changed_time_baseline["accounts"][0]["files"][0]
                self.assertFalse(changed_time_file["legacy_phone_bootstrap"])
                self.assertEqual(changed_time_file["source_sha256"], "")
                result, _changed_time_manifest = run_go_stage(
                    "phone-go-legacy-changed-time", changed_time_baseline_path
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(
                    "backup-key-file", (result.stdout + result.stderr).lower()
                )
                index.write_bytes(original_index)
                os.utime(
                    index,
                    ns=(index_state.st_atime_ns, index_state.st_mtime_ns),
                )

            no_op = root / "noop.duckdb"
            no_op_summary = export(
                phone_manifest(
                    root / "phone-noop.json",
                    status="unchanged",
                    fingerprints=fingerprints,
                ),
                no_op,
                base_path=initial,
            )
            self.assertEqual(no_op_summary["reused"], 1)
            self.assertEqual(no_op_summary["backup_message_rows"], 1)

            second_ciphertext = encrypted_backup_segment("second", 202, key[:16])
            with archive.open("ab") as destination:
                destination.write(second_ciphertext)
            connection = sqlite3.connect(index)
            try:
                connection.execute(
                    "INSERT INTO MsgSegments VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        2,
                        "bob",
                        3,
                        4,
                        len(first_ciphertext),
                        len(second_ciphertext),
                        "BAK_1_TEXT",
                        "segment-2",
                    ),
                )
                connection.commit()
            finally:
                connection.close()

            changed_manifest = phone_manifest(root / "phone-changed.json")
            delta = root / "delta.duckdb"
            summary = export(changed_manifest, delta, key_path, base_path=no_op)
            fresh = root / "fresh.duckdb"
            export(phone_manifest(root / "phone-fresh.json"), fresh, key_path)
            self.assertEqual(summary["changed"], 1)

            def phone_rows(path: Path) -> tuple[list[tuple[object, ...]], list[tuple[object, ...]]]:
                connection = duckdb.connect(str(path), read_only=True)
                try:
                    raw = connection.execute(
                        "SELECT message_ordinal, content, server_id, raw_record "
                        "FROM chatlog.backup_message_records "
                        "ORDER BY segment_key, message_ordinal"
                    ).fetchall()
                    canonical = connection.execute(
                        "SELECT source_kind, raw_content, server_id "
                        "FROM chatlog.messages ORDER BY source_message_key"
                    ).fetchall()
                    return raw, canonical
                finally:
                    connection.close()

            self.assertEqual(phone_rows(delta), phone_rows(fresh))
            self.assertEqual(len(phone_rows(delta)[0]), 2)

    def test_mixed_v3_v4_account_reprojects_each_message_once(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wechat-delta-mixed-test-") as raw_root:
            root = Path(raw_root)
            data_dir = root / "wechat-data"
            v3_database = data_dir / "Msg" / "MSG0.db"
            v4_database = data_dir / "Msg" / "message_0.db"
            v3_database.parent.mkdir(parents=True)
            create_message_database(v3_database)
            create_v4_message_database(v4_database)

            def mixed_manifest(path: Path, v3_status: str, v3_hashes: dict[str, object] | None) -> Path:
                v3_fragment = manifest_for(
                    v3_database,
                    root / f"{path.stem}-v3.json",
                    status=v3_status,
                    source_digest=(None if v3_hashes is None else str(v3_hashes["source_sha256"])),
                    snapshot_digest=(None if v3_hashes is None else str(v3_hashes["snapshot_sha256"])),
                    data_dir=data_dir,
                    relative_path="Msg/MSG0.db",
                    account_version=4,
                )
                v4_fragment = manifest_for(
                    v4_database,
                    root / f"{path.stem}-v4.json",
                    data_dir=data_dir,
                    relative_path="Msg/message_0.db",
                    account_version=4,
                )
                payload = json.loads(v3_fragment.read_text(encoding="utf-8"))
                v4_payload = json.loads(v4_fragment.read_text(encoding="utf-8"))
                payload["accounts"][0]["files"].append(
                    v4_payload["accounts"][0]["files"][0]
                )
                path.write_text(json.dumps(payload), encoding="utf-8")
                return path

            baseline = root / "baseline.duckdb"
            export(mixed_manifest(root / "mixed-full.json", "ok", None), baseline)
            baseline_json = write_delta_baseline(
                baseline, root / "mixed-baseline.json"
            )
            v3_hashes = next(
                item
                for item in baseline_json["accounts"][0]["files"]
                if item["relative_path"] == "Msg/MSG0.db"
            )
            connection = sqlite3.connect(v4_database)
            try:
                connection.execute(
                    "UPDATE Msg_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa "
                    "SET message_content=? WHERE local_id=1",
                    (b"after",),
                )
                connection.commit()
            finally:
                connection.close()

            delta = root / "delta.duckdb"
            export(
                mixed_manifest(root / "mixed-delta.json", "unchanged", v3_hashes),
                delta,
                base_path=baseline,
            )
            connection = duckdb.connect(str(delta), read_only=True)
            try:
                self.assertEqual(
                    connection.execute(
                        "SELECT source_kind, count(*) FROM chatlog.messages "
                        "GROUP BY source_kind ORDER BY source_kind"
                    ).fetchall(),
                    [("v3_msg", 3), ("v4_msg", 1)],
                )
                self.assertEqual(
                    connection.execute(
                        "SELECT count(*) - count(DISTINCT source_message_key) "
                        "FROM chatlog.messages"
                    ).fetchone()[0],
                    0,
                )
            finally:
                connection.close()

    def test_future_schema_and_failed_delta_preserve_baseline(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wechat-delta-failure-test-") as raw_root:
            root = Path(raw_root)
            database = root / "MSG0.db"
            create_message_database(database)
            baseline = root / "baseline.duckdb"
            export(manifest_for(database, root / "full.json"), baseline)

            future = root / "future.duckdb"
            shutil.copyfile(baseline, future)
            connection = duckdb.connect(str(future))
            try:
                connection.execute("UPDATE export_catalog.meta SET schema_version=999")
                connection.execute("CHECKPOINT")
            finally:
                connection.close()
            future_before = file_digest(future)
            with self.assertRaisesRegex(Exception, "newer than this exporter"):
                write_delta_baseline(future, root / "future-baseline.json")
            self.assertEqual(file_digest(future), future_before)

            bad_manifest = manifest_for(
                database,
                root / "bad.json",
                snapshot_digest="0" * 64,
            )
            baseline_before = file_digest(baseline)
            failed_output = root / "failed.duckdb"
            with self.assertRaisesRegex(Exception, "snapshot fingerprint mismatch"):
                export(bad_manifest, failed_output, base_path=baseline)
            self.assertEqual(file_digest(baseline), baseline_before)
            self.assertFalse(failed_output.exists())
            self.assertFalse(Path(str(failed_output) + ".wal").exists())

    def test_added_removed_idempotent_and_partial_retention(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wechat-delta-set-test-") as raw_root:
            root = Path(raw_root)
            data_dir = root / "wechat-data"
            first = data_dir / "Msg" / "MSG0.db"
            second = data_dir / "Msg" / "MSG1.db"
            third = data_dir / "Msg" / "MSG2.db"
            first.parent.mkdir(parents=True)
            for database in (first, second, third):
                create_message_database(database)

            def combined_manifest(
                path: Path,
                specifications: list[tuple[Path, str, str, str | None, str | None]],
                *,
                complete: bool = True,
            ) -> Path:
                payload: dict[str, object] | None = None
                files: list[dict[str, object]] = []
                for index, (database, relative, status, source_digest, snapshot_digest) in enumerate(
                    specifications
                ):
                    fragment_path = root / f"fragment-{path.stem}-{index}.json"
                    manifest_for(
                        database,
                        fragment_path,
                        status=status,
                        source_digest=source_digest,
                        snapshot_digest=snapshot_digest,
                        data_dir=data_dir,
                        relative_path=relative,
                    )
                    fragment = json.loads(fragment_path.read_text(encoding="utf-8"))
                    if payload is None:
                        payload = fragment
                    files.append(fragment["accounts"][0]["files"][0])
                assert payload is not None
                payload["accounts"][0]["files"] = files  # type: ignore[index]
                payload["status"] = "complete" if complete else "partial"
                payload["allow_partial"] = not complete
                path.write_text(json.dumps(payload), encoding="utf-8")
                return path

            initial_manifest = combined_manifest(
                root / "initial.json",
                [
                    (first, "Msg/MSG0.db", "ok", None, None),
                    (second, "Msg/MSG1.db", "ok", None, None),
                ],
            )
            initial = root / "initial.duckdb"
            export(initial_manifest, initial)
            baseline = write_delta_baseline(initial, root / "set-baseline.json")
            fingerprints = {
                item["relative_path"]: item
                for item in baseline["accounts"][0]["files"]
            }
            update_manifest = combined_manifest(
                root / "update.json",
                [
                    (
                        first,
                        "Msg/MSG0.db",
                        "unchanged",
                        fingerprints["Msg/MSG0.db"]["source_sha256"],
                        fingerprints["Msg/MSG0.db"]["snapshot_sha256"],
                    ),
                    (third, "Msg/MSG2.db", "ok", None, None),
                ],
            )
            updated = root / "updated.duckdb"
            summary = export(update_manifest, updated, base_path=initial)
            self.assertEqual(
                (summary["added"], summary["changed"], summary["removed"], summary["reused"]),
                (1, 0, 1, 1),
            )
            connection = duckdb.connect(str(updated), read_only=True)
            try:
                self.assertEqual(
                    connection.execute(
                        "SELECT relative_path FROM export_catalog.database_files "
                        "WHERE present ORDER BY relative_path"
                    ).fetchall(),
                    [("Msg/MSG0.db",), ("Msg/MSG2.db",)],
                )
                self.assertEqual(
                    connection.execute("SELECT count(*) FROM chatlog.messages").fetchone()[0],
                    6,
                )
            finally:
                connection.close()

            updated_baseline = write_delta_baseline(
                updated, root / "updated-baseline.json"
            )
            updated_fingerprints = {
                item["relative_path"]: item
                for item in updated_baseline["accounts"][0]["files"]
            }
            idempotent_manifest = combined_manifest(
                root / "idempotent.json",
                [
                    (
                        database,
                        relative,
                        "unchanged",
                        updated_fingerprints[relative]["source_sha256"],
                        updated_fingerprints[relative]["snapshot_sha256"],
                    )
                    for database, relative in (
                        (first, "Msg/MSG0.db"),
                        (third, "Msg/MSG2.db"),
                    )
                ],
            )
            idempotent = root / "idempotent.duckdb"
            repeat_summary = export(
                idempotent_manifest, idempotent, base_path=updated
            )
            self.assertEqual(repeat_summary["reused"], 2)
            self.assertEqual(message_rows(idempotent), message_rows(updated))

            partial_manifest = combined_manifest(
                root / "partial.json",
                [
                    (
                        first,
                        "Msg/MSG0.db",
                        "unchanged",
                        fingerprints["Msg/MSG0.db"]["source_sha256"],
                        fingerprints["Msg/MSG0.db"]["snapshot_sha256"],
                    )
                ],
                complete=False,
            )
            partial = root / "partial.duckdb"
            partial_summary = export(partial_manifest, partial, base_path=initial)
            self.assertTrue(partial_summary["partial"])
            self.assertEqual(partial_summary["removed"], 0)
            connection = duckdb.connect(str(partial), read_only=True)
            try:
                self.assertEqual(
                    connection.execute(
                        "SELECT count(*) FROM export_catalog.database_files WHERE present"
                    ).fetchone()[0],
                    2,
                )
            finally:
                connection.close()

    def test_go_stager_detects_same_size_restored_mtime_change(self) -> None:
        project_root = Path(__file__).resolve().parent.parent
        go_executable = project_root / "go" / "bin" / "go.exe"
        if not go_executable.is_file():
            self.skipTest("bundled Go executable is unavailable")
        with tempfile.TemporaryDirectory(prefix="wechat-go-delta-test-") as raw_root:
            root = Path(raw_root)
            data_dir = root / "wechat-data"
            database = data_dir / "Msg" / "MSG0.db"
            database.parent.mkdir(parents=True)
            create_message_database(database)
            full = root / "full.duckdb"
            export(
                manifest_for(
                    database, root / "full.json", data_dir=data_dir
                ),
                full,
            )
            baseline_path = root / "baseline.json"
            write_delta_baseline(full, baseline_path)
            config_path = root / "chatlog.json"
            config_path.write_text(
                json.dumps(
                    {
                        "history": [
                            {
                                "account": "fixture",
                                "platform": "windows",
                                "version": 3,
                                "full_version": "3.9.fixture",
                                "data_dir": str(data_dir),
                                "data_key": "",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            def stage(name: str) -> dict[str, object]:
                stage_dir = root / name
                output_manifest = root / f"{name}.json"
                environment = os.environ.copy()
                environment["CGO_ENABLED"] = "0"
                result = subprocess.run(
                    [
                        str(go_executable),
                        "run",
                        str(project_root / "scripts" / "export_wechat_history.go"),
                        "--stage",
                        str(stage_dir),
                        "--manifest",
                        str(output_manifest),
                        "--config",
                        str(config_path),
                        "--baseline",
                        str(baseline_path),
                        "--configured-accounts-only",
                    ],
                    cwd=project_root,
                    env=environment,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=90,
                )
                if result.returncode:
                    self.fail(
                        f"Go staging failed ({result.returncode}):\n"
                        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
                    )
                return json.loads(output_manifest.read_text(encoding="utf-8"))

            unchanged = stage("stage-unchanged")
            unchanged_file = unchanged["accounts"][0]["files"][0]  # type: ignore[index]
            self.assertEqual(unchanged_file["status"], "unchanged")
            self.assertFalse(unchanged_file.get("staged_path"))

            original_state = database.stat()
            connection = sqlite3.connect(database)
            try:
                connection.execute(
                    "UPDATE MSG SET strContent='ONE' WHERE localId=1"
                )
                connection.commit()
            finally:
                connection.close()
            self.assertEqual(database.stat().st_size, original_state.st_size)
            os.utime(
                database,
                ns=(original_state.st_atime_ns, original_state.st_mtime_ns),
            )

            changed = stage("stage-changed")
            changed_file = changed["accounts"][0]["files"][0]  # type: ignore[index]
            self.assertEqual(changed_file["status"], "ok")
            self.assertNotEqual(
                changed_file["source_sha256"], unchanged_file["source_sha256"]
            )
            delta = root / "delta.duckdb"
            export(root / "stage-changed.json", delta, base_path=full)
            self.assertEqual(message_rows(delta)[0][-1], "ONE")

    def test_noop_changed_schema_and_legacy_bootstrap(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wechat-delta-test-") as raw_root:
            root = Path(raw_root)
            source_a = root / "state-a.db"
            source_b = root / "state-b.db"
            create_message_database(source_a)
            shutil.copyfile(source_a, source_b)
            mutate_message_database(source_b)

            full_a = root / "full-a.duckdb"
            export(manifest_for(source_a, root / "full-a.json"), full_a)
            connection = duckdb.connect(str(full_a))
            try:
                connection.execute("CREATE TABLE main.keep_me AS SELECT 42 AS value")
                connection.execute("CHECKPOINT")
            finally:
                connection.close()

            baseline_path = root / "baseline.json"
            baseline = write_delta_baseline(full_a, baseline_path)
            baseline_file = baseline["accounts"][0]["files"][0]

            no_op_manifest = manifest_for(
                source_a,
                root / "noop.json",
                status="unchanged",
                source_digest=baseline_file["source_sha256"],
                snapshot_digest=baseline_file["snapshot_sha256"],
            )
            no_op = root / "noop.duckdb"
            summary = export(no_op_manifest, no_op, base_path=full_a)
            self.assertEqual((summary["added"], summary["changed"], summary["removed"]), (0, 0, 0))
            self.assertEqual(summary["reused"], 1)
            self.assertEqual(message_rows(no_op), message_rows(full_a))

            delta_b = root / "delta-b.duckdb"
            delta_summary = export(
                manifest_for(source_b, root / "delta-b.json"),
                delta_b,
                base_path=no_op,
            )
            full_b = root / "full-b.duckdb"
            export(manifest_for(source_b, root / "full-b.json"), full_b)
            self.assertEqual(delta_summary["changed"], 1)
            self.assertEqual(message_rows(delta_b), message_rows(full_b))
            self.assertEqual(raw_shape_and_rows(delta_b), raw_shape_and_rows(full_b))
            connection = duckdb.connect(str(delta_b), read_only=True)
            try:
                self.assertEqual(
                    connection.execute("SELECT value FROM main.keep_me").fetchone()[0], 42
                )
                mode, completed = connection.execute(
                    "SELECT export_mode, completed FROM export_catalog.runs "
                    "ORDER BY imported_at DESC LIMIT 1"
                ).fetchone()
                self.assertEqual((mode, completed), ("delta", True))
            finally:
                connection.close()

            legacy = root / "legacy.duckdb"
            shutil.copyfile(full_a, legacy)
            downgrade_to_legacy(legacy)
            legacy_baseline = write_delta_baseline(legacy, root / "legacy-baseline.json")
            self.assertEqual(
                legacy_baseline["accounts"][0]["files"][0]["snapshot_sha256"], ""
            )
            migrated = root / "migrated.duckdb"
            export(
                manifest_for(source_b, root / "legacy-delta.json"),
                migrated,
                base_path=legacy,
            )
            self.assertEqual(message_rows(migrated), message_rows(full_b))
            connection = duckdb.connect(str(migrated), read_only=True)
            try:
                self.assertEqual(
                    connection.execute(
                        "SELECT schema_version FROM export_catalog.meta"
                    ).fetchone()[0],
                    EXPORT_SCHEMA_VERSION,
                )
            finally:
                connection.close()


if __name__ == "__main__":
    unittest.main()

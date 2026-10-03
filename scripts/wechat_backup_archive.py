"""Stream WeChat phone-backup message segments from a backup bundle.

``Backup.db`` is only an index.  Each ``MsgSegments`` row points at an
AES-128-ECB encrypted range in an adjacent ``BAK_*_TEXT`` file.  This module
reads one range at a time, validates it, and returns the repeated field-2
message records from the decrypted protobuf root value.

The protobuf schema is intentionally decoded only as far as the exporter
needs.  Every complete field is still walked and every message's original
field-2 payload is retained, so unknown fields and undecodable text are not
lost.
"""

from __future__ import annotations

import hashlib
import os
import re
import sqlite3
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Iterator

try:
    from Crypto.Cipher import AES
except ImportError as exc:  # pragma: no cover - depends on the caller's environment.
    raise ImportError(
        "wechat_backup_archive requires PyCryptodome (the 'pycryptodome' package)"
    ) from exc


AES_BLOCK_SIZE = 16
READ_CHUNK_SIZE = 8 * 1024 * 1024
MAX_PROTOBUF_FIELD_NUMBER = (1 << 29) - 1
MAX_PROTOBUF_GROUP_DEPTH = 100
SOURCE_FILE_NAME = re.compile(r"BAK_[0-9]+_TEXT\Z")


class BackupArchiveError(RuntimeError):
    """The backup index or one of its encrypted ranges is not trustworthy."""


@dataclass(frozen=True, slots=True)
class BackupMessage:
    """One protobuf message stored as a root field-2 value.

    ``record_offset`` is the zero-based offset of ``raw_record`` in the
    segment's unpadded ``root_value``.  Text properties are ``None`` both when
    absent and when their raw value is not valid UTF-8; the corresponding
    ``raw_*`` property distinguishes those cases without losing bytes.
    """

    ordinal: int
    record_offset: int
    record_length: int
    raw_record: bytes
    message_type: int | None
    sender_id: str | None
    recipient_id: str | None
    content: str | None
    create_time: int | None
    server_id: int | None
    msg_sequence: int | None
    sequence: int | None
    raw_sender_id: bytes | None
    raw_recipient_id: bytes | None
    raw_content: bytes | None


@dataclass(frozen=True, slots=True)
class BackupSegment:
    """A validated, decrypted ``MsgSegments`` range and its messages."""

    index_rowid: int
    talker_id: int
    user_name: str
    start_time: int
    end_time: int
    segment_id: str
    source_file: str
    source_offset: int
    encrypted_length: int
    plaintext_length: int
    padding_length: int
    root_value: bytes
    ciphertext_sha256: str
    plaintext_sha256: str
    messages: tuple[BackupMessage, ...]


@dataclass(frozen=True, slots=True)
class _Fingerprint:
    device: int
    inode: int
    mode: int
    size: int
    modified_ns: int
    changed_ns: int


@dataclass(frozen=True, slots=True)
class _SourceInfo:
    relative_name: str
    path: Path
    fingerprint: _Fingerprint


@dataclass(frozen=True, slots=True)
class _IndexRow:
    rowid: int
    talker_id: int
    user_name: str
    start_time: int
    end_time: int
    source_offset: int
    encrypted_length: int
    source_file: str
    segment_id: str


def _fingerprint_result(value: os.stat_result) -> _Fingerprint:
    return _Fingerprint(
        device=int(value.st_dev),
        inode=int(value.st_ino),
        mode=int(value.st_mode),
        size=int(value.st_size),
        modified_ns=int(value.st_mtime_ns),
        changed_ns=int(value.st_ctime_ns),
    )


def _fingerprint_path(path: Path) -> _Fingerprint:
    try:
        return _fingerprint_result(path.stat())
    except OSError as exc:
        raise BackupArchiveError(f"cannot stat backup input {path}: {exc}") from exc


def _fingerprint_handle(handle: BinaryIO) -> _Fingerprint:
    try:
        return _fingerprint_result(os.fstat(handle.fileno()))
    except OSError as exc:
        raise BackupArchiveError(f"cannot stat an open backup source: {exc}") from exc


def _require_unchanged(path: Path, expected: _Fingerprint, label: str) -> None:
    current = _fingerprint_path(path)
    if current != expected:
        raise BackupArchiveError(f"{label} changed while the backup was being read: {path}")


def _require_open_unchanged(
    handle: BinaryIO, path: Path, expected: _Fingerprint, label: str
) -> None:
    current = _fingerprint_handle(handle)
    # Windows can report creation time through stat(path).st_ctime_ns but the
    # last-write time through fstat(handle).st_ctime_ns for the same file.
    # Compare stable identity/content fields here; the path-level check below
    # still compares the full fingerprint, including changed_ns.
    if (
        current.device,
        current.inode,
        current.mode,
        current.size,
        current.modified_ns,
    ) != (
        expected.device,
        expected.inode,
        expected.mode,
        expected.size,
        expected.modified_ns,
    ):
        raise BackupArchiveError(f"open {label} changed while it was being read: {path}")
    _require_unchanged(path, expected, label)


def _require_regular_file(path: Path, fingerprint: _Fingerprint, label: str) -> None:
    if not stat.S_ISREG(fingerprint.mode):
        raise BackupArchiveError(f"{label} is not a regular file: {path}")


def _validate_key(key: bytes) -> bytes:
    if not isinstance(key, bytes):
        raise TypeError("key must be bytes")
    if len(key) != AES_BLOCK_SIZE:
        raise ValueError("AES-128 backup key must be exactly 16 bytes")
    return key


def _sqlite_uri(path: Path) -> str:
    return path.as_uri() + "?mode=ro&immutable=1"


def _open_index(index_path: Path) -> sqlite3.Connection:
    try:
        with index_path.open("rb") as source:
            header = source.read(16)
    except OSError as exc:
        raise BackupArchiveError(f"cannot read decrypted backup index {index_path}: {exc}") from exc
    if header != b"SQLite format 3\x00":
        raise BackupArchiveError(
            f"backup index is not a decrypted SQLite database: {index_path}"
        )

    # An immutable connection deliberately ignores WAL state.  Refuse any
    # non-empty journal first so committed rows cannot silently be omitted.
    for suffix in ("-wal", "-journal"):
        sidecar = Path(str(index_path) + suffix)
        try:
            if sidecar.exists() and sidecar.stat().st_size:
                raise BackupArchiveError(
                    f"backup index has a non-empty SQLite sidecar; checkpoint it first: {sidecar}"
                )
        except OSError as exc:
            raise BackupArchiveError(f"cannot inspect SQLite sidecar {sidecar}: {exc}") from exc

    try:
        connection = sqlite3.connect(_sqlite_uri(index_path), uri=True)
        connection.execute("PRAGMA query_only = ON")
        connection.execute("BEGIN")
        return connection
    except sqlite3.Error as exc:
        raise BackupArchiveError(f"cannot open decrypted backup index {index_path}: {exc}") from exc


def _validate_index(connection: sqlite3.Connection) -> None:
    required = {
        "talkerid",
        "usrname",
        "starttime",
        "endtime",
        "offset",
        "length",
        "filepath",
        "segmentid",
    }
    try:
        columns = connection.execute('PRAGMA table_info("MsgSegments")').fetchall()
    except sqlite3.Error as exc:
        raise BackupArchiveError(f"cannot inspect MsgSegments: {exc}") from exc
    available = {str(row[1]).casefold() for row in columns}
    missing = sorted(required - available)
    if missing:
        raise BackupArchiveError(
            "backup index MsgSegments is missing required columns: " + ", ".join(missing)
        )

    try:
        quick_check = connection.execute("PRAGMA quick_check").fetchall()
    except sqlite3.Error as exc:
        raise BackupArchiveError(f"backup index quick_check failed to run: {exc}") from exc
    if len(quick_check) != 1 or str(quick_check[0][0]).casefold() != "ok":
        details = "; ".join(str(row[0]) for row in quick_check[:10]) or "no result"
        raise BackupArchiveError(f"backup index quick_check failed: {details}")


def _require_int(value: object, column: str, rowid: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise BackupArchiveError(f"MsgSegments row {rowid!r} has a non-integer {column}")
    return value


def _require_text(value: object, column: str, rowid: object) -> str:
    if not isinstance(value, str) or not value:
        raise BackupArchiveError(f"MsgSegments row {rowid!r} has an invalid {column}")
    if "\x00" in value:
        raise BackupArchiveError(f"MsgSegments row {rowid!r} has a NUL in {column}")
    return value


def _parse_index_row(values: tuple[object, ...]) -> _IndexRow:
    raw_rowid = values[0]
    rowid = _require_int(raw_rowid, "rowid", raw_rowid)
    if rowid <= 0:
        raise BackupArchiveError(f"MsgSegments has an invalid rowid: {rowid}")
    row = _IndexRow(
        rowid=rowid,
        talker_id=_require_int(values[1], "talkerId", rowid),
        user_name=_require_text(values[2], "UsrName", rowid),
        start_time=_require_int(values[3], "StartTime", rowid),
        end_time=_require_int(values[4], "EndTime", rowid),
        source_offset=_require_int(values[5], "OffSet", rowid),
        encrypted_length=_require_int(values[6], "Length", rowid),
        source_file=_require_text(values[7], "FilePath", rowid),
        segment_id=_require_text(values[8], "SegmentId", rowid),
    )
    if row.source_offset < 0:
        raise BackupArchiveError(f"MsgSegments row {rowid} has a negative OffSet")
    if row.encrypted_length <= 0:
        raise BackupArchiveError(f"MsgSegments row {rowid} has a non-positive Length")
    if row.source_offset % AES_BLOCK_SIZE:
        raise BackupArchiveError(f"MsgSegments row {rowid} OffSet is not AES-block aligned")
    if row.encrypted_length % AES_BLOCK_SIZE:
        raise BackupArchiveError(f"MsgSegments row {rowid} Length is not AES-block aligned")
    return row


def _safe_source_path(bundle_root: Path, raw_name: str) -> tuple[str, Path]:
    # Treat both slash styles as separators even when tests run off Windows.
    portable = raw_name.replace("\\", "/")
    pieces = portable.split("/")
    if (
        portable.startswith("/")
        or not pieces
        or any(piece in ("", ".", "..") for piece in pieces)
        or ":" in pieces[0]
    ):
        raise BackupArchiveError("MsgSegments FilePath is absolute or contains traversal")
    if len(pieces) != 1 or SOURCE_FILE_NAME.fullmatch(pieces[0]) is None:
        raise BackupArchiveError(
            "MsgSegments FilePath is not an unqualified BAK_<number>_TEXT source"
        )

    unresolved = bundle_root.joinpath(*pieces)
    current = bundle_root
    for piece in pieces:
        current = current / piece
        try:
            if current.is_symlink():
                raise BackupArchiveError(f"backup source path contains a symbolic link: {raw_name}")
        except OSError as exc:
            raise BackupArchiveError(f"cannot inspect backup source path {raw_name}: {exc}") from exc
    try:
        resolved = unresolved.resolve(strict=True)
        resolved.relative_to(bundle_root)
    except (OSError, ValueError) as exc:
        raise BackupArchiveError(
            f"backup source does not resolve inside the bundle: {raw_name}"
        ) from exc
    return "/".join(pieces), resolved


_INDEX_QUERY = """
    SELECT rowid, talkerId, UsrName, StartTime, EndTime, OffSet, Length, FilePath, SegmentId
    FROM MsgSegments
    ORDER BY FilePath COLLATE BINARY, OffSet, rowid
"""


def _preflight_sources(
    connection: sqlite3.Connection, bundle_root: Path
) -> tuple[dict[str, _SourceInfo], dict[str, str]]:
    sources: dict[str, _SourceInfo] = {}
    path_keys: dict[str, str] = {}
    previous_end: dict[str, int] = {}
    try:
        cursor = connection.execute(_INDEX_QUERY)
        for values in cursor:
            row = _parse_index_row(values)
            info = sources.get(row.source_file)
            if info is None:
                relative_name, source_path = _safe_source_path(bundle_root, row.source_file)
                fingerprint = _fingerprint_path(source_path)
                _require_regular_file(source_path, fingerprint, "backup source")
                identity = os.path.normcase(str(source_path))
                prior_name = path_keys.get(identity)
                if prior_name is not None and prior_name != row.source_file:
                    raise BackupArchiveError(
                        "different MsgSegments FilePath values resolve to the same source file"
                    )
                path_keys[identity] = row.source_file
                info = _SourceInfo(relative_name, source_path, fingerprint)
                sources[row.source_file] = info

            size = info.fingerprint.size
            if row.source_offset > size or row.encrypted_length > size - row.source_offset:
                raise BackupArchiveError(
                    f"MsgSegments row {row.rowid} range exceeds {info.relative_name}"
                )
            identity = os.path.normcase(str(info.path))
            prior_end = previous_end.get(identity)
            if prior_end is not None and row.source_offset < prior_end:
                raise BackupArchiveError(
                    f"MsgSegments row {row.rowid} overlaps a prior encrypted range"
                )
            previous_end[identity] = row.source_offset + row.encrypted_length
    except sqlite3.Error as exc:
        raise BackupArchiveError(f"cannot read MsgSegments: {exc}") from exc
    return sources, path_keys


def _read_varint(data: memoryview, position: int, end: int, context: str) -> tuple[int, int]:
    value = 0
    for index in range(10):
        if position >= end:
            raise BackupArchiveError(f"truncated protobuf varint in {context}")
        byte = data[position]
        position += 1
        if index == 9 and byte > 1:
            raise BackupArchiveError(f"protobuf varint exceeds uint64 in {context}")
        value |= (byte & 0x7F) << (index * 7)
        if byte < 0x80:
            return value, position
    raise BackupArchiveError(f"protobuf varint is too long in {context}")


def _read_tag(data: memoryview, position: int, end: int, context: str) -> tuple[int, int, int]:
    tag, position = _read_varint(data, position, end, context)
    field_number = tag >> 3
    wire_type = tag & 7
    if field_number == 0 or field_number > MAX_PROTOBUF_FIELD_NUMBER:
        raise BackupArchiveError(f"invalid protobuf field number in {context}")
    return field_number, wire_type, position


def _skip_group(
    data: memoryview,
    position: int,
    end: int,
    group_number: int,
    context: str,
    depth: int,
) -> int:
    if depth > MAX_PROTOBUF_GROUP_DEPTH:
        raise BackupArchiveError(f"protobuf groups are nested too deeply in {context}")
    while position < end:
        field_number, wire_type, value_position = _read_tag(data, position, end, context)
        if wire_type == 4:
            if field_number != group_number:
                raise BackupArchiveError(f"mismatched protobuf end-group in {context}")
            return value_position
        position = _skip_wire_value(
            data, value_position, end, field_number, wire_type, context, depth
        )
    raise BackupArchiveError(f"unterminated protobuf group in {context}")


def _skip_wire_value(
    data: memoryview,
    position: int,
    end: int,
    field_number: int,
    wire_type: int,
    context: str,
    depth: int = 0,
) -> int:
    if wire_type == 0:
        _, position = _read_varint(data, position, end, context)
        return position
    if wire_type == 1:
        position += 8
    elif wire_type == 2:
        length, position = _read_varint(data, position, end, context)
        if length > end - position:
            raise BackupArchiveError(f"truncated length-delimited protobuf field in {context}")
        position += length
    elif wire_type == 3:
        return _skip_group(data, position, end, field_number, context, depth + 1)
    elif wire_type == 4:
        raise BackupArchiveError(f"unexpected protobuf end-group in {context}")
    elif wire_type == 5:
        position += 4
    else:
        raise BackupArchiveError(f"invalid protobuf wire type {wire_type} in {context}")
    if position > end:
        raise BackupArchiveError(f"truncated fixed-width protobuf field in {context}")
    return position


def _length_delimited_bounds(
    data: memoryview, position: int, end: int, context: str
) -> tuple[int, int, int]:
    length, value_start = _read_varint(data, position, end, context)
    if length > end - value_start:
        raise BackupArchiveError(f"truncated length-delimited protobuf field in {context}")
    value_end = value_start + length
    return value_start, value_end, value_end


def _embedded_field_one(raw: memoryview, outer_number: int, context: str) -> bytes | None:
    position = 0
    end = len(raw)
    result: bytes | None = None
    nested_context = f"{context} field {outer_number}"
    while position < end:
        field_number, wire_type, value_position = _read_tag(
            raw, position, end, nested_context
        )
        if field_number == 1:
            if wire_type != 2:
                raise BackupArchiveError(
                    f"protobuf field {outer_number}.1 has unexpected wire type {wire_type} in {context}"
                )
            value_start, value_end, position = _length_delimited_bounds(
                raw, value_position, end, nested_context
            )
            result = bytes(raw[value_start:value_end])
        else:
            position = _skip_wire_value(
                raw, value_position, end, field_number, wire_type, nested_context
            )
    if position != end:  # Defensive; every branch above either advances or raises.
        raise BackupArchiveError(f"protobuf embedded value was not consumed exactly in {context}")
    return result


def _utf8_or_none(value: bytes | None) -> str | None:
    if value is None:
        return None
    try:
        return value.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _parse_message(
    raw_record: bytes, ordinal: int, record_offset: int, segment_rowid: int
) -> BackupMessage:
    data = memoryview(raw_record)
    position = 0
    end = len(data)
    context = f"MsgSegments row {segment_rowid}, message {ordinal}"
    scalar_fields: dict[int, int] = {}
    embedded_fields: dict[int, bytes | None] = {}
    scalar_numbers = {1, 7, 16, 17, 18}
    embedded_numbers = {3, 4, 5}

    while position < end:
        field_number, wire_type, value_position = _read_tag(data, position, end, context)
        if field_number in scalar_numbers:
            if wire_type != 0:
                raise BackupArchiveError(
                    f"protobuf field {field_number} has unexpected wire type {wire_type} in {context}"
                )
            value, position = _read_varint(data, value_position, end, context)
            scalar_fields[field_number] = value
        elif field_number in embedded_numbers:
            if wire_type != 2:
                raise BackupArchiveError(
                    f"protobuf field {field_number} has unexpected wire type {wire_type} in {context}"
                )
            value_start, value_end, position = _length_delimited_bounds(
                data, value_position, end, context
            )
            embedded_fields[field_number] = _embedded_field_one(
                data[value_start:value_end], field_number, context
            )
        else:
            position = _skip_wire_value(
                data, value_position, end, field_number, wire_type, context
            )
    if position != end:
        raise BackupArchiveError(f"protobuf message was not consumed exactly in {context}")

    raw_sender = embedded_fields.get(3)
    raw_recipient = embedded_fields.get(4)
    raw_content = embedded_fields.get(5)
    return BackupMessage(
        ordinal=ordinal,
        record_offset=record_offset,
        record_length=len(raw_record),
        raw_record=raw_record,
        message_type=scalar_fields.get(1),
        sender_id=_utf8_or_none(raw_sender),
        recipient_id=_utf8_or_none(raw_recipient),
        content=_utf8_or_none(raw_content),
        create_time=scalar_fields.get(7),
        server_id=scalar_fields.get(16),
        msg_sequence=scalar_fields.get(17),
        sequence=scalar_fields.get(18),
        raw_sender_id=raw_sender,
        raw_recipient_id=raw_recipient,
        raw_content=raw_content,
    )


def _parse_root(root_value: bytes, segment_rowid: int) -> tuple[BackupMessage, ...]:
    data = memoryview(root_value)
    position = 0
    end = len(data)
    messages: list[BackupMessage] = []
    context = f"MsgSegments row {segment_rowid} root"
    while position < end:
        field_number, wire_type, value_position = _read_tag(data, position, end, context)
        if field_number == 2:
            if wire_type != 2:
                raise BackupArchiveError(
                    f"protobuf root field 2 has unexpected wire type {wire_type} in {context}"
                )
            value_start, value_end, position = _length_delimited_bounds(
                data, value_position, end, context
            )
            raw_record = bytes(data[value_start:value_end])
            messages.append(
                _parse_message(raw_record, len(messages), value_start, segment_rowid)
            )
        else:
            position = _skip_wire_value(
                data, value_position, end, field_number, wire_type, context
            )
    if position != end:
        raise BackupArchiveError(f"protobuf root was not consumed exactly in {context}")
    return tuple(messages)


def _decrypt_range(
    handle: BinaryIO,
    source_path: Path,
    expected: _Fingerprint,
    row: _IndexRow,
    key: bytes,
) -> tuple[bytes, str, int]:
    _require_open_unchanged(handle, source_path, expected, "backup source")
    try:
        handle.seek(row.source_offset)
    except OSError as exc:
        raise BackupArchiveError(
            f"cannot seek to MsgSegments row {row.rowid} encrypted range: {exc}"
        ) from exc

    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext_hash = hashlib.sha256()
    plaintext = bytearray()
    remaining = row.encrypted_length
    while remaining:
        amount = min(READ_CHUNK_SIZE, remaining)
        # Both the full range and READ_CHUNK_SIZE are block-aligned.
        try:
            chunk = handle.read(amount)
        except OSError as exc:
            raise BackupArchiveError(
                f"cannot read MsgSegments row {row.rowid} encrypted range: {exc}"
            ) from exc
        if len(chunk) != amount:
            raise BackupArchiveError(
                f"short read in MsgSegments row {row.rowid} encrypted range"
            )
        ciphertext_hash.update(chunk)
        plaintext.extend(cipher.decrypt(chunk))
        remaining -= amount

    _require_open_unchanged(handle, source_path, expected, "backup source")
    padding_length = plaintext[-1]
    if padding_length < 1 or padding_length > AES_BLOCK_SIZE:
        raise BackupArchiveError(f"invalid PKCS#7 padding in MsgSegments row {row.rowid}")
    if plaintext[-padding_length:] != bytes((padding_length,)) * padding_length:
        raise BackupArchiveError(f"invalid PKCS#7 padding in MsgSegments row {row.rowid}")
    del plaintext[-padding_length:]
    root_value = bytes(plaintext)
    return root_value, ciphertext_hash.hexdigest(), padding_length


def iter_backup_segments(
    index_db: Path, bundle_root: Path, key: bytes
) -> Iterator[BackupSegment]:
    """Yield every strictly validated message segment in archive order.

    Args:
        index_db: A decrypted SQLite ``Backup.db``.
        bundle_root: Directory containing the ``BAK_*_TEXT`` files named by
            ``MsgSegments.FilePath``.
        key: The exact 16-byte AES-128 key used for archive segments.

    The iterator performs a metadata preflight before yielding anything.  It
    then reads and decrypts one segment at a time, keeping memory bounded by
    the largest segment.  The index, bundle directory, and every opened source
    are fingerprinted and checked throughout and again when iteration ends.
    """

    aes_key = _validate_key(key)
    try:
        index_path = Path(index_db).resolve(strict=True)
        root_path = Path(bundle_root).resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise BackupArchiveError(f"backup input path cannot be resolved: {exc}") from exc
    index_fingerprint = _fingerprint_path(index_path)
    root_fingerprint = _fingerprint_path(root_path)
    _require_regular_file(index_path, index_fingerprint, "backup index")
    if not stat.S_ISDIR(root_fingerprint.mode):
        raise BackupArchiveError(f"backup bundle root is not a directory: {root_path}")

    connection: sqlite3.Connection | None = None
    active_handle: BinaryIO | None = None
    active_source: _SourceInfo | None = None
    sources: dict[str, _SourceInfo] = {}
    completed = False
    try:
        connection = _open_index(index_path)
        _validate_index(connection)
        sources, _ = _preflight_sources(connection, root_path)
        _require_unchanged(index_path, index_fingerprint, "backup index")
        _require_unchanged(root_path, root_fingerprint, "backup bundle directory")

        try:
            cursor = connection.execute(_INDEX_QUERY)
            for values in cursor:
                row = _parse_index_row(values)
                source = sources[row.source_file]
                if active_source != source:
                    if active_handle is not None and active_source is not None:
                        _require_open_unchanged(
                            active_handle,
                            active_source.path,
                            active_source.fingerprint,
                            "backup source",
                        )
                        active_handle.close()
                    try:
                        active_handle = source.path.open("rb", buffering=0)
                    except OSError as exc:
                        raise BackupArchiveError(
                            f"cannot open backup source {source.path}: {exc}"
                        ) from exc
                    active_source = source
                    _require_open_unchanged(
                        active_handle, source.path, source.fingerprint, "backup source"
                    )

                assert active_handle is not None
                root_value, ciphertext_sha256, padding_length = _decrypt_range(
                    active_handle,
                    source.path,
                    source.fingerprint,
                    row,
                    aes_key,
                )
                messages = _parse_root(root_value, row.rowid)
                yield BackupSegment(
                    index_rowid=row.rowid,
                    talker_id=row.talker_id,
                    user_name=row.user_name,
                    start_time=row.start_time,
                    end_time=row.end_time,
                    segment_id=row.segment_id,
                    source_file=source.relative_name,
                    source_offset=row.source_offset,
                    encrypted_length=row.encrypted_length,
                    plaintext_length=len(root_value),
                    padding_length=padding_length,
                    root_value=root_value,
                    ciphertext_sha256=ciphertext_sha256,
                    plaintext_sha256=hashlib.sha256(root_value).hexdigest(),
                    messages=messages,
                )
        except sqlite3.Error as exc:
            raise BackupArchiveError(f"cannot stream MsgSegments: {exc}") from exc

        if active_handle is not None and active_source is not None:
            _require_open_unchanged(
                active_handle,
                active_source.path,
                active_source.fingerprint,
                "backup source",
            )
            active_handle.close()
            active_handle = None
        for source in sources.values():
            _require_unchanged(source.path, source.fingerprint, "backup source")
        _require_unchanged(index_path, index_fingerprint, "backup index")
        _require_unchanged(root_path, root_fingerprint, "backup bundle directory")
        completed = True
    finally:
        if active_handle is not None:
            active_handle.close()
        if connection is not None:
            connection.close()
        # On normal exhaustion, all inputs were checked immediately above.
        # If a consumer stops early, perform best-effort checks during close;
        # do not mask an exception already propagating from the iterator.
        if not completed:
            try:
                _require_unchanged(index_path, index_fingerprint, "backup index")
                _require_unchanged(root_path, root_fingerprint, "backup bundle directory")
                for source in sources.values():
                    _require_unchanged(source.path, source.fingerprint, "backup source")
            except BackupArchiveError:
                # A mutation is raised during ordinary iteration before this
                # cleanup path.  GeneratorExit cannot safely carry a second
                # failure from best-effort cleanup.
                pass


__all__ = [
    "BackupArchiveError",
    "BackupMessage",
    "BackupSegment",
    "iter_backup_segments",
]

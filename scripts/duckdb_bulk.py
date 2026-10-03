# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "duckdb>=1.2.0",
#     "pyarrow>=17.0.0",
# ]
# ///

"""Fast, typed, lossless inserts from Python rows into DuckDB.

The public functions deliberately do not manage transactions.  A caller that
needs all batches to be atomic should issue ``BEGIN``/``COMMIT`` around the
call.  Data is transferred through a typed Arrow table, so DuckDB performs one
vectorized INSERT per batch instead of one prepared statement per row.

``destination_sql`` must be a trusted, already-quoted DuckDB table identifier,
for example ``'"raw_account"."messages"'``.
"""

from __future__ import annotations

import argparse
import numbers
import time
import uuid
from dataclasses import dataclass
from typing import Any, Iterable, Iterator, Sequence

import pyarrow as pa


DEFAULT_BATCH_SIZE = 65_536
_BIGINT_MIN = -(1 << 63)
_BIGINT_MAX = (1 << 63) - 1
_UBIGINT_MAX = (1 << 64) - 1


class BulkInsertError(ValueError):
    """A row cannot be represented losslessly by the requested schema."""


@dataclass(frozen=True, slots=True)
class Column:
    """One positional destination column."""

    name: str
    duckdb_type: str


ColumnLike = Column | tuple[str, str]


def _quote_identifier(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'


def _normalise_type(value: str) -> str:
    normalised = " ".join(value.upper().split())
    aliases = {
        "TEXT": "VARCHAR",
        "STRING": "VARCHAR",
        "INT8": "BIGINT",
        "LONG": "BIGINT",
        "UINT64": "UBIGINT",
        "BYTEA": "BLOB",
        "BINARY": "BLOB",
        "VARBINARY": "BLOB",
        "FLOAT8": "DOUBLE",
        "DOUBLE PRECISION": "DOUBLE",
    }
    normalised = aliases.get(normalised, normalised)
    if normalised not in {"VARCHAR", "BIGINT", "UBIGINT", "BLOB", "DOUBLE"}:
        raise BulkInsertError(
            f"unsupported bulk column type {value!r}; supported types are "
            "VARCHAR, BIGINT, UBIGINT, BLOB, and DOUBLE"
        )
    return normalised


def _prepare_columns(columns: Sequence[ColumnLike]) -> tuple[Column, ...]:
    prepared: list[Column] = []
    seen: set[str] = set()
    for ordinal, item in enumerate(columns):
        if isinstance(item, Column):
            name, duckdb_type = item.name, item.duckdb_type
        else:
            try:
                name, duckdb_type = item
            except (TypeError, ValueError) as exc:
                raise BulkInsertError(
                    f"column #{ordinal + 1} must be a (name, type) pair"
                ) from exc
        if not isinstance(name, str) or not name:
            raise BulkInsertError(f"column #{ordinal + 1} has an empty or non-string name")
        folded = name.casefold()
        if folded in seen:
            raise BulkInsertError(f"duplicate column name: {name!r}")
        seen.add(folded)
        prepared.append(Column(name, _normalise_type(str(duckdb_type))))
    if not prepared:
        raise BulkInsertError("at least one column is required")
    return tuple(prepared)


def _arrow_type(duckdb_type: str) -> pa.DataType:
    # Large offsets avoid Arrow's 2 GiB aggregate-buffer limit for text/blob
    # columns while still mapping directly to DuckDB VARCHAR/BLOB.
    return {
        "VARCHAR": pa.large_string(),
        "BIGINT": pa.int64(),
        "UBIGINT": pa.uint64(),
        "BLOB": pa.large_binary(),
        "DOUBLE": pa.float64(),
    }[duckdb_type]


def _coerce(value: Any, duckdb_type: str, row_number: int, column_name: str) -> Any:
    if value is None:
        return None
    problem = f"row {row_number}, column {column_name!r}"
    if duckdb_type == "VARCHAR":
        if not isinstance(value, str):
            raise BulkInsertError(f"{problem}: expected str or None, got {type(value).__name__}")
        return value
    if duckdb_type == "BLOB":
        if isinstance(value, bytes):
            return value
        if isinstance(value, (bytearray, memoryview)):
            return bytes(value)
        raise BulkInsertError(
            f"{problem}: expected bytes-like value or None, got {type(value).__name__}"
        )
    if duckdb_type in {"BIGINT", "UBIGINT"}:
        if isinstance(value, bool) or not isinstance(value, numbers.Integral):
            raise BulkInsertError(
                f"{problem}: expected an integer or None, got {type(value).__name__}"
            )
        result = int(value)
        minimum, maximum = (
            (_BIGINT_MIN, _BIGINT_MAX)
            if duckdb_type == "BIGINT"
            else (0, _UBIGINT_MAX)
        )
        if not minimum <= result <= maximum:
            raise BulkInsertError(
                f"{problem}: integer is outside DuckDB {duckdb_type} range"
            )
        return result
    if isinstance(value, bool) or not isinstance(value, numbers.Real):
        raise BulkInsertError(
            f"{problem}: expected a real number or None, got {type(value).__name__}"
        )
    return float(value)


def _to_arrow_table(
    rows: Sequence[Sequence[Any]], columns: tuple[Column, ...], row_offset: int
) -> pa.Table:
    values: list[list[Any]] = [[] for _ in columns]
    width = len(columns)
    for batch_index, row in enumerate(rows):
        row_number = row_offset + batch_index + 1
        if isinstance(row, (str, bytes, bytearray, memoryview)):
            raise BulkInsertError(f"row {row_number}: expected a sequence of {width} values")
        try:
            actual_width = len(row)
        except TypeError as exc:
            raise BulkInsertError(
                f"row {row_number}: expected a sequence of {width} values"
            ) from exc
        if actual_width != width:
            raise BulkInsertError(
                f"row {row_number}: expected {width} values, got {actual_width}"
            )
        for ordinal, column in enumerate(columns):
            values[ordinal].append(
                _coerce(row[ordinal], column.duckdb_type, row_number, column.name)
            )

    fields = [pa.field(column.name, _arrow_type(column.duckdb_type)) for column in columns]
    arrays = [
        pa.array(column_values, type=field.type, from_pandas=False)
        for column_values, field in zip(values, fields, strict=True)
    ]
    return pa.Table.from_arrays(arrays, schema=pa.schema(fields))


def _insert_prepared_batch(
    connection: Any,
    destination_sql: str,
    rows: Sequence[Sequence[Any]],
    columns: tuple[Column, ...],
    row_offset: int,
) -> int:
    if not rows:
        return 0
    table = _to_arrow_table(rows, columns, row_offset)
    registration = "_wechat_bulk_" + uuid.uuid4().hex
    connection.register(registration, table)
    try:
        connection.execute(
            f"INSERT INTO {destination_sql} SELECT * FROM {_quote_identifier(registration)}"
        )
    finally:
        connection.unregister(registration)
    return len(rows)


def insert_batch(
    connection: Any,
    destination_sql: str,
    rows: Sequence[Sequence[Any]],
    columns: Sequence[ColumnLike],
) -> int:
    """Insert one materialized batch and return its row count.

    Conversion is strict: values that cannot be represented by their declared
    type fail before the INSERT, rather than being stringified or truncated.
    """

    return _insert_prepared_batch(
        connection, destination_sql, rows, _prepare_columns(columns), 0
    )


def _chunks(rows: Iterable[Sequence[Any]], size: int) -> Iterator[list[Sequence[Any]]]:
    batch: list[Sequence[Any]] = []
    for row in rows:
        batch.append(row)
        if len(batch) == size:
            yield batch
            batch = []
    if batch:
        yield batch


def insert_rows(
    connection: Any,
    destination_sql: str,
    rows: Iterable[Sequence[Any]],
    columns: Sequence[ColumnLike],
    *,
    batch_size: int = DEFAULT_BATCH_SIZE,
) -> int:
    """Stream rows into DuckDB in Arrow batches and return rows inserted."""

    if isinstance(batch_size, bool) or not isinstance(batch_size, int) or batch_size <= 0:
        raise BulkInsertError("batch_size must be a positive integer")
    prepared = _prepare_columns(columns)
    inserted = 0
    for batch in _chunks(rows, batch_size):
        inserted += _insert_prepared_batch(
            connection, destination_sql, batch, prepared, inserted
        )
    return inserted


def insert_batches(
    connection: Any,
    destination_sql: str,
    batches: Iterable[Sequence[Sequence[Any]]],
    columns: Sequence[ColumnLike],
) -> int:
    """Insert caller-supplied batches without combining them in memory."""

    prepared = _prepare_columns(columns)
    inserted = 0
    for batch in batches:
        inserted += _insert_prepared_batch(
            connection, destination_sql, batch, prepared, inserted
        )
    return inserted


def _benchmark(row_count: int, batch_size: int) -> None:
    import duckdb

    connection = duckdb.connect(":memory:")
    connection.execute(
        "CREATE TABLE bench(id BIGINT, body VARCHAR, payload BLOB, score DOUBLE)"
    )
    columns = (
        ("id", "BIGINT"),
        ("body", "VARCHAR"),
        ("payload", "BLOB"),
        ("score", "DOUBLE"),
    )

    # Boundary and binary round-trip check before the throughput run.
    edge_rows = [
        (_BIGINT_MIN, "", b"", None),
        (_BIGINT_MAX, "微信 \U0001f642", b"\x00\xff\x80", -0.0),
        (None, None, None, 1.25),
    ]
    connection.execute("BEGIN")
    inserted = insert_batch(connection, "bench", edge_rows, columns)
    actual = connection.execute(
        "SELECT id, body, payload, score FROM bench ORDER BY rowid"
    ).fetchall()
    if inserted != len(edge_rows) or actual != edge_rows:
        connection.execute("ROLLBACK")
        raise AssertionError(f"Arrow round-trip mismatch: {actual!r}")
    connection.execute("ROLLBACK")

    connection.execute("CREATE TABLE unsigned_bench(value UBIGINT)")
    unsigned_rows = [(0,), (_UBIGINT_MAX,), (None,)]
    insert_batch(connection, "unsigned_bench", unsigned_rows, (("value", "UBIGINT"),))
    if connection.execute("SELECT value FROM unsigned_bench ORDER BY rowid").fetchall() != unsigned_rows:
        raise AssertionError("UBIGINT boundary round-trip mismatch")

    def generated_rows() -> Iterator[tuple[Any, ...]]:
        for index in range(row_count):
            yield (
                index,
                None if index % 17 == 0 else f"message-{index}-微信",
                None if index % 19 == 0 else index.to_bytes(8, "little") + b"\x00\xff",
                None if index % 23 == 0 else index / 10.0,
            )

    started = time.perf_counter()
    connection.execute("BEGIN")
    inserted = insert_rows(
        connection, "bench", generated_rows(), columns, batch_size=batch_size
    )
    connection.execute("COMMIT")
    elapsed = time.perf_counter() - started
    observed = connection.execute(
        "SELECT count(*), sum(id), count(*) FILTER (WHERE body IS NULL), "
        "count(*) FILTER (WHERE payload IS NULL) FROM bench"
    ).fetchone()
    expected = (
        row_count,
        row_count * (row_count - 1) // 2,
        (row_count + 16) // 17,
        (row_count + 18) // 19,
    )
    if inserted != row_count or observed != expected:
        raise AssertionError(
            f"benchmark verification failed: inserted={inserted}, "
            f"observed={observed}, expected={expected}"
        )
    print(
        f"duckdb={duckdb.__version__} pyarrow={pa.__version__} "
        f"rows={row_count:,} batch_size={batch_size:,} elapsed={elapsed:.3f}s "
        f"rows_per_second={row_count / elapsed:,.0f} verified=true"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Benchmark the Arrow bulk-insert path")
    parser.add_argument("--rows", type=int, default=3_000_000)
    parser.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE)
    args = parser.parse_args()
    if args.rows < 0:
        parser.error("--rows must not be negative")
    _benchmark(args.rows, args.batch_size)


if __name__ == "__main__":
    main()

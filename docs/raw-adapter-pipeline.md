# Raw adapter qualification and direction

The `scripts/export_wechat_history.py` semantic schema is version **7**. Its
normalized contact and message fields use source evidence while retaining the
original raw tables and account/database/object provenance.

## Friend eligibility

Windows v3 uses the locally documented `Contact.Reserved1` values: `1` is a
contact in the address book and `0` is a nonfriend room member. Other values,
missing flags, and malformed numeric values produce `NULL`. See the source
adapter's [ContactV3 declaration](../internal/model/contact.go).

For v4, the primary [WeLink database documentation](https://welink.click/database)
describes `(contact.flag & 3) != 0` as its friend predicate and `verify_flag = 0`
as a normal contact. This exporter requires that positive bit-mask evidence,
an explicit `verify_flag = 0`, and `delete_flag = 0`. Missing, malformed, or
unsupported flag values remain `NULL`. Known group/member types, a deleted
entry, and verified-account entries are excluded. A `local_type` value or a
nonempty remark alone never qualifies a contact.

The documented mask is **nonzero**, rather than `= 3`; the exporter does not
invent reciprocal friendship semantics for individual bits. This is evidence
of local address-book membership, not verification of a reciprocal relationship
on WeChat's servers. These are private client schemas and may change; unfamiliar
evidence stays unqualified.

Across adapters, group IDs, `gh_` IDs, `filehelper`, and the source account's own
username are not person-to-person friends. Missing usernames stay unknown.
Darwin v3 `WCContact` table membership has no verified friendship flag in this
adapter, so its `is_friend` is `NULL`.

## Message direction

Windows v3 accepts only canonical integral `IsSender = 0` or `1`. Other values
remain unknown. For live v4 and phone backup records:

- A known sender equal to the source **account username** is outgoing.
- A sender equal to a known private-chat peer is incoming.
- A known group sender differing from a known account username is incoming.
- Missing senders and unrelated private-chat senders remain unknown.

The catalog `account_id` includes a path hash; it is not a sender username. The
manifest's `account` field becomes `account_name`. If that field is absent,
the exporter does not substitute the catalog ID. The local
[MessageV4 implementation](../internal/model/message_v4.go) already marks its
`status = 2` heuristic inaccurate; transport status no longer overrides sender
identity. Any unfamiliar `sending_direction` source field remains raw evidence
without an invented numeric mapping.

## Retained sender maps and Delta migration

Each message database has its own `Name2Id` row IDs. New v4 raw imports retain
the original, possibly sparse SQLite row ID as `__chatlog_sqlite_rowid` on the
raw `Name2Id` table. That metadata is recorded in `raw_columns_json`; source
column definitions remain unchanged. A source column colliding with the reserved
metadata name is rejected.

Map refresh validates current account/database ownership, source columns, text
usernames, row count, and unique integral row IDs. It reads the retained raw
table and refreshes only that database's map. It never opens a stale staging
path or clears an unchanged shard's mapping because another shard changed.
Legacy raw tables lacking row-ID metadata retain their existing sender map only
when its count, unique row IDs, and usernames agree with the retained raw
`Name2Id` evidence. If that proof is missing or corrupt, Delta fails and requires
a full export; DuckDB physical row IDs are never used as substitutes.

A Delta from an older semantic version reconstructs contacts and legacy v3
direction from retained raw tables and corrects stored v4/phone direction even
when source bytes were unchanged. Source keys and account isolation stay stable.
The copy-on-write export validates the result before replacing the target;
failure leaves its baseline unchanged.

## Focused verification

The qualification tests create in-memory and temporary synthetic databases,
mock SQLite extension loading, and use no live data or credentials:

```powershell
Set-Location -LiteralPath 'G:\workspace\go\chatlog\scripts'
uv run --no-project --offline --with duckdb --with pycryptodome --with pyarrow `
  python -m unittest test_export_wechat_history_delta.RawQualificationTest
```

They cover positive and unknown v3/v4 flags, unqualified Darwin contacts,
conflicting status, unknown senders, hashed account IDs, unchanged semantic
migration, sparse per-database sender IDs, missing staging files, same-second
late messages, and rejection/rollback of corrupt retained-map evidence.

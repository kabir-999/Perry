"""
Column-level encryption for sensitive text columns, via Postgres's pgcrypto
extension (pgp_sym_encrypt/pgp_sym_decrypt).

The encryption/decryption happens inside Postgres itself: SQLAlchemy wraps
the bound parameter and the selected column with the pgcrypto function calls
at the SQL-expression level (`bind_expression`/`column_expression`), so
plaintext is never written to disk — only the ciphertext bytes are. The key
is passed as a bound parameter each time, never interpolated into SQL text.

Requires the `pgcrypto` extension to be enabled (see the
`b5c6d7e8f9a0_scan_event_encryption` migration).
"""
from __future__ import annotations

from sqlalchemy import LargeBinary, func
from sqlalchemy.types import TypeDecorator

from app.config import settings


class EncryptedText(TypeDecorator):
    """A UTF-8 text column stored as pgcrypto ciphertext (bytea) at rest.

    Application code reads/writes this exactly like a normal `str` column —
    the encrypt/decrypt calls are injected transparently into the generated
    SQL for every INSERT/UPDATE/SELECT.
    """

    impl = LargeBinary
    cache_ok = True

    def bind_processor(self, dialect):
        # LargeBinary's own bind_processor wraps every value in the DBAPI's
        # Binary() adapter, which breaks pgp_sym_encrypt(text, text) — it
        # needs the original Python str, untouched; Postgres does the
        # bytes conversion itself. TypeDecorator otherwise chains through
        # the impl's processor regardless of process_bind_param, so this
        # has to be overridden directly, not just process_bind_param.
        return None

    def result_processor(self, dialect, coltype):
        # column_expression() already runs pgp_sym_decrypt server-side and
        # returns text, so the driver hands back a str already — nothing to
        # post-process on the Python side.
        return None

    def bind_expression(self, bindvalue):
        from sqlalchemy import type_coerce, Text
        return func.pgp_sym_encrypt(type_coerce(bindvalue, Text()), settings.LOG_ENCRYPTION_KEY)

    def column_expression(self, col):
        return func.pgp_sym_decrypt(col, settings.LOG_ENCRYPTION_KEY)

"""Persistent storage for audit results and certificates.

Uses aiosqlite for non-blocking SQLite access.  The database holds two
tables — ``certificates`` (signed attestation records) and ``audits``
(raw analysis results) — plus indexes for fast lookups by skill hash
and creation date.

Typical lifecycle::

    store = AuditStore("data/auditskill.db")
    await store.initialize()
    # ... use save/get methods ...
    await store.close()
"""

from __future__ import annotations

import json
import logging
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import aiosqlite

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# SQL constants
# ---------------------------------------------------------------------------

_CREATE_CERTIFICATES = """\
CREATE TABLE IF NOT EXISTS certificates (
    id TEXT PRIMARY KEY,
    skill_hash TEXT NOT NULL,
    skill_name TEXT,
    verdict TEXT NOT NULL,
    score INTEGER NOT NULL,
    certificate_json TEXT NOT NULL,
    signature TEXT NOT NULL,
    created_at TEXT NOT NULL,
    valid_until TEXT NOT NULL
);
"""

_CREATE_AUDITS = """\
CREATE TABLE IF NOT EXISTS audits (
    id TEXT PRIMARY KEY,
    skill_hash TEXT NOT NULL,
    mode TEXT NOT NULL,
    verdict TEXT NOT NULL,
    score INTEGER NOT NULL,
    result_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
"""

_CREATE_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_cert_skill ON certificates(skill_hash);",
    "CREATE INDEX IF NOT EXISTS idx_audit_skill ON audits(skill_hash);",
    "CREATE INDEX IF NOT EXISTS idx_audit_created ON audits(created_at);",
]


def _generate_cert_id() -> str:
    """Return a new certificate ID like ``seal_a1b2c3d4e5f6``."""
    return f"seal_{secrets.token_hex(6)}"


def _generate_audit_id() -> str:
    """Return a new audit ID like ``audit_a1b2c3d4e5f6``."""
    return f"audit_{secrets.token_hex(6)}"


def _row_to_dict(cursor: aiosqlite.Cursor, row: aiosqlite.Row) -> dict[str, Any]:
    """Convert a raw SQLite row into a ``dict`` keyed by column name."""
    columns = [desc[0] for desc in cursor.description]  # type: ignore[union-attr]
    return dict(zip(columns, row))


class AuditStore:
    """Async SQLite store for AuditSkill certificates and audit results.

    Args:
        db_path: Filesystem path to the SQLite database file.  Parent
            directories are created automatically on :meth:`initialize`.
    """

    def __init__(self, db_path: str = "data/auditskill.db") -> None:
        self._db_path = db_path
        self._db: aiosqlite.Connection | None = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def initialize(self) -> None:
        """Open (or create) the database and ensure schema is up to date.

        Creates parent directories for *db_path* if they don't exist.

        Raises:
            OSError: If the directory cannot be created.
            aiosqlite.Error: If the database cannot be opened.
        """
        db_dir = Path(self._db_path).parent
        db_dir.mkdir(parents=True, exist_ok=True)
        logger.info("Opening database at %s", self._db_path)

        self._db = await aiosqlite.connect(self._db_path)
        # Enable WAL for better concurrent-read performance.
        await self._db.execute("PRAGMA journal_mode=WAL;")

        await self._db.execute(_CREATE_CERTIFICATES)
        await self._db.execute(_CREATE_AUDITS)
        for idx_sql in _CREATE_INDEXES:
            await self._db.execute(idx_sql)
        await self._db.commit()
        logger.info("Database schema ready")

    async def close(self) -> None:
        """Close the database connection if open.

        Safe to call multiple times or when the connection was never opened.
        """
        if self._db is not None:
            await self._db.close()
            self._db = None
            logger.info("Database connection closed")

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    @property
    def _conn(self) -> aiosqlite.Connection:
        """Return the live connection, raising if not initialised."""
        if self._db is None:
            raise RuntimeError(
                "AuditStore is not initialised — call await store.initialize() first"
            )
        return self._db

    # ------------------------------------------------------------------
    # Certificates
    # ------------------------------------------------------------------

    async def save_certificate(
        self,
        cert_id: str | None,
        skill_hash: str,
        skill_name: str | None,
        verdict: str,
        score: int,
        cert_json: dict[str, Any] | str,
        signature: str,
        created_at: str,
        valid_until: str,
    ) -> str:
        """Insert a new certificate record.

        Args:
            cert_id: Unique certificate ID.  If *None*, one is generated
                automatically with a ``seal_`` prefix.
            skill_hash: SHA-256 hash of the audited SKILL.md content.
            skill_name: Human-readable skill name (may be ``None``).
            verdict: Outcome string (e.g. ``"pass"``, ``"fail"``).
            score: Numeric score (0–100).
            cert_json: Full certificate payload — accepts a *dict* (will be
                serialised) or a pre-serialised JSON *str*.
            signature: Base64-encoded Ed25519 signature.
            created_at: ISO-8601 creation timestamp.
            valid_until: ISO-8601 expiry timestamp.

        Returns:
            The certificate ID that was stored.

        Raises:
            RuntimeError: If the store has not been initialised.
            aiosqlite.IntegrityError: If *cert_id* already exists.
        """
        if cert_id is None:
            cert_id = _generate_cert_id()

        json_str = cert_json if isinstance(cert_json, str) else json.dumps(cert_json)

        await self._conn.execute(
            """
            INSERT INTO certificates
                (id, skill_hash, skill_name, verdict, score,
                 certificate_json, signature, created_at, valid_until)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                cert_id,
                skill_hash,
                skill_name,
                verdict,
                score,
                json_str,
                signature,
                created_at,
                valid_until,
            ),
        )
        await self._conn.commit()
        logger.debug("Saved certificate %s for skill_hash=%s", cert_id, skill_hash)
        return cert_id

    async def get_certificate(self, cert_id: str) -> dict[str, Any] | None:
        """Retrieve a single certificate by its ID.

        The ``certificate_json`` field is deserialised back into a dict.

        Returns:
            The certificate row as a *dict*, or ``None`` if not found.
        """
        cursor = await self._conn.execute(
            "SELECT * FROM certificates WHERE id = ?",
            (cert_id,),
        )
        row = await cursor.fetchone()
        if row is None:
            return None

        result = _row_to_dict(cursor, row)
        result["certificate_json"] = json.loads(result["certificate_json"])
        return result

    async def get_certificates_by_hash(self, skill_hash: str) -> list[dict[str, Any]]:
        """Return every certificate issued for *skill_hash*.

        Results are ordered newest-first by ``created_at``.

        Args:
            skill_hash: The SHA-256 hash to look up.

        Returns:
            A (possibly empty) list of certificate dicts.
        """
        cursor = await self._conn.execute(
            "SELECT * FROM certificates WHERE skill_hash = ? ORDER BY created_at DESC",
            (skill_hash,),
        )
        rows = await cursor.fetchall()
        results: list[dict[str, Any]] = []
        for row in rows:
            record = _row_to_dict(cursor, row)
            record["certificate_json"] = json.loads(record["certificate_json"])
            results.append(record)
        return results

    # ------------------------------------------------------------------
    # Audits
    # ------------------------------------------------------------------

    async def save_audit(
        self,
        audit_id: str | None,
        skill_hash: str,
        mode: str,
        verdict: str,
        score: int,
        result_json: dict[str, Any] | str,
        created_at: str,
    ) -> str:
        """Insert a new audit result.

        Args:
            audit_id: Unique audit ID.  If *None*, one is generated
                automatically with an ``audit_`` prefix.
            skill_hash: SHA-256 hash of the audited SKILL.md content.
            mode: Audit mode identifier (e.g. ``"structure"``, ``"security"``).
            verdict: Outcome string (e.g. ``"pass"``, ``"fail"``).
            score: Numeric score (0–100).
            result_json: Full result payload — accepts a *dict* or a
                pre-serialised JSON *str*.
            created_at: ISO-8601 creation timestamp.

        Returns:
            The audit ID that was stored.

        Raises:
            RuntimeError: If the store has not been initialised.
            aiosqlite.IntegrityError: If *audit_id* already exists.
        """
        if audit_id is None:
            audit_id = _generate_audit_id()

        json_str = result_json if isinstance(result_json, str) else json.dumps(result_json)

        await self._conn.execute(
            """
            INSERT INTO audits
                (id, skill_hash, mode, verdict, score, result_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (audit_id, skill_hash, mode, verdict, score, json_str, created_at),
        )
        await self._conn.commit()
        logger.debug("Saved audit %s for skill_hash=%s mode=%s", audit_id, skill_hash, mode)
        return audit_id

    async def get_cached_audit(
        self,
        skill_hash: str,
        mode: str,
        max_age_seconds: int = 3600,
    ) -> dict[str, Any] | None:
        """Return the most recent audit for *skill_hash* + *mode* if fresh.

        "Fresh" means the audit's ``created_at`` timestamp is no older than
        *max_age_seconds* relative to the current UTC time.

        Args:
            skill_hash: The SHA-256 hash to look up.
            mode: Audit mode to match.
            max_age_seconds: Maximum acceptable age in seconds (default 1 h).

        Returns:
            The audit row as a *dict* (with ``result_json`` deserialised),
            or ``None`` if no fresh result exists.
        """
        cursor = await self._conn.execute(
            """
            SELECT * FROM audits
            WHERE skill_hash = ? AND mode = ?
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (skill_hash, mode),
        )
        row = await cursor.fetchone()
        if row is None:
            return None

        record = _row_to_dict(cursor, row)

        # Check freshness against UTC now.
        try:
            # Normalise a trailing 'Z' → '+00:00'; datetime.fromisoformat did
            # not accept the 'Z' military-zone suffix before Python 3.11, which
            # would make every cached row unparseable (and the cache useless).
            created_raw = str(record["created_at"])
            if created_raw.endswith("Z"):
                created_raw = created_raw[:-1] + "+00:00"
            created = datetime.fromisoformat(created_raw)
            # Ensure timezone-aware comparison.
            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
            age = (datetime.now(timezone.utc) - created).total_seconds()
            if age > max_age_seconds:
                logger.debug(
                    "Cached audit %s is stale (%.0fs > %ds)",
                    record["id"],
                    age,
                    max_age_seconds,
                )
                return None
        except (ValueError, TypeError) as exc:
            logger.warning("Could not parse created_at for audit %s: %s", record["id"], exc)
            return None

        record["result_json"] = json.loads(record["result_json"])
        return record

"""
Forensic Case Management System for File Signature Analyzer.

Provides secure case lifecycle management with encrypted-at-rest SQLite
databases, evidence tracking, categorization, audit logging, and case
export capabilities suitable for digital forensic workflows.
"""

import base64
import hashlib
import json
import logging
import os
import shutil
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Optional dependency: cryptography (Fernet symmetric encryption)
# ---------------------------------------------------------------------------
try:
    from cryptography.fernet import Fernet, InvalidToken

    _HAS_FERNET = True
except ImportError:
    _HAS_FERNET = False
    Fernet = None  # type: ignore[assignment,misc]
    InvalidToken = Exception  # type: ignore[assignment,misc]

# ---------------------------------------------------------------------------
# Optional dependency: forensic audit logger
# ---------------------------------------------------------------------------
try:
    from core.forensic_logger import ForensicAuditLogger
except ImportError:
    ForensicAuditLogger = None  # type: ignore[assignment,misc]

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
VALID_CATEGORIES: List[str] = [
    "relevant",
    "irrelevant",
    "suspicious",
    "contraband",
    "exculpatory",
    "uncategorized",
]

VALID_CLASSIFICATIONS: List[str] = [
    "UNCLASSIFIED",
    "CONFIDENTIAL",
    "SECRET",
    "TOP SECRET",
    "LAW ENFORCEMENT SENSITIVE",
    "ATTORNEY-CLIENT PRIVILEGED",
]

_PBKDF2_ITERATIONS = 100_000
_SALT_LENGTH = 32

_SCHEMA_SQL = """\
CREATE TABLE IF NOT EXISTS cases (
    case_id TEXT PRIMARY KEY,
    investigator_name TEXT NOT NULL,
    organization TEXT DEFAULT '',
    date_created TEXT NOT NULL,
    date_closed TEXT,
    description TEXT DEFAULT '',
    classification_level TEXT DEFAULT 'UNCLASSIFIED',
    status TEXT DEFAULT 'open'
);

CREATE TABLE IF NOT EXISTS evidence_items (
    evidence_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(case_id),
    file_path TEXT NOT NULL,
    file_name TEXT NOT NULL,
    file_size INTEGER,
    file_type TEXT,
    category TEXT DEFAULT 'uncategorized',
    date_added TEXT NOT NULL,
    hashes TEXT,
    analysis_results TEXT,
    is_quarantined INTEGER DEFAULT 0,
    quarantine_path TEXT
);

CREATE TABLE IF NOT EXISTS evidence_notes (
    note_id TEXT PRIMARY KEY,
    evidence_id TEXT NOT NULL REFERENCES evidence_items(evidence_id),
    case_id TEXT NOT NULL REFERENCES cases(case_id),
    operator_id TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    content TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS case_audit_log (
    log_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(case_id),
    session_id TEXT,
    timestamp TEXT NOT NULL,
    action TEXT NOT NULL,
    details TEXT
);
"""


class CaseManagerError(Exception):
    """Base exception for case management operations."""


class CaseNotOpenError(CaseManagerError):
    """Raised when an operation requires an open case but none is active."""


class CaseAlreadyExistsError(CaseManagerError):
    """Raised when attempting to create a case with a duplicate ID."""


class EncryptionError(CaseManagerError):
    """Raised when an encryption or decryption operation fails."""


class CaseManager:
    """Manages forensic cases with encrypted-at-rest SQLite storage.

    Parameters
    ----------
    cases_root : str or Path
        Root directory for all case data.  Defaults to ``./cases``.
    audit_logger : ForensicAuditLogger or None
        Optional external audit logger for cross-logging events.
    session_id : str or None
        Identifier for the current operator session.
    """

    def __init__(
        self,
        cases_root: str = "cases",
        audit_logger: Any = None,
        session_id: Optional[str] = None,
    ) -> None:
        self._cases_root = Path(cases_root).resolve()
        self._cases_root.mkdir(parents=True, exist_ok=True)

        self._audit_logger = audit_logger
        self._session_id = session_id or str(uuid.uuid4())

        self._lock = threading.Lock()

        # Active case state
        self._conn: Optional[sqlite3.Connection] = None
        self._active_case_id: Optional[str] = None
        self._active_case_dir: Optional[Path] = None
        self._fernet: Optional[Any] = None  # Fernet instance for active case

        self._index_path = self._cases_root / "case_index.json"
        if not self._index_path.exists():
            self._write_index([])

        if not _HAS_FERNET:
            logger.warning(
                "cryptography package not installed. "
                "Case encryption is DISABLED -- databases will be stored in plaintext. "
                "Install with: pip install cryptography"
            )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _utcnow(self) -> str:
        """Return current UTC timestamp in ISO-8601 format."""
        return datetime.now(timezone.utc).isoformat()

    def _derive_key(self, passphrase: str, salt: bytes) -> bytes:
        """Derive a Fernet-compatible key from *passphrase* and *salt*."""
        raw = hashlib.pbkdf2_hmac(
            "sha256",
            passphrase.encode("utf-8"),
            salt,
            _PBKDF2_ITERATIONS,
        )
        return base64.urlsafe_b64encode(raw)

    def _make_fernet(self, passphrase: str, salt: bytes) -> Any:
        """Create a ``Fernet`` instance from a passphrase + salt."""
        if not _HAS_FERNET:
            return None
        key = self._derive_key(passphrase, salt)
        return Fernet(key)

    def _case_dir(self, case_id: str) -> Path:
        return self._cases_root / case_id

    def _db_path(self, case_id: str) -> Path:
        return self._case_dir(case_id) / "case.db"

    def _enc_path(self, case_id: str) -> Path:
        return self._case_dir(case_id) / "case.db.enc"

    def _meta_path(self, case_id: str) -> Path:
        return self._case_dir(case_id) / "case_meta.json"

    def _read_meta(self, case_id: str) -> dict:
        meta_path = self._meta_path(case_id)
        if not meta_path.exists():
            raise CaseManagerError(f"Case metadata not found: {case_id}")
        with open(meta_path, "r", encoding="utf-8") as fh:
            return json.load(fh)

    def _write_meta(self, case_id: str, meta: dict) -> None:
        with open(self._meta_path(case_id), "w", encoding="utf-8") as fh:
            json.dump(meta, fh, indent=2)

    def _read_index(self) -> List[dict]:
        if not self._index_path.exists():
            return []
        with open(self._index_path, "r", encoding="utf-8") as fh:
            return json.load(fh)

    def _write_index(self, index: List[dict]) -> None:
        with open(self._index_path, "w", encoding="utf-8") as fh:
            json.dump(index, fh, indent=2)

    def _update_index_entry(self, case_id: str, **fields: Any) -> None:
        index = self._read_index()
        for entry in index:
            if entry.get("case_id") == case_id:
                entry.update(fields)
                break
        else:
            entry = {"case_id": case_id}
            entry.update(fields)
            index.append(entry)
        self._write_index(index)

    def _remove_index_entry(self, case_id: str) -> None:
        index = self._read_index()
        index = [e for e in index if e.get("case_id") != case_id]
        self._write_index(index)

    def _encrypt_db(self, case_id: str) -> None:
        """Encrypt the plaintext database file and remove the original."""
        if self._fernet is None:
            return  # encryption unavailable or no passphrase
        db_path = self._db_path(case_id)
        enc_path = self._enc_path(case_id)
        if not db_path.exists():
            return
        plaintext = db_path.read_bytes()
        ciphertext = self._fernet.encrypt(plaintext)
        enc_path.write_bytes(ciphertext)
        # Securely remove plaintext DB
        self._secure_delete_file(db_path)

    def _decrypt_db(self, case_id: str) -> None:
        """Decrypt the encrypted database file to plaintext."""
        if self._fernet is None:
            return  # encryption unavailable
        enc_path = self._enc_path(case_id)
        db_path = self._db_path(case_id)
        if not enc_path.exists():
            if db_path.exists():
                logger.info("No encrypted DB found; using plaintext DB.")
                return
            raise CaseManagerError(
                f"Neither encrypted nor plaintext database found for case {case_id}"
            )
        try:
            ciphertext = enc_path.read_bytes()
            plaintext = self._fernet.decrypt(ciphertext)
        except InvalidToken:
            raise EncryptionError(
                "Decryption failed -- incorrect passphrase or corrupted data."
            )
        db_path.write_bytes(plaintext)

    @staticmethod
    def _secure_delete_file(path: Path) -> None:
        """Overwrite a file with zeros before unlinking."""
        if not path.exists():
            return
        length = path.stat().st_size
        with open(path, "wb") as fh:
            fh.write(b"\x00" * length)
            fh.flush()
            os.fsync(fh.fileno())
        path.unlink()

    def _open_connection(self, case_id: str) -> sqlite3.Connection:
        """Open a SQLite connection and ensure schema exists."""
        db_path = self._db_path(case_id)
        conn = sqlite3.connect(str(db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.executescript(_SCHEMA_SQL)
        conn.commit()
        return conn

    def _require_open_case(self) -> None:
        """Raise if no case is currently open."""
        if self._conn is None or self._active_case_id is None:
            raise CaseNotOpenError("No case is currently open.")

    def _log_audit(self, action: str, case_id: Optional[str] = None, details: str = "") -> None:
        """Write to the in-DB audit log and the external audit logger."""
        ts = self._utcnow()
        cid = case_id or self._active_case_id

        # Internal DB log (only if connection is open)
        if self._conn is not None and cid is not None:
            try:
                self._conn.execute(
                    "INSERT INTO case_audit_log (log_id, case_id, session_id, timestamp, action, details) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (str(uuid.uuid4()), cid, self._session_id, ts, action, details),
                )
                self._conn.commit()
            except sqlite3.Error:
                logger.debug("Could not write audit log to DB.", exc_info=True)

        # External audit logger
        if self._audit_logger is not None:
            try:
                self._audit_logger.log(
                    action=action,
                    case_id=cid,
                    session_id=self._session_id,
                    details=details,
                )
            except Exception:
                logger.debug("External audit logger call failed.", exc_info=True)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def create_case(
        self,
        case_id: str,
        investigator_name: str,
        organization: str = "",
        description: str = "",
        classification_level: str = "UNCLASSIFIED",
        passphrase: str = "",
    ) -> dict:
        """Create a new forensic case.

        Parameters
        ----------
        case_id : str
            Unique case identifier (e.g. ``"CASE-2025-0042"``).
        investigator_name : str
            Name of the lead investigator.
        organization : str
            Affiliated organization.
        description : str
            Free-text case description.
        classification_level : str
            One of :data:`VALID_CLASSIFICATIONS`.
        passphrase : str
            Passphrase used to derive the Fernet encryption key.

        Returns
        -------
        dict
            Metadata of the newly created case.

        Raises
        ------
        CaseAlreadyExistsError
            If *case_id* already exists.
        ValueError
            If *classification_level* is invalid.
        """
        if not case_id or not case_id.strip():
            raise ValueError("case_id must be a non-empty string.")
        if not investigator_name or not investigator_name.strip():
            raise ValueError("investigator_name must be a non-empty string.")
        if classification_level not in VALID_CLASSIFICATIONS:
            raise ValueError(
                f"Invalid classification level '{classification_level}'. "
                f"Must be one of {VALID_CLASSIFICATIONS}."
            )

        with self._lock:
            case_dir = self._case_dir(case_id)
            if case_dir.exists():
                raise CaseAlreadyExistsError(f"Case '{case_id}' already exists.")

            # Create directory structure
            case_dir.mkdir(parents=True)
            (case_dir / "evidence_locker").mkdir()
            (case_dir / "exports").mkdir()

            # Generate salt and persist unencrypted metadata
            salt = os.urandom(_SALT_LENGTH)
            now = self._utcnow()
            meta = {
                "case_id": case_id,
                "date_created": now,
                "salt": base64.b64encode(salt).decode("ascii"),
                "encrypted": bool(_HAS_FERNET and passphrase),
            }
            self._write_meta(case_id, meta)

            # Derive encryption key
            if _HAS_FERNET and passphrase:
                self._fernet = self._make_fernet(passphrase, salt)
            else:
                self._fernet = None

            # Open DB, create schema, insert case row
            self._conn = self._open_connection(case_id)
            self._active_case_id = case_id
            self._active_case_dir = case_dir

            self._conn.execute(
                "INSERT INTO cases "
                "(case_id, investigator_name, organization, date_created, "
                "description, classification_level, status) "
                "VALUES (?, ?, ?, ?, ?, ?, 'open')",
                (case_id, investigator_name, organization, now, description, classification_level),
            )
            self._conn.commit()

            self._log_audit("CASE_CREATE", case_id, f"Case created by {investigator_name}")

            # Update global index
            self._update_index_entry(
                case_id,
                investigator_name=investigator_name,
                organization=organization,
                date_created=now,
                classification_level=classification_level,
                status="open",
                encrypted=meta["encrypted"],
            )

            return {
                "case_id": case_id,
                "investigator_name": investigator_name,
                "organization": organization,
                "date_created": now,
                "classification_level": classification_level,
                "status": "open",
                "encrypted": meta["encrypted"],
            }

    def open_case(self, case_id: str, passphrase: str = "") -> dict:
        """Open an existing case, decrypting the database if necessary.

        Parameters
        ----------
        case_id : str
            The case identifier to open.
        passphrase : str
            Passphrase for decryption.

        Returns
        -------
        dict
            Case metadata row from the ``cases`` table.

        Raises
        ------
        CaseManagerError
            If the case directory or metadata is missing.
        EncryptionError
            If decryption fails.
        """
        with self._lock:
            # Close any currently open case first
            if self._active_case_id is not None:
                self._close_case_unlocked()

            case_dir = self._case_dir(case_id)
            if not case_dir.exists():
                raise CaseManagerError(f"Case directory not found: {case_id}")

            meta = self._read_meta(case_id)
            salt = base64.b64decode(meta.get("salt", ""))
            is_encrypted = meta.get("encrypted", False)

            if is_encrypted and _HAS_FERNET:
                if not passphrase:
                    raise EncryptionError("Passphrase required for encrypted case.")
                self._fernet = self._make_fernet(passphrase, salt)
                self._decrypt_db(case_id)
            elif is_encrypted and not _HAS_FERNET:
                raise EncryptionError(
                    "This case is encrypted but the cryptography package is not installed."
                )
            else:
                self._fernet = None

            self._conn = self._open_connection(case_id)
            self._active_case_id = case_id
            self._active_case_dir = case_dir

            self._log_audit("CASE_OPEN", case_id, "Case opened")

            row = self._conn.execute(
                "SELECT * FROM cases WHERE case_id = ?", (case_id,)
            ).fetchone()
            if row is None:
                raise CaseManagerError(f"Case row not found in database for {case_id}")
            return dict(row)

    def close_case(self) -> None:
        """Commit, close the database connection, and encrypt the DB file.

        Safe to call even if no case is open (no-op).
        """
        with self._lock:
            self._close_case_unlocked()

    def _close_case_unlocked(self) -> None:
        """Internal close without acquiring the lock (caller must hold it)."""
        if self._conn is None:
            return

        case_id = self._active_case_id
        self._log_audit("CASE_CLOSE", case_id, "Case closed")

        try:
            self._conn.commit()
        except sqlite3.Error:
            logger.debug("Commit on close failed.", exc_info=True)
        try:
            self._conn.close()
        except sqlite3.Error:
            logger.debug("Connection close failed.", exc_info=True)

        self._conn = None

        if case_id:
            self._encrypt_db(case_id)

        self._active_case_id = None
        self._active_case_dir = None
        self._fernet = None

    def get_active_case(self) -> Optional[dict]:
        """Return the currently active case metadata, or ``None``."""
        with self._lock:
            if self._conn is None or self._active_case_id is None:
                return None
            row = self._conn.execute(
                "SELECT * FROM cases WHERE case_id = ?", (self._active_case_id,)
            ).fetchone()
            return dict(row) if row else None

    # ------------------------------------------------------------------
    # Evidence management
    # ------------------------------------------------------------------

    def add_evidence(
        self,
        file_path: str,
        file_type: str = "",
        file_size: int = 0,
        hashes: Optional[dict] = None,
        analysis_results: Optional[dict] = None,
        category: str = "uncategorized",
    ) -> str:
        """Add an evidence item to the active case.

        Parameters
        ----------
        file_path : str
            Original path of the evidence file.
        file_type : str
            Detected or declared file type.
        file_size : int
            Size in bytes.
        hashes : dict or None
            Dictionary of hash values (e.g. ``{"md5": "...", "sha256": "..."}``).
        analysis_results : dict or None
            Arbitrary analysis output to store as JSON.
        category : str
            One of :data:`VALID_CATEGORIES`.

        Returns
        -------
        str
            The generated ``evidence_id`` (UUID4).
        """
        if category not in VALID_CATEGORIES:
            raise ValueError(
                f"Invalid category '{category}'. Must be one of {VALID_CATEGORIES}."
            )

        with self._lock:
            self._require_open_case()
            assert self._conn is not None  # for type checker
            assert self._active_case_id is not None

            evidence_id = str(uuid.uuid4())
            file_name = os.path.basename(file_path)
            now = self._utcnow()

            self._conn.execute(
                "INSERT INTO evidence_items "
                "(evidence_id, case_id, file_path, file_name, file_size, file_type, "
                "category, date_added, hashes, analysis_results, is_quarantined, quarantine_path) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, NULL)",
                (
                    evidence_id,
                    self._active_case_id,
                    file_path,
                    file_name,
                    file_size,
                    file_type,
                    category,
                    now,
                    json.dumps(hashes) if hashes else None,
                    json.dumps(analysis_results) if analysis_results else None,
                ),
            )
            self._conn.commit()

            self._log_audit(
                "EVIDENCE_ADD",
                details=f"Added evidence {evidence_id}: {file_name} ({category})",
            )
            return evidence_id

    def update_evidence_category(self, evidence_id: str, category: str) -> None:
        """Update the category of an evidence item.

        Parameters
        ----------
        evidence_id : str
            The evidence item to update.
        category : str
            New category value; must be in :data:`VALID_CATEGORIES`.

        Raises
        ------
        ValueError
            If *category* is not a recognised value.
        CaseNotOpenError
            If no case is currently open.
        CaseManagerError
            If the evidence item is not found.
        """
        if category not in VALID_CATEGORIES:
            raise ValueError(
                f"Invalid category '{category}'. Must be one of {VALID_CATEGORIES}."
            )

        with self._lock:
            self._require_open_case()
            assert self._conn is not None

            cursor = self._conn.execute(
                "UPDATE evidence_items SET category = ? WHERE evidence_id = ?",
                (category, evidence_id),
            )
            if cursor.rowcount == 0:
                raise CaseManagerError(f"Evidence item not found: {evidence_id}")
            self._conn.commit()

            self._log_audit(
                "EVIDENCE_UPDATE",
                details=f"Updated category of {evidence_id} to '{category}'",
            )

    def add_note(self, evidence_id: str, content: str, operator_id: str = "") -> str:
        """Attach a timestamped note to an evidence item.

        Parameters
        ----------
        evidence_id : str
            Target evidence item.
        content : str
            Free-text note body.
        operator_id : str
            Identifier of the operator creating the note.

        Returns
        -------
        str
            The generated ``note_id`` (UUID4).
        """
        if not content or not content.strip():
            raise ValueError("Note content must not be empty.")

        with self._lock:
            self._require_open_case()
            assert self._conn is not None
            assert self._active_case_id is not None

            # Validate evidence exists
            row = self._conn.execute(
                "SELECT evidence_id FROM evidence_items WHERE evidence_id = ?",
                (evidence_id,),
            ).fetchone()
            if row is None:
                raise CaseManagerError(f"Evidence item not found: {evidence_id}")

            note_id = str(uuid.uuid4())
            now = self._utcnow()

            self._conn.execute(
                "INSERT INTO evidence_notes "
                "(note_id, evidence_id, case_id, operator_id, timestamp, content) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (note_id, evidence_id, self._active_case_id, operator_id, now, content),
            )
            self._conn.commit()

            self._log_audit(
                "NOTE_ADD",
                details=f"Note {note_id} added to evidence {evidence_id}",
            )
            return note_id

    def get_evidence_list(
        self,
        case_id: Optional[str] = None,
        category: Optional[str] = None,
    ) -> List[dict]:
        """Retrieve evidence items, optionally filtered by case or category.

        Parameters
        ----------
        case_id : str or None
            Filter by case; defaults to the active case.
        category : str or None
            Filter by category.

        Returns
        -------
        list[dict]
        """
        with self._lock:
            self._require_open_case()
            assert self._conn is not None

            target_case = case_id or self._active_case_id
            params: list = [target_case]
            query = "SELECT * FROM evidence_items WHERE case_id = ?"
            if category is not None:
                if category not in VALID_CATEGORIES:
                    raise ValueError(
                        f"Invalid category '{category}'. Must be one of {VALID_CATEGORIES}."
                    )
                query += " AND category = ?"
                params.append(category)
            query += " ORDER BY date_added ASC"

            rows = self._conn.execute(query, params).fetchall()
            results = []
            for r in rows:
                d = dict(r)
                # Deserialise JSON fields
                if d.get("hashes"):
                    try:
                        d["hashes"] = json.loads(d["hashes"])
                    except (json.JSONDecodeError, TypeError):
                        pass
                if d.get("analysis_results"):
                    try:
                        d["analysis_results"] = json.loads(d["analysis_results"])
                    except (json.JSONDecodeError, TypeError):
                        pass
                results.append(d)
            return results

    def get_evidence_notes(self, evidence_id: str) -> List[dict]:
        """Return all notes attached to an evidence item.

        Parameters
        ----------
        evidence_id : str

        Returns
        -------
        list[dict]
        """
        with self._lock:
            self._require_open_case()
            assert self._conn is not None

            rows = self._conn.execute(
                "SELECT * FROM evidence_notes WHERE evidence_id = ? ORDER BY timestamp ASC",
                (evidence_id,),
            ).fetchall()
            return [dict(r) for r in rows]

    def get_evidence_by_hash(self, sha256_hash: str) -> Optional[dict]:
        """Look up an evidence item by its SHA-256 hash.

        The hash is searched inside the JSON ``hashes`` column using a
        ``LIKE`` match on the SHA-256 value.

        Parameters
        ----------
        sha256_hash : str

        Returns
        -------
        dict or None
        """
        if not sha256_hash:
            return None

        with self._lock:
            self._require_open_case()
            assert self._conn is not None

            # Use LIKE to search within the JSON-encoded hashes field
            rows = self._conn.execute(
                "SELECT * FROM evidence_items WHERE hashes LIKE ?",
                (f"%{sha256_hash}%",),
            ).fetchall()

            for r in rows:
                d = dict(r)
                try:
                    h = json.loads(d.get("hashes", "{}") or "{}")
                except (json.JSONDecodeError, TypeError):
                    continue
                if h.get("sha256") == sha256_hash:
                    d["hashes"] = h
                    if d.get("analysis_results"):
                        try:
                            d["analysis_results"] = json.loads(d["analysis_results"])
                        except (json.JSONDecodeError, TypeError):
                            pass
                    return d
            return None

    # ------------------------------------------------------------------
    # Export / listing / deletion
    # ------------------------------------------------------------------

    def export_case(self, output_dir: str, include_files: bool = False) -> str:
        """Export the active case as a JSON package.

        Parameters
        ----------
        output_dir : str
            Directory to write the export package into.
        include_files : bool
            If ``True``, copy evidence files into the export directory.

        Returns
        -------
        str
            Path to the exported JSON file.
        """
        with self._lock:
            self._require_open_case()
            assert self._conn is not None
            assert self._active_case_id is not None

            out = Path(output_dir).resolve()
            out.mkdir(parents=True, exist_ok=True)

            case_row = self._conn.execute(
                "SELECT * FROM cases WHERE case_id = ?", (self._active_case_id,)
            ).fetchone()
            evidence_rows = self._conn.execute(
                "SELECT * FROM evidence_items WHERE case_id = ? ORDER BY date_added",
                (self._active_case_id,),
            ).fetchall()
            note_rows = self._conn.execute(
                "SELECT * FROM evidence_notes WHERE case_id = ? ORDER BY timestamp",
                (self._active_case_id,),
            ).fetchall()
            audit_rows = self._conn.execute(
                "SELECT * FROM case_audit_log WHERE case_id = ? ORDER BY timestamp",
                (self._active_case_id,),
            ).fetchall()

            def _deserialise(row_dict: dict) -> dict:
                for field in ("hashes", "analysis_results"):
                    if row_dict.get(field):
                        try:
                            row_dict[field] = json.loads(row_dict[field])
                        except (json.JSONDecodeError, TypeError):
                            pass
                return row_dict

            package = {
                "export_timestamp": self._utcnow(),
                "case": dict(case_row) if case_row else {},
                "evidence_items": [_deserialise(dict(r)) for r in evidence_rows],
                "evidence_notes": [dict(r) for r in note_rows],
                "audit_log": [dict(r) for r in audit_rows],
            }

            export_file = out / f"{self._active_case_id}_export.json"
            with open(export_file, "w", encoding="utf-8") as fh:
                json.dump(package, fh, indent=2, default=str)

            if include_files and self._active_case_dir is not None:
                files_dir = out / "evidence_files"
                files_dir.mkdir(exist_ok=True)
                for ev in evidence_rows:
                    src = Path(dict(ev)["file_path"])
                    if src.exists():
                        shutil.copy2(str(src), str(files_dir / src.name))

            self._log_audit(
                "CASE_EXPORT",
                details=f"Exported to {export_file}",
            )
            return str(export_file)

    def list_cases(self) -> List[dict]:
        """Return a list of all cases from the global index file.

        Returns
        -------
        list[dict]
        """
        with self._lock:
            return self._read_index()

    def delete_case(self, case_id: str, passphrase: str = "") -> None:
        """Permanently delete a case and all associated data.

        If the case is encrypted the correct *passphrase* must be
        provided to authorise deletion.

        Parameters
        ----------
        case_id : str
            The case to delete.
        passphrase : str
            Passphrase for verification (must match original if encrypted).

        Raises
        ------
        CaseManagerError
            If the case does not exist or passphrase verification fails.
        """
        with self._lock:
            case_dir = self._case_dir(case_id)
            if not case_dir.exists():
                raise CaseManagerError(f"Case not found: {case_id}")

            meta = self._read_meta(case_id)
            is_encrypted = meta.get("encrypted", False)

            # Verify passphrase by attempting decryption of a test token
            if is_encrypted and _HAS_FERNET:
                if not passphrase:
                    raise EncryptionError(
                        "Passphrase required to delete an encrypted case."
                    )
                salt = base64.b64decode(meta.get("salt", ""))
                fernet = self._make_fernet(passphrase, salt)
                enc_path = self._enc_path(case_id)
                if enc_path.exists():
                    try:
                        fernet.decrypt(enc_path.read_bytes())
                    except InvalidToken:
                        raise EncryptionError(
                            "Incorrect passphrase -- deletion denied."
                        )

            # If this case is currently open, close it first (without re-encrypting)
            if self._active_case_id == case_id:
                if self._conn is not None:
                    try:
                        self._conn.close()
                    except sqlite3.Error:
                        pass
                    self._conn = None
                self._active_case_id = None
                self._active_case_dir = None
                self._fernet = None

            # Securely remove all files
            for root, dirs, files in os.walk(str(case_dir), topdown=False):
                for fname in files:
                    self._secure_delete_file(Path(root) / fname)
                for dname in dirs:
                    Path(root, dname).rmdir()
            case_dir.rmdir()

            self._remove_index_entry(case_id)

            # External audit log (DB log is gone with the case)
            if self._audit_logger is not None:
                try:
                    self._audit_logger.log(
                        action="CASE_DELETE",
                        case_id=case_id,
                        session_id=self._session_id,
                        details=f"Case {case_id} permanently deleted",
                    )
                except Exception:
                    logger.debug("External audit logger call failed.", exc_info=True)

    # ------------------------------------------------------------------
    # Context manager support
    # ------------------------------------------------------------------

    def __enter__(self) -> "CaseManager":
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close_case()

    def __del__(self) -> None:
        try:
            self.close_case()
        except Exception:
            pass

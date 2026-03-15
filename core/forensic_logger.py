"""
Tamper-evident forensic audit logger for the File Signature Analyzer.

Provides a blockchain-style chained-hash audit trail suitable for
court-admissible digital forensic evidence.  Every log entry is
cryptographically linked to its predecessor so that any retroactive
modification, insertion, or deletion is detectable.

Design goals
------------
* Zero external dependencies -- only the Python standard library.
* Thread-safe for concurrent analysis pipelines.
* Crash-resilient -- a partial last line written during an unclean
  shutdown is detected, reported, and skipped on the next read.
* Export to JSON and styled HTML for reporting / court submission.

Usage
-----
>>> logger = ForensicAuditLogger(log_dir="./audit_logs")
>>> logger.start_session(operator_id="analyst-1")
>>> logger.log(ActionType.FILE_OPEN, file_path="/evidence/img001.dd")
>>> ok, last_ok, err = logger.verify_chain_integrity()
>>> logger.end_session()
"""

from __future__ import annotations

import enum
import hashlib
import html as html_mod
import json
import os
import shutil
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_GENESIS_SEED = "FORENSIC_AUDIT_GENESIS"
GENESIS_HASH: str = hashlib.sha256(_GENESIS_SEED.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Action type enumeration
# ---------------------------------------------------------------------------

class ActionType(enum.Enum):
    """Controlled vocabulary for auditable actions."""

    SESSION_START = "SESSION_START"
    SESSION_END = "SESSION_END"
    FILE_OPEN = "FILE_OPEN"
    ANALYSIS_START = "ANALYSIS_START"
    ANALYSIS_END = "ANALYSIS_END"
    HASH_COMPUTE = "HASH_COMPUTE"
    EXPORT = "EXPORT"
    CASE_OPEN = "CASE_OPEN"
    CASE_CLOSE = "CASE_CLOSE"
    EVIDENCE_ADD = "EVIDENCE_ADD"
    EVIDENCE_CATEGORIZE = "EVIDENCE_CATEGORIZE"
    INTEGRITY_CHECK = "INTEGRITY_CHECK"
    INTEGRITY_VIOLATION = "INTEGRITY_VIOLATION"
    SAFETY_FLAG = "SAFETY_FLAG"
    SAFETY_QUARANTINE = "SAFETY_QUARANTINE"
    NOTE_ADD = "NOTE_ADD"
    CERTIFICATE_GENERATE = "CERTIFICATE_GENERATE"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _canonical_json(obj: Any) -> str:
    """Return a deterministic JSON string (sorted keys, no extra whitespace)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _compute_entry_hash(previous_hash: str, entry: Dict[str, Any]) -> str:
    """Compute the SHA-256 chain hash for *entry*.

    The hash covers ``previous_hash`` concatenated with the canonical
    JSON serialisation of the entry **without** the ``entry_hash`` field.
    """
    entry_copy = {k: v for k, v in entry.items() if k != "entry_hash"}
    payload = previous_hash + _canonical_json(entry_copy)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _utc_now_iso() -> str:
    """Return the current UTC time as ISO 8601 with microsecond precision."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


# ---------------------------------------------------------------------------
# Main logger class
# ---------------------------------------------------------------------------

class ForensicAuditLogger:
    """Tamper-evident, chain-hashed forensic audit logger.

    Parameters
    ----------
    log_dir : str or Path
        Directory where session log files are stored.  Created
        automatically if it does not exist.
    """

    def __init__(self, log_dir: str | Path = "./audit_logs") -> None:
        self._log_dir = Path(log_dir)
        self._log_dir.mkdir(parents=True, exist_ok=True)

        self._lock = threading.Lock()

        # Session state (populated by start_session)
        self._session_id: Optional[str] = None
        self._operator_id: Optional[str] = None
        self._log_file_path: Optional[Path] = None
        self._log_file_handle = None
        self._entry_counter: int = 0
        self._previous_hash: str = GENESIS_HASH
        self._entries: List[Dict[str, Any]] = []

    # -- properties ----------------------------------------------------------

    @property
    def session_id(self) -> Optional[str]:
        """Currently active session ID, or ``None``."""
        return self._session_id

    @property
    def log_dir(self) -> Path:
        return self._log_dir

    @property
    def log_file_path(self) -> Optional[Path]:
        """Path to the current session's JSONL log file."""
        return self._log_file_path

    # -- session lifecycle ---------------------------------------------------

    def start_session(self, operator_id: str) -> str:
        """Begin a new audit session.

        Parameters
        ----------
        operator_id : str
            Identifier of the human operator (badge number, username, etc.).

        Returns
        -------
        str
            The newly generated UUID4 session ID.

        Raises
        ------
        RuntimeError
            If a session is already active.
        """
        with self._lock:
            if self._session_id is not None:
                raise RuntimeError(
                    f"Session {self._session_id} is already active. "
                    "Call end_session() before starting a new one."
                )

            self._session_id = str(uuid.uuid4())
            self._operator_id = operator_id
            self._entry_counter = 0
            self._previous_hash = GENESIS_HASH
            self._entries = []

            date_str = datetime.now(timezone.utc).strftime("%Y%m%d")
            filename = f"session_{self._session_id}_{date_str}.jsonl"
            self._log_file_path = self._log_dir / filename
            self._log_file_handle = open(  # noqa: SIM115
                self._log_file_path, "a", encoding="utf-8"
            )

        # Log the session-start event (outside the lock -- log() acquires it)
        self.log(
            action_type=ActionType.SESSION_START,
            result_summary=f"Session started by {operator_id}",
        )

        return self._session_id

    def end_session(self) -> None:
        """Finalise and close the current session.

        Raises
        ------
        RuntimeError
            If no session is active.
        """
        if self._session_id is None:
            raise RuntimeError("No active session to end.")

        self.log(
            action_type=ActionType.SESSION_END,
            result_summary="Session ended normally",
        )

        with self._lock:
            if self._log_file_handle is not None:
                self._log_file_handle.flush()
                self._log_file_handle.close()
                self._log_file_handle = None

            self._session_id = None
            self._operator_id = None
            self._log_file_path = None

    # -- core logging --------------------------------------------------------

    def log(
        self,
        action_type: ActionType,
        file_path: Optional[str] = None,
        file_hash_before: Optional[str] = None,
        file_hash_after: Optional[str] = None,
        result_summary: Optional[str] = None,
        additional_data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Append a tamper-evident entry to the audit log.

        Parameters
        ----------
        action_type : ActionType
            The action being recorded.
        file_path : str, optional
            Filesystem path of the subject file (if applicable).
        file_hash_before : str, optional
            Hash of the file before the action (if applicable).
        file_hash_after : str, optional
            Hash of the file after the action (if applicable).
        result_summary : str, optional
            Human-readable summary of the outcome.
        additional_data : dict, optional
            Arbitrary extra metadata to attach.

        Returns
        -------
        dict
            The complete log entry including its chain hash.

        Raises
        ------
        RuntimeError
            If no session is active.
        """
        with self._lock:
            if self._session_id is None:
                raise RuntimeError(
                    "Cannot log without an active session. "
                    "Call start_session() first."
                )

            self._entry_counter += 1

            entry: Dict[str, Any] = {
                "entry_id": self._entry_counter,
                "timestamp": _utc_now_iso(),
                "session_id": self._session_id,
                "operator_id": self._operator_id,
                "action_type": action_type.value,
                "file_path": file_path,
                "file_hash_before": file_hash_before,
                "file_hash_after": file_hash_after,
                "result_summary": result_summary,
                "additional_data": additional_data if additional_data else {},
                "previous_hash": self._previous_hash,
                "entry_hash": "",  # placeholder -- computed below
            }

            entry_hash = _compute_entry_hash(self._previous_hash, entry)
            entry["entry_hash"] = entry_hash
            self._previous_hash = entry_hash

            self._entries.append(entry)

            # Persist immediately
            if self._log_file_handle is not None:
                line = _canonical_json(entry) + "\n"
                self._log_file_handle.write(line)
                self._log_file_handle.flush()

        return entry

    # -- querying ------------------------------------------------------------

    def get_session_entries(self) -> List[Dict[str, Any]]:
        """Return a copy of all log entries for the current session.

        Returns
        -------
        list of dict
            Shallow copies of every entry logged in the active session.

        Raises
        ------
        RuntimeError
            If no session is active.
        """
        with self._lock:
            if self._session_id is None:
                raise RuntimeError("No active session.")
            return [dict(e) for e in self._entries]

    # -- chain verification --------------------------------------------------

    def verify_chain_integrity(
        self,
        log_file_path: Optional[str | Path] = None,
    ) -> Tuple[bool, int, Optional[str]]:
        """Replay and verify the chained-hash integrity of a log file.

        Parameters
        ----------
        log_file_path : str or Path, optional
            Path to a ``.jsonl`` session log.  Defaults to the current
            session's log file.

        Returns
        -------
        tuple (is_valid, last_valid_entry_id, error_message)
            *is_valid* is ``True`` when the entire chain is intact.
            *last_valid_entry_id* is the ``entry_id`` of the last
            verified entry (``0`` if the file is empty or the very
            first entry is invalid).
            *error_message* is ``None`` when valid, otherwise a
            human-readable description of the first violation found.
        """
        path = Path(log_file_path) if log_file_path else self._log_file_path
        if path is None:
            return (False, 0, "No log file path provided and no active session.")

        if not path.exists():
            return (False, 0, f"Log file does not exist: {path}")

        previous_hash = GENESIS_HASH
        last_valid_id = 0

        with open(path, "r", encoding="utf-8") as fh:
            for line_no, raw_line in enumerate(fh, start=1):
                raw_line = raw_line.strip()
                if not raw_line:
                    continue

                # -- crash recovery: detect corrupt trailing line ------------
                try:
                    entry = json.loads(raw_line)
                except json.JSONDecodeError:
                    # If this is the very last line it may be a crash
                    # artifact.  Peek ahead to decide.
                    remaining = fh.read().strip()
                    if remaining:
                        return (
                            False,
                            last_valid_id,
                            f"Corrupt entry at line {line_no} "
                            "(not the last line -- data may be tampered).",
                        )
                    # Last line is corrupt -- treat as crash recovery.
                    return (
                        True,
                        last_valid_id,
                        f"WARNING: Corrupt trailing line {line_no} skipped "
                        "(likely crash during write).",
                    )

                stored_hash = entry.get("entry_hash", "")
                expected_hash = _compute_entry_hash(previous_hash, entry)

                if stored_hash != expected_hash:
                    return (
                        False,
                        last_valid_id,
                        f"Hash mismatch at entry_id {entry.get('entry_id')} "
                        f"(line {line_no}). Expected {expected_hash}, "
                        f"got {stored_hash}.",
                    )

                if entry.get("previous_hash") != previous_hash:
                    return (
                        False,
                        last_valid_id,
                        f"Previous-hash link broken at entry_id "
                        f"{entry.get('entry_id')} (line {line_no}).",
                    )

                previous_hash = stored_hash
                last_valid_id = entry.get("entry_id", last_valid_id)

        return (True, last_valid_id, None)

    # -- export --------------------------------------------------------------

    def export_as_json(self, output_path: str | Path) -> None:
        """Export the current session's entries as a pretty-printed JSON file.

        Parameters
        ----------
        output_path : str or Path
            Destination file path.

        Raises
        ------
        RuntimeError
            If no session is active.
        """
        entries = self.get_session_entries()
        with open(output_path, "w", encoding="utf-8") as fh:
            json.dump(entries, fh, indent=2, ensure_ascii=False)

    def export_as_html(self, output_path: str | Path) -> None:
        """Export the current session as a styled HTML report.

        The report includes a header with session metadata, a table of
        every audit entry, the chain-integrity verification result, and
        a generation timestamp footer.

        Parameters
        ----------
        output_path : str or Path
            Destination file path.

        Raises
        ------
        RuntimeError
            If no session is active.
        """
        entries = self.get_session_entries()
        if not entries:
            raise RuntimeError("No entries to export.")

        is_valid, last_ok, err_msg = self.verify_chain_integrity()

        session_id = entries[0]["session_id"]
        operator = entries[0]["operator_id"]
        first_ts = entries[0]["timestamp"]
        last_ts = entries[-1]["timestamp"]

        integrity_class = "pass" if is_valid else "fail"
        integrity_text = "PASSED" if is_valid else "FAILED"
        integrity_detail = err_msg if err_msg else "All entries verified."

        # Build table rows
        rows_html = []
        columns = [
            "entry_id", "timestamp", "action_type", "file_path",
            "file_hash_before", "file_hash_after", "result_summary",
            "entry_hash",
        ]
        for entry in entries:
            cells = "".join(
                f"<td>{html_mod.escape(str(entry.get(c, '') or ''))}</td>"
                for c in columns
            )
            rows_html.append(f"<tr>{cells}</tr>")

        header_cells = "".join(f"<th>{html_mod.escape(c)}</th>" for c in columns)
        generation_ts = _utc_now_iso()

        page = f"""\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Forensic Audit Report &mdash; {html_mod.escape(session_id)}</title>
<style>
  :root {{
    --bg: #fdfdfd; --fg: #1a1a1a; --accent: #003366;
    --border: #bbb; --header-bg: #003366; --header-fg: #fff;
    --pass: #14612e; --fail: #991b1b;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: "Segoe UI", Arial, Helvetica, sans-serif;
         background: var(--bg); color: var(--fg); padding: 24px; }}
  h1 {{ color: var(--accent); margin-bottom: 4px; font-size: 1.5rem; }}
  .subtitle {{ color: #555; margin-bottom: 20px; font-size: 0.9rem; }}
  .meta {{ margin-bottom: 20px; line-height: 1.8; }}
  .meta span {{ font-weight: 600; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.8rem;
           margin-bottom: 24px; }}
  th {{ background: var(--header-bg); color: var(--header-fg);
       padding: 8px 6px; text-align: left; white-space: nowrap; }}
  td {{ border-bottom: 1px solid var(--border); padding: 6px;
       word-break: break-all; }}
  tr:nth-child(even) {{ background: #f4f6f8; }}
  .integrity {{ padding: 12px 16px; border-radius: 4px; margin-bottom: 20px;
                font-weight: 600; }}
  .integrity.pass {{ background: #d4edda; color: var(--pass); }}
  .integrity.fail {{ background: #f8d7da; color: var(--fail); }}
  .integrity .detail {{ font-weight: 400; font-size: 0.85rem; display: block;
                        margin-top: 4px; }}
  footer {{ border-top: 1px solid var(--border); padding-top: 12px;
           font-size: 0.8rem; color: #666; }}
</style>
</head>
<body>
<h1>Forensic Audit Report</h1>
<p class="subtitle">File Signature Analyzer &mdash; Tamper-Evident Audit Trail</p>

<div class="meta">
  <span>Session ID:</span> {html_mod.escape(session_id)}<br>
  <span>Operator:</span> {html_mod.escape(operator)}<br>
  <span>Session start:</span> {html_mod.escape(first_ts)}<br>
  <span>Session end:</span> {html_mod.escape(last_ts)}<br>
  <span>Total entries:</span> {len(entries)}
</div>

<div class="integrity {integrity_class}">
  Chain Integrity Verification: {integrity_text}
  <span class="detail">{html_mod.escape(integrity_detail)}</span>
</div>

<table>
<thead><tr>{header_cells}</tr></thead>
<tbody>
{"".join(rows_html)}
</tbody>
</table>

<footer>
  Report generated at {html_mod.escape(generation_ts)} UTC.
  This document was produced automatically by the File Signature Analyzer
  forensic audit subsystem.  The chain-integrity status above reflects
  verification performed at generation time.
</footer>
</body>
</html>
"""
        with open(output_path, "w", encoding="utf-8") as fh:
            fh.write(page)

    # -- log rotation --------------------------------------------------------

    def rotate_log(self, max_size_mb: float = 50) -> Optional[Path]:
        """Rotate the current log file if it exceeds *max_size_mb*.

        The active file is renamed with a ``.rotated.<timestamp>`` suffix
        and a fresh file is opened.  The chain continues unbroken in the
        new file (the first entry carries the last ``previous_hash``).

        Parameters
        ----------
        max_size_mb : float
            Maximum file size in megabytes before rotation triggers.

        Returns
        -------
        Path or None
            Path to the rotated (archived) file, or ``None`` if rotation
            was not needed.

        Raises
        ------
        RuntimeError
            If no session is active.
        """
        with self._lock:
            if self._log_file_path is None or self._log_file_handle is None:
                raise RuntimeError("No active session to rotate.")

            try:
                current_size = self._log_file_path.stat().st_size
            except OSError:
                return None

            if current_size < max_size_mb * 1024 * 1024:
                return None

            # Close the current file
            self._log_file_handle.flush()
            self._log_file_handle.close()

            # Rename with rotation timestamp
            ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
            rotated = self._log_file_path.with_suffix(f".rotated.{ts}.jsonl")
            shutil.move(str(self._log_file_path), str(rotated))

            # Open a new file (same path) and continue the chain
            self._log_file_handle = open(  # noqa: SIM115
                self._log_file_path, "a", encoding="utf-8"
            )

            return rotated

    # -- context manager -----------------------------------------------------

    def __enter__(self) -> "ForensicAuditLogger":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:  # noqa: ANN001
        with self._lock:
            if self._log_file_handle is not None:
                self._log_file_handle.flush()
                self._log_file_handle.close()
                self._log_file_handle = None

    # -- repr ----------------------------------------------------------------

    def __repr__(self) -> str:
        state = "active" if self._session_id else "idle"
        return (
            f"<ForensicAuditLogger log_dir={self._log_dir!r} "
            f"state={state} session={self._session_id}>"
        )

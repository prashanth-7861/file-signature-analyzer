"""
Evidence Integrity Verification System.

Provides cryptographic hash verification, chain-of-custody tracking,
evidence quarantine, and integrity certificate generation for forensic
file analysis workflows. All file access is strictly read-only.
"""

import hashlib
import json
import os
import shutil
import threading
from datetime import datetime, timezone
from pathlib import Path

try:
    from core.forensic_logger import ForensicAuditLogger
except ImportError:
    ForensicAuditLogger = None


class EvidenceIntegrityVerifier:
    """Forensic evidence integrity verification and chain-of-custody tracker.

    Computes multi-algorithm cryptographic hashes in a single pass,
    verifies that files are not modified during analysis, generates
    court-ready integrity certificates, and manages an evidence quarantine
    locker.  All operations are thread-safe and strictly read-only with
    respect to the evidence files themselves.

    Attributes:
        hash_algorithms: List of hashlib algorithm names to compute.
        evidence_locker_path: Directory used for quarantined evidence copies.
        audit_logger: Optional ForensicAuditLogger for structured audit logs.
        integrity_records: Mapping of file paths to their integrity records.
    """

    CHUNK_SIZE = 8192

    def __init__(
        self,
        hash_algorithms=None,
        evidence_locker_path=None,
        audit_logger=None,
    ):
        """Initialise the verifier.

        Args:
            hash_algorithms: Hash algorithms to compute.  Defaults to
                ``["md5", "sha1", "sha256", "sha512"]``.
            evidence_locker_path: Filesystem path for the quarantine locker.
                Defaults to ``./evidence_locker``.
            audit_logger: Optional ``ForensicAuditLogger`` instance.
        """
        self.hash_algorithms = list(hash_algorithms or ["md5", "sha1", "sha256", "sha512"])
        self.evidence_locker_path = Path(evidence_locker_path or "evidence_locker")
        self.audit_logger = audit_logger
        self.integrity_records: dict = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _log(self, action: str, details: dict) -> None:
        """Write an entry to the audit logger if one is configured."""
        if self.audit_logger is not None:
            try:
                self.audit_logger.log_action(action, details)
            except Exception:
                # Logging must never interrupt evidence operations.
                pass

    @staticmethod
    def _iso_now() -> str:
        """Return the current UTC time as an ISO 8601 string."""
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _canonical_path(file_path) -> str:
        """Return the resolved, absolute string representation of *file_path*."""
        return str(Path(file_path).resolve())

    # ------------------------------------------------------------------
    # Multi-algorithm hashing (single pass)
    # ------------------------------------------------------------------

    def compute_hashes(self, file_path, algorithms=None) -> dict:
        """Compute multiple cryptographic hashes of a file in one pass.

        The file is read once in ``CHUNK_SIZE``-byte chunks and each chunk
        is fed to every requested hash object simultaneously.

        Args:
            file_path: Path to the file to hash.
            algorithms: Sequence of hashlib algorithm names.  Defaults to
                ``self.hash_algorithms``.

        Returns:
            Dictionary mapping algorithm name to its hex-digest string.

        Raises:
            FileNotFoundError: If *file_path* does not exist.
            OSError: On read errors.
        """
        algorithms = algorithms or self.hash_algorithms
        hashers = {alg: hashlib.new(alg) for alg in algorithms}

        with open(file_path, "rb") as fh:
            while True:
                chunk = fh.read(self.CHUNK_SIZE)
                if not chunk:
                    break
                for h in hashers.values():
                    h.update(chunk)

        return {alg: h.hexdigest() for alg, h in hashers.items()}

    # ------------------------------------------------------------------
    # Pre / Post analysis verification
    # ------------------------------------------------------------------

    def pre_analysis_check(self, file_path) -> dict:
        """Record the integrity baseline for *file_path* before analysis.

        Computes all configured hashes, stores an integrity record keyed
        by the canonical file path, and logs a ``PRE_ANALYSIS_CHECK``
        action.

        Args:
            file_path: Path to the evidence file.

        Returns:
            The integrity record dictionary.
        """
        canonical = self._canonical_path(file_path)
        file_size = os.path.getsize(canonical)
        hashes = self.compute_hashes(canonical)
        now = self._iso_now()

        record = {
            "file_path": canonical,
            "file_size": file_size,
            "hashes_before": hashes,
            "hashes_after": None,
            "verified": False,
            "verification_time": now,
            "status": "pending",
        }

        with self._lock:
            self.integrity_records[canonical] = record

        self._log("PRE_ANALYSIS_CHECK", {
            "file_path": canonical,
            "file_size": file_size,
            "hashes": hashes,
            "timestamp": now,
        })

        return dict(record)

    def post_analysis_check(self, file_path):
        """Verify that *file_path* was not modified during analysis.

        Computes current hashes and compares them against the baseline
        recorded by :meth:`pre_analysis_check`.  If any hash differs the
        record is marked as ``"modified"`` and an ``INTEGRITY_VIOLATION``
        action is logged.

        Args:
            file_path: Path to the evidence file.

        Returns:
            Tuple of ``(integrity_ok, record)`` where *integrity_ok* is
            ``True`` when all hashes match.

        Raises:
            ValueError: If no pre-analysis record exists for this file.
        """
        canonical = self._canonical_path(file_path)

        with self._lock:
            record = self.integrity_records.get(canonical)
            if record is None:
                raise ValueError(
                    f"No pre-analysis record found for: {canonical}"
                )

        hashes_after = self.compute_hashes(canonical)
        now = self._iso_now()

        integrity_ok = hashes_after == record["hashes_before"]
        status = "verified" if integrity_ok else "modified"

        with self._lock:
            record["hashes_after"] = hashes_after
            record["verified"] = integrity_ok
            record["verification_time"] = now
            record["status"] = status

        if integrity_ok:
            self._log("POST_ANALYSIS_CHECK", {
                "file_path": canonical,
                "status": status,
                "timestamp": now,
            })
        else:
            self._log("INTEGRITY_VIOLATION", {
                "file_path": canonical,
                "status": status,
                "hashes_before": record["hashes_before"],
                "hashes_after": hashes_after,
                "timestamp": now,
            })

        return integrity_ok, dict(record)

    # ------------------------------------------------------------------
    # Integrity certificate generation
    # ------------------------------------------------------------------

    def generate_integrity_certificate(
        self, file_path, output_path, format="json"
    ) -> None:
        """Generate a formal integrity certificate for *file_path*.

        The certificate includes all computed hashes, file metadata,
        timestamps, and operator information.  It is suitable for
        inclusion in forensic reports or court submissions.

        Args:
            file_path: Path to the evidence file.
            output_path: Destination path for the certificate.
            format: ``"json"`` or ``"html"``.

        Raises:
            ValueError: If the format is unsupported or no integrity
                record exists.
        """
        canonical = self._canonical_path(file_path)

        with self._lock:
            record = self.integrity_records.get(canonical)

        hashes = (
            record["hashes_before"] if record else self.compute_hashes(canonical)
        )
        file_size = os.path.getsize(canonical)
        now = self._iso_now()

        certificate = {
            "certificate_type": "Evidence Integrity Certificate",
            "certificate_id": hashlib.sha256(
                f"{canonical}{now}".encode()
            ).hexdigest()[:16],
            "generated_at": now,
            "file": {
                "path": canonical,
                "name": os.path.basename(canonical),
                "size_bytes": file_size,
            },
            "hashes": hashes,
            "verification": {
                "status": record["status"] if record else "unverified",
                "verified": record["verified"] if record else False,
                "verification_time": record["verification_time"] if record else None,
            },
            "chain_of_custody": {
                "operator": os.environ.get("USERNAME", os.environ.get("USER", "unknown")),
                "hostname": os.environ.get("COMPUTERNAME", os.environ.get("HOSTNAME", "unknown")),
                "certificate_generated": now,
            },
        }

        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)

        if format == "json":
            with open(output, "w", encoding="utf-8") as fh:
                json.dump(certificate, fh, indent=2, ensure_ascii=False)
        elif format == "html":
            html = self._render_html_certificate(certificate)
            with open(output, "w", encoding="utf-8") as fh:
                fh.write(html)
        else:
            raise ValueError(f"Unsupported certificate format: {format!r}")

        self._log("CERTIFICATE_GENERATED", {
            "file_path": canonical,
            "output_path": str(output),
            "format": format,
            "certificate_id": certificate["certificate_id"],
            "timestamp": now,
        })

    @staticmethod
    def _render_html_certificate(cert: dict) -> str:
        """Render a certificate dictionary as a styled HTML document."""
        file_info = cert["file"]
        hashes = cert["hashes"]
        verification = cert["verification"]
        custody = cert["chain_of_custody"]

        hash_rows = "\n".join(
            f"            <tr><td>{alg.upper()}</td>"
            f"<td class=\"hash\">{digest}</td></tr>"
            for alg, digest in hashes.items()
        )

        status = verification["status"]
        status_class = {
            "verified": "status-verified",
            "modified": "status-modified",
            "pending": "status-pending",
        }.get(status, "status-pending")

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Evidence Integrity Certificate - {cert['certificate_id']}</title>
<style>
    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
    body {{
        font-family: "Segoe UI", Tahoma, Geneva, Verdana, sans-serif;
        background: #f4f6f8; color: #1a1a2e; padding: 40px;
    }}
    .certificate {{
        max-width: 800px; margin: 0 auto; background: #fff;
        border: 2px solid #16213e; border-radius: 4px;
        padding: 48px; position: relative;
    }}
    .certificate::before {{
        content: ""; position: absolute; top: 8px; left: 8px;
        right: 8px; bottom: 8px; border: 1px solid #16213e;
        pointer-events: none;
    }}
    h1 {{
        text-align: center; font-size: 24px; margin-bottom: 4px;
        text-transform: uppercase; letter-spacing: 2px; color: #16213e;
    }}
    .cert-id {{
        text-align: center; font-size: 12px; color: #666;
        margin-bottom: 32px; font-family: monospace;
    }}
    h2 {{
        font-size: 14px; text-transform: uppercase;
        letter-spacing: 1px; color: #16213e;
        border-bottom: 1px solid #ccc; padding-bottom: 4px;
        margin: 24px 0 12px;
    }}
    table {{ width: 100%; border-collapse: collapse; margin-bottom: 8px; }}
    td {{ padding: 6px 8px; font-size: 13px; vertical-align: top; }}
    td:first-child {{ font-weight: 600; width: 160px; color: #333; }}
    .hash {{ font-family: "Consolas", "Courier New", monospace; font-size: 12px; word-break: break-all; }}
    .status-verified {{ color: #0a8a0a; font-weight: 700; }}
    .status-modified {{ color: #c0392b; font-weight: 700; }}
    .status-pending  {{ color: #b8860b; font-weight: 700; }}
    .footer {{
        margin-top: 40px; text-align: center; font-size: 11px;
        color: #888; border-top: 1px solid #ccc; padding-top: 16px;
    }}
</style>
</head>
<body>
<div class="certificate">
    <h1>Evidence Integrity Certificate</h1>
    <p class="cert-id">ID: {cert['certificate_id']}</p>

    <h2>File Information</h2>
    <table>
        <tr><td>File Name</td><td>{file_info['name']}</td></tr>
        <tr><td>File Path</td><td class="hash">{file_info['path']}</td></tr>
        <tr><td>File Size</td><td>{file_info['size_bytes']:,} bytes</td></tr>
    </table>

    <h2>Cryptographic Hashes</h2>
    <table>
{hash_rows}
    </table>

    <h2>Verification Status</h2>
    <table>
        <tr><td>Status</td><td class="{status_class}">{status.upper()}</td></tr>
        <tr><td>Verified</td><td>{"Yes" if verification["verified"] else "No"}</td></tr>
        <tr><td>Verification Time</td><td>{verification["verification_time"] or "N/A"}</td></tr>
    </table>

    <h2>Chain of Custody</h2>
    <table>
        <tr><td>Operator</td><td>{custody['operator']}</td></tr>
        <tr><td>Hostname</td><td>{custody['hostname']}</td></tr>
        <tr><td>Certificate Generated</td><td>{custody['certificate_generated']}</td></tr>
    </table>

    <div class="footer">
        This certificate was generated automatically by the File Signature Analyzer
        Evidence Integrity Verification System. It attests to the cryptographic
        hash values of the referenced file at the time of examination.
    </div>
</div>
</body>
</html>"""

    # ------------------------------------------------------------------
    # Evidence quarantine
    # ------------------------------------------------------------------

    def quarantine_file(self, file_path, reason="", case_id=None) -> str:
        """Copy an evidence file into the quarantine locker.

        The original file is never moved or modified.  A metadata sidecar
        file is created alongside the quarantined copy containing full
        hash information, source path, timestamps, and quarantine reason.

        Args:
            file_path: Path to the file to quarantine.
            reason: Free-text reason for quarantine.
            case_id: Optional case identifier.  Files are grouped under
                this identifier inside the locker.

        Returns:
            The absolute path of the quarantined copy inside the locker.
        """
        canonical = self._canonical_path(file_path)
        hashes = self.compute_hashes(canonical)
        file_size = os.path.getsize(canonical)
        now = self._iso_now()

        case_dir = case_id if case_id else "uncategorized"
        sha256_prefix = hashes["sha256"][:16]
        original_name = os.path.basename(canonical)

        dest_dir = self.evidence_locker_path / case_dir / sha256_prefix
        dest_dir.mkdir(parents=True, exist_ok=True)

        evidence_name = f"{original_name}.evidence"
        metadata_name = f"{original_name}.metadata.json"

        dest_file = dest_dir / evidence_name
        dest_meta = dest_dir / metadata_name

        shutil.copy2(canonical, dest_file)

        metadata = {
            "original_path": canonical,
            "original_name": original_name,
            "file_size": file_size,
            "hashes": hashes,
            "quarantine_time": now,
            "reason": reason,
            "case_id": case_id,
            "locker_path": str(dest_file),
        }

        with open(dest_meta, "w", encoding="utf-8") as fh:
            json.dump(metadata, fh, indent=2, ensure_ascii=False)

        self._log("SAFETY_QUARANTINE", {
            "file_path": canonical,
            "locker_path": str(dest_file),
            "reason": reason,
            "case_id": case_id,
            "hashes": hashes,
            "timestamp": now,
        })

        return str(dest_file)

    # ------------------------------------------------------------------
    # Quarantine verification
    # ------------------------------------------------------------------

    def verify_quarantined_file(self, locker_path) -> bool:
        """Verify that a quarantined file matches its sidecar metadata.

        Args:
            locker_path: Path to the ``.evidence`` file inside the locker.

        Returns:
            ``True`` if all hashes in the sidecar still match the file.

        Raises:
            FileNotFoundError: If the evidence or metadata file is missing.
            ValueError: If the metadata is malformed.
        """
        locker_path = Path(locker_path)
        if not locker_path.exists():
            raise FileNotFoundError(f"Evidence file not found: {locker_path}")

        stem = locker_path.name
        if stem.endswith(".evidence"):
            stem = stem[: -len(".evidence")]
        meta_path = locker_path.parent / f"{stem}.metadata.json"

        if not meta_path.exists():
            raise FileNotFoundError(f"Metadata sidecar not found: {meta_path}")

        with open(meta_path, "r", encoding="utf-8") as fh:
            metadata = json.load(fh)

        expected_hashes = metadata.get("hashes")
        if not expected_hashes:
            raise ValueError("Metadata sidecar does not contain hashes")

        algorithms = list(expected_hashes.keys())
        actual_hashes = self.compute_hashes(locker_path, algorithms=algorithms)

        match = actual_hashes == expected_hashes

        self._log("QUARANTINE_VERIFICATION", {
            "locker_path": str(locker_path),
            "match": match,
            "timestamp": self._iso_now(),
        })

        return match

    # ------------------------------------------------------------------
    # Status query
    # ------------------------------------------------------------------

    def get_integrity_status(self, file_path) -> str:
        """Return the integrity status of *file_path*.

        Args:
            file_path: Path to the evidence file.

        Returns:
            ``"verified"`` if integrity was confirmed, ``"pending"`` if
            only a pre-analysis check was performed, or ``"modified"``
            if a post-analysis check detected changes.  Returns
            ``"pending"`` when no record exists.
        """
        canonical = self._canonical_path(file_path)
        with self._lock:
            record = self.integrity_records.get(canonical)
        if record is None:
            return "pending"
        return record["status"]

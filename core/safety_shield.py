"""
Safety Shield Module for Forensic File Signature Analyzer.

Provides hash-based and statistical detection of dangerous, illegal, or
suspicious content WITHOUT ever rendering, decoding, or displaying actual
file content.  All analysis operates on raw bytes and numeric metrics only,
ensuring the operator is never exposed to harmful material.

Detection capabilities:
    - Known-bad hash matching (MD5 / SHA-1 / SHA-256)
    - Section-level entropy analysis
    - Encrypted container identification
    - Double-extension detection
    - Hidden executable detection
    - File-size anomaly detection
    - Steganography indicator analysis (statistical / LSB byte-distribution)

Author:  File Signature Analyzer Project
License: Proprietary - Forensic Use
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import os
import struct
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

# ---------------------------------------------------------------------------
# Conditional imports for optional forensic subsystems
# ---------------------------------------------------------------------------
try:
    from core.forensic_logger import ForensicAuditLogger
except ImportError:
    ForensicAuditLogger = None  # type: ignore[assignment,misc]

try:
    from core.evidence_integrity import EvidenceIntegrityVerifier
except ImportError:
    EvidenceIntegrityVerifier = None  # type: ignore[assignment,misc]

# ---------------------------------------------------------------------------
# Module-level logger
# ---------------------------------------------------------------------------
_log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
_HASH_LENGTH_TO_TYPE: Dict[int, str] = {32: "md5", 40: "sha1", 64: "sha256"}

_SEVERITY_ORDER: Dict[str, int] = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

# Dangerous executable extensions (lowercase, with dot)
_EXECUTABLE_EXTENSIONS: set = {
    ".exe", ".scr", ".pif", ".cmd", ".bat", ".com", ".vbs", ".vbe",
    ".js", ".jse", ".wsf", ".wsh", ".ps1", ".msi", ".dll", ".sys",
    ".cpl", ".hta", ".inf", ".reg", ".rgs", ".sct", ".shb", ".shs",
    ".elf", ".bin", ".run", ".app", ".action", ".command", ".sh",
}

# Magic bytes for well-known executable formats
_PE_MAGIC = b"MZ"
_ELF_MAGIC = b"\x7fELF"
_MACH_O_MAGICS = {b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf",
                   b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"}
_SHEBANG = b"#!"

# Non-executable extensions that should never contain executables
_NON_EXECUTABLE_EXTENSIONS: set = {
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".tif",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".txt", ".csv", ".xml", ".html", ".htm", ".mp3", ".wav",
    ".mp4", ".avi", ".mov", ".flv", ".ogg", ".webm",
}

# Typical max sizes (bytes) for sanity checks
_SIZE_EXPECTATIONS: Dict[str, int] = {
    ".txt": 100 * 1024 * 1024,       # 100 MB
    ".csv": 500 * 1024 * 1024,       # 500 MB
    ".json": 200 * 1024 * 1024,      # 200 MB
    ".xml": 200 * 1024 * 1024,       # 200 MB
    ".log": 500 * 1024 * 1024,       # 500 MB
    ".ini": 1 * 1024 * 1024,         # 1 MB
    ".cfg": 1 * 1024 * 1024,         # 1 MB
}

# Minimum plausible archive size (bytes)
_MIN_ARCHIVE_SIZE: int = 22  # Empty ZIP is 22 bytes


class SafetyShield:
    """Hash-based and statistical safety shield for forensic file analysis.

    This class performs all detection using raw byte analysis and hash
    comparison.  It **never** decodes, renders, or displays actual file
    content, protecting the operator from exposure to harmful material.

    Parameters
    ----------
    hash_database_path : str or Path or None
        Path to a hash database file (text or JSON).  Loaded on
        construction if provided.
    audit_logger : ForensicAuditLogger or None
        Optional audit logger for recording safety events.
    evidence_integrity : EvidenceIntegrityVerifier or None
        Optional integrity verifier used for quarantine operations.
    """

    # Entropy thresholds
    ENTROPY_THRESHOLD: float = 7.5
    ENCRYPTED_ENTROPY_THRESHOLD: float = 7.9

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------
    def __init__(
        self,
        hash_database_path: Optional[str] = None,
        audit_logger: Any = None,
        evidence_integrity: Any = None,
    ) -> None:
        self.hash_database_path: Optional[str] = hash_database_path
        self.known_hashes: Dict[str, Set[str]] = {
            "md5": set(),
            "sha1": set(),
            "sha256": set(),
        }
        self.alert_callbacks: List[Callable[[Dict[str, Any]], None]] = []
        self.audit_logger: Any = audit_logger
        self.evidence_integrity: Any = evidence_integrity

        if hash_database_path is not None:
            self.load_hash_database(hash_database_path)

    # ------------------------------------------------------------------
    # Hash database management
    # ------------------------------------------------------------------
    def load_hash_database(self, path: str) -> None:
        """Load known-bad hashes from *path*.

        Supports two formats:

        * **Text file** -- one hex hash per line.  Hash type is inferred
          from length (32 -> md5, 40 -> sha1, 64 -> sha256).  Lines
          starting with ``#`` or empty lines are skipped.
        * **JSON file** -- a dict with keys ``"md5"``, ``"sha1"``,
          ``"sha256"`` mapping to lists of hex strings.

        Parameters
        ----------
        path : str
            Filesystem path to the database file.

        Raises
        ------
        FileNotFoundError
            If *path* does not exist.
        ValueError
            If *path* contains unparseable content.
        """
        path_obj = Path(path)
        if not path_obj.is_file():
            raise FileNotFoundError(f"Hash database not found: {path}")

        raw = path_obj.read_text(encoding="utf-8", errors="replace")

        # Attempt JSON first
        if path_obj.suffix.lower() == ".json" or raw.lstrip().startswith("{"):
            try:
                data = json.loads(raw)
                for hash_type in ("md5", "sha1", "sha256"):
                    if hash_type in data and isinstance(data[hash_type], list):
                        self.known_hashes[hash_type].update(
                            h.strip().lower() for h in data[hash_type] if h.strip()
                        )
                self.hash_database_path = str(path)
                _log.info(
                    "Loaded JSON hash database from %s (md5=%d, sha1=%d, sha256=%d)",
                    path,
                    len(self.known_hashes["md5"]),
                    len(self.known_hashes["sha1"]),
                    len(self.known_hashes["sha256"]),
                )
                return
            except json.JSONDecodeError:
                pass  # Fall through to text parsing

        # Text format: one hash per line
        for line in raw.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            hash_type = _HASH_LENGTH_TO_TYPE.get(len(line))
            if hash_type is not None:
                self.known_hashes[hash_type].add(line.lower())
            else:
                _log.warning("Skipping hash of unrecognised length %d: %s", len(line), line[:16])

        self.hash_database_path = str(path)
        _log.info(
            "Loaded text hash database from %s (md5=%d, sha1=%d, sha256=%d)",
            path,
            len(self.known_hashes["md5"]),
            len(self.known_hashes["sha1"]),
            len(self.known_hashes["sha256"]),
        )

    def add_hash(self, hash_value: str, hash_type: str = "sha256") -> None:
        """Add a single hash to the in-memory database.

        Parameters
        ----------
        hash_value : str
            Hex-encoded hash string.
        hash_type : str
            One of ``"md5"``, ``"sha1"``, ``"sha256"``.

        Raises
        ------
        ValueError
            If *hash_type* is not recognised.
        """
        hash_type = hash_type.lower()
        if hash_type not in self.known_hashes:
            raise ValueError(f"Unsupported hash type: {hash_type}")
        self.known_hashes[hash_type].add(hash_value.strip().lower())

    def save_hash_database(self, path: str) -> None:
        """Persist the current in-memory hash database to *path* as JSON.

        Parameters
        ----------
        path : str
            Destination file path.
        """
        data = {k: sorted(v) for k, v in self.known_hashes.items()}
        Path(path).write_text(
            json.dumps(data, indent=2), encoding="utf-8"
        )
        _log.info("Saved hash database to %s", path)

    # ------------------------------------------------------------------
    # Primary scan entry-point
    # ------------------------------------------------------------------
    def scan_file(
        self,
        file_path: str,
        file_hashes: Optional[Dict[str, str]] = None,
        operator_id: str = "",
    ) -> Dict[str, Any]:
        """Run all detection checks on a single file.

        Parameters
        ----------
        file_path : str
            Path to the file on disk.
        file_hashes : dict or None
            Pre-computed hashes ``{"md5": ..., "sha1": ..., "sha256": ...}``.
            If ``None``, hashes will be computed internally.
        operator_id : str
            Identifier of the analyst performing the scan.

        Returns
        -------
        dict
            A flag-result dictionary (see module docstring for schema).
        """
        flags: List[Dict[str, Any]] = []
        file_path = str(file_path)

        # Compute hashes if not supplied
        if file_hashes is None:
            file_hashes = self._compute_hashes(file_path)

        # --- Run all detectors ---
        try:
            flags.extend(self.check_known_hashes(file_hashes))
        except Exception as exc:
            _log.error("check_known_hashes failed for %s: %s", file_path, exc)

        try:
            entropy_result = self.analyze_entropy_sections(file_path)
            if entropy_result.get("flagged"):
                flags.append(entropy_result)
        except Exception as exc:
            _log.error("analyze_entropy_sections failed for %s: %s", file_path, exc)

        try:
            enc_result = self.detect_encrypted_container(file_path)
            if enc_result.get("flagged"):
                flags.append(enc_result)
        except Exception as exc:
            _log.error("detect_encrypted_container failed for %s: %s", file_path, exc)

        try:
            dbl_result = self.detect_double_extension(file_path)
            if dbl_result.get("flagged"):
                flags.append(dbl_result)
        except Exception as exc:
            _log.error("detect_double_extension failed for %s: %s", file_path, exc)

        try:
            hidden_result = self.detect_hidden_executable(file_path)
            if hidden_result.get("flagged"):
                flags.append(hidden_result)
        except Exception as exc:
            _log.error("detect_hidden_executable failed for %s: %s", file_path, exc)

        try:
            size_result = self.detect_size_anomaly(file_path)
            if size_result.get("flagged"):
                flags.append(size_result)
        except Exception as exc:
            _log.error("detect_size_anomaly failed for %s: %s", file_path, exc)

        try:
            steg_result = self.detect_steganography_indicators(file_path)
            if steg_result.get("flagged"):
                flags.append(steg_result)
        except Exception as exc:
            _log.error("detect_steganography_indicators failed for %s: %s", file_path, exc)

        # Clean internal 'flagged' keys from output
        for flag in flags:
            flag.pop("flagged", None)

        # Determine overall risk
        overall_risk = self._compute_overall_risk(flags)

        # Fire alerts for critical / high
        for flag in flags:
            if _SEVERITY_ORDER.get(flag.get("severity", "info"), 0) >= _SEVERITY_ORDER["high"]:
                self._fire_alert(flag)

        # Auto-quarantine when warranted
        action_taken_quarantine = False
        if overall_risk in ("critical", "high"):
            try:
                self.auto_quarantine(file_path, flags)
                action_taken_quarantine = True
            except Exception as exc:
                _log.error("auto_quarantine failed for %s: %s", file_path, exc)

        if action_taken_quarantine:
            for flag in flags:
                if flag.get("action_taken") in (None, "none", "flagged"):
                    if _SEVERITY_ORDER.get(flag.get("severity", "info"), 0) >= _SEVERITY_ORDER["high"]:
                        flag["action_taken"] = "quarantined"

        result: Dict[str, Any] = {
            "file_path": file_path,
            "flags": flags,
            "overall_risk": overall_risk,
            "scan_timestamp": datetime.now(timezone.utc).isoformat(),
            "operator_id": operator_id,
            "preview_blocked": self.should_block_preview({"flags": flags}),
        }

        # Audit log the full scan
        self._audit_log("SAFETY_SCAN", {
            "file_path": file_path,
            "overall_risk": overall_risk,
            "flag_count": len(flags),
            "operator_id": operator_id,
        })

        return result

    # ------------------------------------------------------------------
    # Detection methods
    # ------------------------------------------------------------------
    def check_known_hashes(
        self, file_hashes: Dict[str, str]
    ) -> List[Dict[str, Any]]:
        """Check file hashes against the known-bad hash database.

        Parameters
        ----------
        file_hashes : dict
            ``{"md5": "<hex>", "sha1": "<hex>", "sha256": "<hex>"}``.

        Returns
        -------
        list[dict]
            A list of flag dicts (one per matching hash type).
        """
        matches: List[Dict[str, Any]] = []
        for hash_type, hash_value in file_hashes.items():
            if hash_type not in self.known_hashes:
                continue
            if hash_value and hash_value.lower() in self.known_hashes[hash_type]:
                flag = {
                    "type": "known_hash_match",
                    "severity": "critical",
                    "description": (
                        f"File matches known-bad {hash_type.upper()} hash."
                    ),
                    "action_taken": "flagged",
                    "details": {
                        "hash_type": hash_type,
                        "hash_value": hash_value.lower(),
                    },
                    "flagged": True,
                }
                matches.append(flag)
                self._audit_log("SAFETY_FLAG", {
                    "type": "known_hash_match",
                    "hash_type": hash_type,
                    "hash_value": hash_value.lower(),
                })
        return matches

    def analyze_entropy_sections(self, file_path: str) -> Dict[str, Any]:
        """Calculate Shannon entropy on header, body, and tail sections.

        Parameters
        ----------
        file_path : str
            Path to the file on disk.

        Returns
        -------
        dict
            A flag dict.  ``"flagged"`` is ``True`` when any section
            exceeds ``ENTROPY_THRESHOLD``.
        """
        section_size = 1024
        file_size = os.path.getsize(file_path)

        if file_size == 0:
            return {"flagged": False}

        with open(file_path, "rb") as fh:
            header = fh.read(section_size)

            if file_size > section_size * 3:
                mid_start = file_size // 2 - section_size // 2
                fh.seek(mid_start)
                body = fh.read(section_size)
            else:
                body = header  # small files: reuse header

            if file_size > section_size * 2:
                fh.seek(max(0, file_size - section_size))
                tail = fh.read(section_size)
            else:
                tail = header

        header_entropy = self._shannon_entropy(header)
        body_entropy = self._shannon_entropy(body)
        tail_entropy = self._shannon_entropy(tail)

        max_entropy = max(header_entropy, body_entropy, tail_entropy)
        flagged = max_entropy > self.ENTROPY_THRESHOLD

        severity = "info"
        if max_entropy > self.ENCRYPTED_ENTROPY_THRESHOLD:
            severity = "high"
        elif max_entropy > self.ENTROPY_THRESHOLD:
            severity = "medium"

        return {
            "type": "high_entropy",
            "severity": severity,
            "description": (
                f"Entropy analysis: header={header_entropy:.3f}, "
                f"body={body_entropy:.3f}, tail={tail_entropy:.3f} "
                f"(threshold={self.ENTROPY_THRESHOLD})."
            ),
            "action_taken": "flagged" if flagged else "none",
            "details": {
                "header_entropy": round(header_entropy, 4),
                "body_entropy": round(body_entropy, 4),
                "tail_entropy": round(tail_entropy, 4),
                "max_entropy": round(max_entropy, 4),
                "threshold": self.ENTROPY_THRESHOLD,
            },
            "flagged": flagged,
        }

    def detect_encrypted_container(self, file_path: str) -> Dict[str, Any]:
        """Detect known encrypted container formats.

        Checks for TrueCrypt/VeraCrypt, BitLocker, LUKS, encrypted ZIP,
        encrypted RAR, and PGP containers.

        Parameters
        ----------
        file_path : str
            Path to the file on disk.

        Returns
        -------
        dict
            A flag dict.
        """
        file_size = os.path.getsize(file_path)
        if file_size == 0:
            return {"flagged": False}

        read_len = min(file_size, 4096)
        with open(file_path, "rb") as fh:
            header = fh.read(read_len)

        detections: List[str] = []

        # BitLocker: -FVE-FS- at offset 3
        if len(header) > 11 and header[3:11] == b"-FVE-FS-":
            detections.append("BitLocker")

        # LUKS
        if header[:6] == b"LUKS\xba\xbe":
            detections.append("LUKS")

        # PGP (old-format packet tag for encrypted data)
        if len(header) >= 1 and header[0] in (0x85, 0xC6):
            detections.append("PGP encrypted data")

        # Encrypted ZIP: PK\x03\x04 with general-purpose bit flag bit 0
        if header[:4] == b"PK\x03\x04" and len(header) >= 8:
            gp_flags = struct.unpack_from("<H", header, 6)[0]
            if gp_flags & 0x0001:
                detections.append("Encrypted ZIP")

        # Encrypted RAR
        if header[:7] == b"Rar!\x1a\x07\x00":
            # RAR4: check header flags at offset 10
            if len(header) >= 12:
                flags = struct.unpack_from("<H", header, 10)[0]
                if flags & 0x0004:  # password flag
                    detections.append("Encrypted RAR4")
        elif header[:8] == b"Rar!\x1a\x07\x01\x00":
            # RAR5: scan for encryption record in first 4k
            if b"\x04\x00" in header[12:]:
                detections.append("Encrypted RAR5 (possible)")

        # TrueCrypt / VeraCrypt: no recognisable magic + very high entropy
        if not detections:
            # Only run this heuristic when nothing else matched
            has_known_magic = self._has_recognised_magic(header)
            if not has_known_magic and file_size >= 512:
                ent = self._shannon_entropy(header[:512])
                if ent > self.ENCRYPTED_ENTROPY_THRESHOLD:
                    detections.append("TrueCrypt/VeraCrypt (heuristic)")

        if not detections:
            return {"flagged": False}

        return {
            "type": "encrypted_container",
            "severity": "high",
            "description": (
                f"Encrypted container detected: {', '.join(detections)}."
            ),
            "action_taken": "flagged",
            "details": {
                "container_types": detections,
            },
            "flagged": True,
        }

    def detect_double_extension(self, file_path: str) -> Dict[str, Any]:
        """Detect double-extension tricks (e.g. ``report.pdf.exe``).

        Parameters
        ----------
        file_path : str
            Path to the file.

        Returns
        -------
        dict
            A flag dict.
        """
        name = Path(file_path).name
        suffixes = Path(name).suffixes  # e.g. ['.pdf', '.exe']

        if len(suffixes) >= 2:
            final_ext = suffixes[-1].lower()
            if final_ext in _EXECUTABLE_EXTENSIONS:
                return {
                    "type": "double_extension",
                    "severity": "high",
                    "description": (
                        f"Double extension detected: '{name}'. "
                        f"Final extension '{final_ext}' is executable."
                    ),
                    "action_taken": "flagged",
                    "details": {
                        "filename": name,
                        "extensions": [s.lower() for s in suffixes],
                        "final_extension": final_ext,
                    },
                    "flagged": True,
                }

        return {"flagged": False}

    def detect_hidden_executable(self, file_path: str) -> Dict[str, Any]:
        """Detect executables disguised with non-executable extensions.

        Reads the first few bytes to check for PE (MZ), ELF, Mach-O, or
        shebang headers in files whose extension suggests a non-executable
        type (images, documents, etc.).

        Parameters
        ----------
        file_path : str
            Path to the file.

        Returns
        -------
        dict
            A flag dict.
        """
        ext = Path(file_path).suffix.lower()
        if ext not in _NON_EXECUTABLE_EXTENSIONS:
            return {"flagged": False}

        file_size = os.path.getsize(file_path)
        if file_size < 2:
            return {"flagged": False}

        with open(file_path, "rb") as fh:
            magic = fh.read(4)

        detected_type: Optional[str] = None

        if magic[:2] == _PE_MAGIC:
            detected_type = "PE (Windows executable)"
        elif magic[:4] == _ELF_MAGIC:
            detected_type = "ELF (Linux executable)"
        elif magic[:4] in _MACH_O_MAGICS:
            detected_type = "Mach-O (macOS executable)"
        elif magic[:2] == _SHEBANG:
            detected_type = "Script (shebang)"

        if detected_type is None:
            return {"flagged": False}

        return {
            "type": "hidden_executable",
            "severity": "critical",
            "description": (
                f"Hidden executable detected: {detected_type} header "
                f"found in file with '{ext}' extension."
            ),
            "action_taken": "flagged",
            "details": {
                "declared_extension": ext,
                "actual_type": detected_type,
                "magic_bytes": magic[:4].hex(),
            },
            "flagged": True,
        }

    def detect_size_anomaly(
        self, file_path: str, file_type: Optional[str] = None
    ) -> Dict[str, Any]:
        """Flag files with unusual sizes for their type.

        Parameters
        ----------
        file_path : str
            Path to the file.
        file_type : str or None
            Optional override for the file extension.

        Returns
        -------
        dict
            A flag dict.
        """
        ext = (file_type or Path(file_path).suffix).lower()
        file_size = os.path.getsize(file_path)

        # Check for oversized text-like files
        max_expected = _SIZE_EXPECTATIONS.get(ext)
        if max_expected is not None and file_size > max_expected:
            return {
                "type": "size_anomaly",
                "severity": "medium",
                "description": (
                    f"File size ({file_size:,} bytes) exceeds expected "
                    f"maximum for '{ext}' ({max_expected:,} bytes)."
                ),
                "action_taken": "flagged",
                "details": {
                    "file_size": file_size,
                    "expected_max": max_expected,
                    "extension": ext,
                },
                "flagged": True,
            }

        # Check for suspiciously tiny archives
        if ext in (".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz"):
            if 0 < file_size < _MIN_ARCHIVE_SIZE:
                return {
                    "type": "size_anomaly",
                    "severity": "low",
                    "description": (
                        f"Archive '{ext}' is suspiciously small "
                        f"({file_size} bytes)."
                    ),
                    "action_taken": "flagged",
                    "details": {
                        "file_size": file_size,
                        "min_expected": _MIN_ARCHIVE_SIZE,
                        "extension": ext,
                    },
                    "flagged": True,
                }

        # Zero-byte file
        if file_size == 0:
            return {
                "type": "size_anomaly",
                "severity": "info",
                "description": "File is empty (0 bytes).",
                "action_taken": "none",
                "details": {"file_size": 0, "extension": ext},
                "flagged": True,
            }

        return {"flagged": False}

    def detect_steganography_indicators(
        self, file_path: str
    ) -> Dict[str, Any]:
        """Statistical analysis for LSB steganography indicators.

        Operates entirely on raw byte values.  Does **not** decode image
        pixel data -- instead, analyses the distribution of least
        significant bits across the file's byte stream.

        A uniform LSB distribution across a large sample is unusual for
        natural data and may indicate embedded hidden content.

        Parameters
        ----------
        file_path : str
            Path to the file.

        Returns
        -------
        dict
            A flag dict.
        """
        ext = Path(file_path).suffix.lower()
        if ext not in (".png", ".bmp", ".gif", ".tiff", ".tif", ".jpg", ".jpeg"):
            return {"flagged": False}

        file_size = os.path.getsize(file_path)
        if file_size < 1024:
            return {"flagged": False}

        # Read a representative sample (skip file header, read data region)
        sample_size = min(file_size - 128, 65536)
        if sample_size < 512:
            return {"flagged": False}

        with open(file_path, "rb") as fh:
            fh.seek(128)  # skip typical image header area
            sample = fh.read(sample_size)

        if len(sample) < 512:
            return {"flagged": False}

        # Count LSBs
        lsb_counts = [0, 0]
        for byte in sample:
            lsb_counts[byte & 1] += 1

        total = lsb_counts[0] + lsb_counts[1]
        ratio = min(lsb_counts) / max(lsb_counts) if max(lsb_counts) > 0 else 0.0

        # In natural images, LSB distribution tends to be skewed.
        # A ratio very close to 1.0 (perfectly uniform) is suspicious.
        # Threshold: ratio > 0.97 on a large enough sample.
        suspicious = ratio > 0.97 and total >= 4096

        # Additional check: chi-squared on LSB pairs (2-bit patterns)
        pair_counts = Counter()
        for i in range(0, len(sample) - 1, 2):
            pair = ((sample[i] & 1) << 1) | (sample[i + 1] & 1)
            pair_counts[pair] += 1

        pair_total = sum(pair_counts.values())
        expected_pair = pair_total / 4.0 if pair_total > 0 else 1.0
        chi_sq = 0.0
        for pattern in range(4):
            observed = pair_counts.get(pattern, 0)
            chi_sq += ((observed - expected_pair) ** 2) / expected_pair if expected_pair > 0 else 0.0

        # Low chi-squared on pairs = very uniform = suspicious
        # For 3 degrees of freedom, chi-sq < 1.0 is unusually uniform
        pair_suspicious = chi_sq < 1.0 and pair_total >= 2048

        flagged = suspicious or pair_suspicious
        if not flagged:
            return {"flagged": False}

        return {
            "type": "steganography_indicators",
            "severity": "medium",
            "description": (
                "Statistical indicators of possible LSB steganography: "
                f"LSB ratio={ratio:.4f}, chi-sq={chi_sq:.4f}."
            ),
            "action_taken": "flagged",
            "details": {
                "lsb_ratio": round(ratio, 6),
                "lsb_counts": lsb_counts,
                "chi_squared": round(chi_sq, 4),
                "sample_bytes": len(sample),
                "pair_total": pair_total,
            },
            "flagged": True,
        }

    # ------------------------------------------------------------------
    # Safety actions
    # ------------------------------------------------------------------
    def auto_quarantine(
        self, file_path: str, flags: List[Dict[str, Any]]
    ) -> str:
        """Quarantine a file when critical or high-severity flags exist.

        Delegates to ``evidence_integrity.quarantine_file()`` when
        available.  Otherwise logs a warning and returns a placeholder.

        Parameters
        ----------
        file_path : str
            The path to the file to quarantine.
        flags : list[dict]
            The flag list from a scan result.

        Returns
        -------
        str
            A quarantine receipt or identifier.
        """
        max_severity = max(
            (_SEVERITY_ORDER.get(f.get("severity", "info"), 0) for f in flags),
            default=0,
        )
        if max_severity < _SEVERITY_ORDER["high"]:
            return "no_action"

        self._audit_log("SAFETY_QUARANTINE", {
            "file_path": file_path,
            "flag_count": len(flags),
            "trigger_severity": [
                f.get("type") for f in flags
                if _SEVERITY_ORDER.get(f.get("severity", "info"), 0) >= _SEVERITY_ORDER["high"]
            ],
        })

        if self.evidence_integrity is not None:
            try:
                receipt = self.evidence_integrity.quarantine_file(file_path)
                return str(receipt)
            except Exception as exc:
                _log.error("Quarantine via evidence_integrity failed: %s", exc)
                return f"quarantine_error: {exc}"

        _log.warning(
            "No evidence_integrity verifier configured; "
            "quarantine of %s is advisory only.",
            file_path,
        )
        return "advisory_quarantine"

    def should_block_preview(self, flag_result: Dict[str, Any]) -> bool:
        """Determine whether file preview should be blocked.

        Returns ``True`` if any flag has severity ``"critical"`` or type
        ``"known_hash_match"``.

        Parameters
        ----------
        flag_result : dict
            A scan result dict containing a ``"flags"`` list.

        Returns
        -------
        bool
        """
        for flag in flag_result.get("flags", []):
            if flag.get("severity") == "critical":
                return True
            if flag.get("type") == "known_hash_match":
                return True
        return False

    def redact_report(
        self, report: Dict[str, Any], redaction_level: str = "standard"
    ) -> Dict[str, Any]:
        """Return a copy of *report* with sensitive data stripped.

        Parameters
        ----------
        report : dict
            A scan result dict.
        redaction_level : str
            ``"minimal"`` -- redact only content previews.
            ``"standard"`` -- also redact full file paths, hash values.
            ``"maximum"`` -- also redact operator id, timestamps, all
            details dicts.

        Returns
        -------
        dict
            A redacted copy of *report*.
        """
        import copy
        redacted = copy.deepcopy(report)

        if redaction_level in ("minimal", "standard", "maximum"):
            # Remove any content-preview keys (defence in depth)
            for flag in redacted.get("flags", []):
                flag.get("details", {}).pop("content_preview", None)
                flag.get("details", {}).pop("raw_bytes", None)

        if redaction_level in ("standard", "maximum"):
            # Redact file paths
            if "file_path" in redacted:
                redacted["file_path"] = self._redact_path(redacted["file_path"])
            for flag in redacted.get("flags", []):
                details = flag.get("details", {})
                if "file_path" in details:
                    details["file_path"] = self._redact_path(details["file_path"])
                # Redact hash values to prefix only
                if "hash_value" in details:
                    hv = details["hash_value"]
                    details["hash_value"] = hv[:8] + "..." if len(hv) > 8 else hv

        if redaction_level == "maximum":
            redacted["operator_id"] = "[REDACTED]"
            redacted["scan_timestamp"] = "[REDACTED]"
            for flag in redacted.get("flags", []):
                flag["details"] = {}

        return redacted

    def get_redacted_summary(self, file_path: str) -> str:
        """Return a safe-to-display one-line summary of the last scan.

        Parameters
        ----------
        file_path : str
            Path to the file (used for display -- filename only).

        Returns
        -------
        str
            A concise human-readable summary.
        """
        name = Path(file_path).name
        result = self.scan_file(file_path)
        risk = result.get("overall_risk", "unknown")
        n_flags = len(result.get("flags", []))
        blocked = result.get("preview_blocked", False)

        parts = [f"{name}: risk={risk}, flags={n_flags}"]
        if blocked:
            parts.append("PREVIEW BLOCKED")
        return " | ".join(parts)

    # ------------------------------------------------------------------
    # Alert system
    # ------------------------------------------------------------------
    def register_alert_callback(
        self, callback: Callable[[Dict[str, Any]], None]
    ) -> None:
        """Register a callback to be invoked on high/critical flags.

        Parameters
        ----------
        callback : callable
            A function accepting a single dict argument (the flag).
        """
        if callback not in self.alert_callbacks:
            self.alert_callbacks.append(callback)

    def _fire_alert(self, flag: Dict[str, Any]) -> None:
        """Invoke all registered alert callbacks with *flag*.

        Exceptions in callbacks are caught and logged so that one
        failing callback does not prevent others from executing.
        """
        for cb in self.alert_callbacks:
            try:
                cb(flag)
            except Exception as exc:
                _log.error("Alert callback %s raised: %s", cb, exc)

        # Also push to audit logger
        self._audit_log("SAFETY_FLAG", {
            "type": flag.get("type"),
            "severity": flag.get("severity"),
            "description": flag.get("description"),
        })

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _shannon_entropy(data: bytes) -> float:
        """Calculate Shannon entropy (bits per byte) over *data*.

        Returns a value between 0.0 (perfectly uniform) and 8.0
        (maximum entropy for byte-level analysis).
        """
        if not data:
            return 0.0
        length = len(data)
        counts = Counter(data)
        entropy = 0.0
        for count in counts.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy

    @staticmethod
    def _compute_hashes(file_path: str) -> Dict[str, str]:
        """Compute MD5, SHA-1, and SHA-256 hashes for a file.

        Reads in 64 KiB blocks to handle large files efficiently.
        """
        hashers = {
            "md5": hashlib.md5(),
            "sha1": hashlib.sha1(),
            "sha256": hashlib.sha256(),
        }
        try:
            with open(file_path, "rb") as fh:
                while True:
                    block = fh.read(65536)
                    if not block:
                        break
                    for h in hashers.values():
                        h.update(block)
        except OSError as exc:
            _log.error("Failed to hash %s: %s", file_path, exc)
            return {"md5": "", "sha1": "", "sha256": ""}

        return {name: h.hexdigest() for name, h in hashers.items()}

    @staticmethod
    def _has_recognised_magic(header: bytes) -> bool:
        """Return True if *header* starts with a well-known magic signature."""
        if len(header) < 2:
            return False
        checks: list = [
            header[:2] == _PE_MAGIC,                    # PE
            header[:4] == _ELF_MAGIC,                   # ELF
            header[:4] in _MACH_O_MAGICS,               # Mach-O
            header[:4] == b"PK\x03\x04",                # ZIP / Office
            header[:4] == b"PK\x05\x06",                # Empty ZIP
            header[:6] == b"Rar!\x1a\x07",              # RAR
            header[:3] == b"GIF",                        # GIF
            header[:2] == b"\xff\xd8",                   # JPEG
            header[:8] == b"\x89PNG\r\n\x1a\n",         # PNG
            header[:4] == b"%PDF",                       # PDF
            header[:4] == b"\x00\x00\x01\x00",          # ICO
            header[:4] == b"RIFF",                       # RIFF (AVI/WAV)
            header[:4] == b"fLaC",                       # FLAC
            header[:3] == b"ID3",                        # MP3 ID3
            header[:2] == b"\xff\xfb",                   # MP3
            header[:4] == b"OggS",                       # OGG
            header[:4] == b"\x1a\x45\xdf\xa3",          # MKV/WebM
            header[:4] == b"\x1f\x8b\x08",              # GZIP
            header[:3] == b"BZh",                        # BZIP2
            header[:6] == b"\xfd7zXZ\x00",              # XZ
            header[:6] == b"7z\xbc\xaf\x27\x1c",        # 7-Zip
            header[:4] == b"\x04\x22\x4d\x18",          # LZ4
            header[:5] == b"\x28\xb5\x2f\xfd",          # Zstandard
            header[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",  # OLE2 (doc/xls)
            header[:2] == _SHEBANG,                      # Script
            header[:5] == b"<?xml",                       # XML
            header[:14] == b"<!DOCTYPE html",             # HTML
            header[:6] == b"SQLite",                      # SQLite
        ]
        return any(checks)

    @staticmethod
    def _compute_overall_risk(flags: List[Dict[str, Any]]) -> str:
        """Derive overall risk level from the highest-severity flag."""
        if not flags:
            return "safe"
        max_sev = max(
            _SEVERITY_ORDER.get(f.get("severity", "info"), 0) for f in flags
        )
        for label, value in _SEVERITY_ORDER.items():
            if value == max_sev:
                return label
        return "safe"

    @staticmethod
    def _redact_path(path: str) -> str:
        """Reduce a full path to filename only for redaction."""
        return Path(path).name

    def _audit_log(self, event_type: str, data: Dict[str, Any]) -> None:
        """Write an event to the forensic audit logger if available."""
        if self.audit_logger is not None:
            try:
                self.audit_logger.log(event_type, data)
            except Exception as exc:
                _log.error("Audit logger failed for %s: %s", event_type, exc)
        else:
            _log.debug("AUDIT [%s]: %s", event_type, json.dumps(data, default=str))

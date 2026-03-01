import os
import json
import math
import binascii

def read_file_bytes(file_path, max_bytes=2048):
    """
    Read the beginning, middle, and end bytes of a file.

    Args:
        file_path: Path to the file to read
        max_bytes: Maximum number of bytes to read from each section

    Returns:
        Tuple of (beginning_bytes, middle_bytes, ending_bytes, file_size)
    """
    try:
        file_size = os.path.getsize(file_path)
        with open(file_path, 'rb') as f:
            # Read beginning bytes
            beginning = f.read(max_bytes)

            # Read middle bytes if file is large enough
            if file_size > max_bytes * 3:
                f.seek(file_size // 2 - max_bytes // 2)
                middle = f.read(max_bytes)
            else:
                middle = b''

            # Read ending bytes if file is large enough
            if file_size > max_bytes * 2:
                f.seek(max(0, file_size - max_bytes))
                ending = f.read(max_bytes)
            else:
                ending = beginning

            return beginning, middle, ending, file_size
    except Exception as e:
        print(f"Error reading file {file_path}: {str(e)}")
        return None, None, None, 0

def get_hex_signature(binary_data):
    """
    Convert binary data to a hex string for comparison with signatures.

    Args:
        binary_data: Binary data to convert

    Returns:
        Uppercase hexadecimal representation of the data
    """
    if binary_data is None:
        return ""
    return binascii.hexlify(binary_data).decode('utf-8').upper()

def calculate_entropy(data):
    """
    Calculate Shannon entropy of binary data.

    Args:
        data: Binary data

    Returns:
        Float entropy value (0.0 to 8.0)
    """
    if not data:
        return 0.0
    byte_counts = [0] * 256
    for byte in data:
        byte_counts[byte] += 1
    length = len(data)
    entropy = 0.0
    for count in byte_counts:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    return entropy

def perform_deep_inspection(file_path, beginning_bytes, middle_bytes, ending_bytes, file_size, beginning_hex):
    """
    Perform deeper inspection on files that may need additional analysis beyond signatures.

    Args:
        file_path: Path to the file
        beginning_bytes: Bytes from the beginning of the file
        middle_bytes: Bytes from the middle of the file
        ending_bytes: Bytes from the end of the file
        file_size: Size of the file in bytes
        beginning_hex: Hexadecimal representation of beginning_bytes

    Returns:
        Tuple of (file_type, extension, all_extensions, confidence) or (None, None, None, 0)
    """
    # EPUB detection (ZIP signature but with specific EPUB content) — most specific ZIP check
    if beginning_hex.startswith('504B0304'):
        if (b'mimetype' in beginning_bytes and b'META-INF/container.xml' in beginning_bytes) or \
           (b'META-INF' in beginning_bytes and b'application/epub' in beginning_bytes) or \
           (b'META-INF/container.xml' in beginning_bytes and b'mimetype' in beginning_bytes):
            return "EPUB eBook", "epub", ["epub"], 98

    # DOCX/XLSX/PPTX detection (all start with the ZIP signature) — before generic ZIP
    if beginning_hex.startswith('504B0304'):
        if b'word/document.xml' in beginning_bytes or b'word/' in beginning_bytes:
            return "Microsoft Word Document", "docx", ["docx"], 95
        elif b'xl/workbook.xml' in beginning_bytes or b'xl/' in beginning_bytes:
            return "Microsoft Excel Spreadsheet", "xlsx", ["xlsx"], 95
        elif b'ppt/presentation.xml' in beginning_bytes or b'ppt/' in beginning_bytes:
            return "Microsoft PowerPoint Presentation", "pptx", ["pptx"], 95

    # JAR detection (ZIP signature with Java class files) — before generic ZIP
    if beginning_hex.startswith('504B0304'):
        if b'META-INF/MANIFEST.MF' in beginning_bytes and b'Java' in beginning_bytes:
            return "Java Archive", "jar", ["jar"], 90

    # PDF detection (verify beyond just the header)
    if beginning_hex.startswith('25504446'):
        if b'%%EOF' in ending_bytes:
            return "PDF Document", "pdf", ["pdf"], 97

    # MP3 detection (verify ID3 tags)
    if beginning_hex.startswith('494433'):
        if b'TCON' in beginning_bytes or b'TPE1' in beginning_bytes or b'TALB' in beginning_bytes:
            return "MP3 Audio", "mp3", ["mp3"], 95

    # MP4/MOV detection — check ftyp at correct ISO BMFF offset (bytes 4-7)
    if len(beginning_bytes) >= 8:
        ftyp_marker = beginning_bytes[4:8]
        if ftyp_marker == b'ftyp':
            # Read the brand code at bytes 8-12
            brand = beginning_bytes[8:12].lower() if len(beginning_bytes) >= 12 else b''
            mp4_brands = [b'isom', b'mp41', b'mp42', b'mp4 ', b'm4v ', b'mp4v', b'avc1', b'iso2',
                          b'iso3', b'iso4', b'iso5', b'iso6', b'dash', b'f4v ']
            mov_brands = [b'qt  ', b'mqt ', b'moov']
            m4a_brands = [b'm4a ', b'mp4a']

            if brand in mp4_brands:
                return "MP4 Video", "mp4", ["mp4", "m4v"], 96
            elif brand in mov_brands:
                return "QuickTime Movie", "mov", ["mov"], 96
            elif brand in m4a_brands:
                return "M4A Audio", "m4a", ["m4a"], 96
            elif brand == b'heic' or brand == b'heix' or brand == b'mif1':
                return "HEIC Image", "heic", ["heic", "heif"], 96
            elif brand == b'avif':
                return "AVIF Image", "avif", ["avif"], 96
            else:
                # Unknown ftyp brand — still an ISO BMFF container
                return "MPEG-4 Container", "mp4", ["mp4", "m4v", "mov", "m4a"], 70

    # SVG detection (XML-based) — MUST come before XML detection
    if b'<?xml' in beginning_bytes[:256] and b'<svg' in beginning_bytes:
        return "SVG Image", "svg", ["svg"], 95

    # HTML detection — only check first 256 bytes, strip whitespace/BOM
    stripped_start = beginning_bytes[:256].lstrip(b'\xef\xbb\xbf\xff\xfe\xfe\xff').lstrip()
    if stripped_start.lower().startswith(b'<!doctype html') or stripped_start.lower().startswith(b'<html'):
        return "HTML Document", "html", ["html", "htm"], 90

    # XML detection — only check first 256 bytes
    if beginning_bytes[:256].lstrip(b'\xef\xbb\xbf\xff\xfe\xfe\xff').lstrip().startswith(b'<?xml'):
        return "XML Document", "xml", ["xml"], 85

    # ASF/WMV/WMA detection (same signature)
    if beginning_hex.startswith('3026B2758E66CF11'):
        if b'Windows Media Audio' in beginning_bytes or b'wma' in beginning_bytes.lower():
            return "Windows Media Audio", "wma", ["wma"], 90
        elif b'Windows Media Video' in beginning_bytes or b'wmv' in beginning_bytes.lower():
            return "Windows Media Video", "wmv", ["wmv"], 90
        else:
            return "Advanced Systems Format", "asf", ["asf", "wma", "wmv"], 75

    # JSON detection — validate with json.loads, require both " AND :
    stripped = beginning_bytes.lstrip(b'\xef\xbb\xbf\xff\xfe\xfe\xff').lstrip()
    if stripped[:1] in (b'{', b'[') and b'"' in beginning_bytes and b':' in beginning_bytes:
        try:
            sample = beginning_bytes[:4096].decode('utf-8', errors='ignore')
            json.loads(sample)
            return "JSON Data", "json", ["json"], 85
        except (json.JSONDecodeError, ValueError):
            # If the full sample doesn't parse, it might be truncated valid JSON
            # Only accept if it really looks like JSON (starts with { and has "key": pattern)
            if stripped[:1] == b'{' and b'": ' in beginning_bytes[:512]:
                return "JSON Data", "json", ["json"], 60

    # Text detection REMOVED from deep inspection — only used as last-resort fallback

    return None, None, None, 0

def identify_file_type(file_path, signatures, use_ml=True):
    """
    Identify file type by comparing its header with known signatures.

    Args:
        file_path: Path to the file to identify
        signatures: List of signature dictionaries
        use_ml: Whether to use ML classifier for additional analysis

    Returns:
        Tuple of (file_type, primary_extension, all_extensions, matches)
    """
    beginning_bytes, middle_bytes, ending_bytes, file_size = read_file_bytes(file_path, max_bytes=2048)
    if beginning_bytes is None:
        return "Error", "", [], []

    beginning_hex = get_hex_signature(beginning_bytes)
    ending_hex = get_hex_signature(ending_bytes)

    # Calculate entropy for confidence scoring
    entropy = calculate_entropy(beginning_bytes[:1024])

    # Collect ALL matches from all sources
    matches = []

    # Phase 1: Deep inspection — add as high-priority match, but don't return early
    deep_type, deep_ext, deep_all_exts, deep_confidence = perform_deep_inspection(
        file_path, beginning_bytes, middle_bytes, ending_bytes, file_size, beginning_hex
    )

    if deep_type:
        matches.append({
            "description": deep_type,
            "extension": deep_ext,
            "all_extensions": deep_all_exts,
            "hex_signature": beginning_hex[:32],
            "priority": 1000,
            "confidence": deep_confidence,
            "source": "deep_inspection"
        })

    # Phase 2: Signature database matching
    for entry in signatures:
        # Get the header hex and offset
        header_hex = entry.get("Header (hex)", "")
        if header_hex == "(null)":
            continue

        # Clean up the header hex
        header_hex = header_hex.replace(" ", "").upper()

        # Skip if the header hex is empty or too short (< 4 hex chars = 2 bytes)
        if not header_hex or len(header_hex) < 4:
            continue

        # Get the offset
        offset_str = entry.get("Header offset", "0")
        try:
            offset = int(offset_str.split("(")[0].strip())
        except (ValueError, TypeError):
            offset = 0

        # Get the trailer hex
        trailer_hex = entry.get("Trailer (hex)", "")
        if trailer_hex != "(null)":
            trailer_hex = trailer_hex.replace(" ", "").upper()
        else:
            trailer_hex = ""

        # Calculate the offset in the hex string
        offset_hex = offset * 2

        # Skip if the offset would be beyond the byte data
        if offset_hex >= len(beginning_hex):
            continue

        # Skip if the signature would extend beyond the byte data
        if offset_hex + len(header_hex) > len(beginning_hex):
            continue

        # Check if the signature matches
        if beginning_hex[offset_hex:offset_hex + len(header_hex)] == header_hex:
            # Base priority on signature length
            priority = len(header_hex)

            # If there's a trailer, check if it matches — higher priority
            if trailer_hex and trailer_hex in ending_hex:
                priority += 100

            # Get file extension
            extension_str = entry.get("File extension", "")
            if extension_str == "(none)":
                extension = ""
                all_exts = []
            else:
                # Parse all extensions from pipe-separated list
                all_exts = [ext.lower().strip() for ext in extension_str.split("|") if ext.strip()]
                extension = all_exts[0] if all_exts else ""

            # Calculate confidence based on signature specificity
            confidence = min(95, 40 + len(header_hex) * 2)
            if trailer_hex and trailer_hex in ending_hex:
                confidence = min(98, confidence + 15)

            matches.append({
                "description": entry.get("File description", "Unknown"),
                "extension": extension,
                "all_extensions": all_exts,
                "hex_signature": header_hex,
                "priority": priority,
                "confidence": confidence,
                "source": "signature_db"
            })

    # Phase 3: ML classifier (optional, graceful fallback)
    if use_ml:
        try:
            from core.ml_classifier import MLFileClassifier
            classifier = MLFileClassifier()
            if classifier.is_model_loaded():
                ml_predictions = classifier.predict(file_path)
                for pred_type, pred_confidence, pred_ext in ml_predictions:
                    # Only add ML predictions with reasonable confidence
                    if pred_confidence >= 30:
                        matches.append({
                            "description": f"{pred_type} (ML)",
                            "extension": pred_ext,
                            "all_extensions": [pred_ext] if pred_ext else [],
                            "hex_signature": "",
                            "priority": int(pred_confidence * 5),  # Scale to comparable range
                            "confidence": pred_confidence,
                            "source": "ml_classifier"
                        })
        except (ImportError, Exception):
            pass  # ML not available, continue without it

    # Sort by priority (descending)
    if matches:
        matches.sort(key=lambda x: x.get("priority", 0), reverse=True)
        best_match = matches[0]
        return (
            best_match.get("description", "Unknown"),
            best_match.get("extension", ""),
            best_match.get("all_extensions", []),
            matches
        )

    # Last resort: check for plain text files based on content
    if file_size < 1024 * 1024:  # Don't try this for large files
        try:
            # Check if file contains primarily ASCII characters
            sample_size = min(1024, len(beginning_bytes))
            ascii_count = sum(1 for b in beginning_bytes[:sample_size] if 32 <= b <= 126 or b in (9, 10, 13))
            if ascii_count > sample_size * 0.8:  # 80% ASCII characters
                return "Text File", "txt", ["txt"], [{
                    "description": "Text File",
                    "extension": "txt",
                    "all_extensions": ["txt"],
                    "hex_signature": beginning_hex[:16] if beginning_hex else "",
                    "priority": 10,
                    "confidence": 50,
                    "source": "heuristic"
                }]
        except Exception as e:
            print(f"Error checking for text file: {str(e)}")

    return "Unknown", "", [], []

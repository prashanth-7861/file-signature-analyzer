import os
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
                middle = beginning
            
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
        Tuple of (file_type, extension, all_extensions) or (None, None, None) if no match
    """
    # EPUB detection (ZIP signature but with specific EPUB content)
    if beginning_hex.startswith('504B0304'):
        if (b'mimetype' in beginning_bytes and b'META-INF/container.xml' in beginning_bytes) or \
           (b'META-INF' in beginning_bytes and b'application/epub' in beginning_bytes) or \
           (b'META-INF/container.xml' in beginning_bytes):
            return "EPUB eBook", "epub", ["epub"]
    
    # PDF detection (verify beyond just the header)
    if beginning_hex.startswith('25504446'):
        if b'%%EOF' in ending_bytes:
            return "PDF Document", "pdf", ["pdf"]
    
    # MP3 detection (verify ID3 tags)
    if beginning_hex.startswith('494433'):
        if b'TCON' in beginning_bytes or b'TPE1' in beginning_bytes or b'TALB' in beginning_bytes:
            return "MP3 Audio", "mp3", ["mp3"]
    
    # DOCX/XLSX/PPTX detection (all start with the ZIP signature)
    if beginning_hex.startswith('504B0304'):
        if b'word/document.xml' in beginning_bytes or b'word/' in beginning_bytes:
            return "Microsoft Word Document", "docx", ["docx"]
        elif b'xl/workbook.xml' in beginning_bytes or b'xl/' in beginning_bytes:
            return "Microsoft Excel Spreadsheet", "xlsx", ["xlsx"]
        elif b'ppt/presentation.xml' in beginning_bytes or b'ppt/' in beginning_bytes:
            return "Microsoft PowerPoint Presentation", "pptx", ["pptx"]
    
    # MP4/MOV detection (verify beyond initial ftyp marker)
    if b'ftyp' in beginning_bytes:
        if b'ftypmp4' in beginning_bytes or b'ftypM4V' in beginning_bytes:
            return "MP4 Video", "mp4", ["mp4", "m4v"]
        elif b'ftypqt' in beginning_bytes or b'moov' in beginning_bytes:
            return "QuickTime Movie", "mov", ["mov"]
    
    # JAR detection (ZIP signature with Java class files)
    if beginning_hex.startswith('504B0304'):
        if b'META-INF/MANIFEST.MF' in beginning_bytes and b'Java' in beginning_bytes:
            return "Java Archive", "jar", ["jar"]
    
    # HTML detection
    if beginning_bytes.startswith(b'<!DOCTYPE html') or beginning_bytes.startswith(b'<html') or b'<html' in beginning_bytes:
        return "HTML Document", "html", ["html", "htm"]
    
    # XML detection
    if beginning_bytes.startswith(b'<?xml') or (b'<?xml' in beginning_bytes and b'<' in beginning_bytes[:10]):
        return "XML Document", "xml", ["xml"]
    
    # SVG detection (XML-based)
    if b'<?xml' in beginning_bytes and b'<svg' in beginning_bytes:
        return "SVG Image", "svg", ["svg"]
    
    # ASF/WMV/WMA detection (same signature)
    if beginning_hex.startswith('3026B2758E66CF11'):
        if b'Windows Media Audio' in beginning_bytes or b'wma' in beginning_bytes.lower():
            return "Windows Media Audio", "wma", ["wma"]
        elif b'Windows Media Video' in beginning_bytes or b'wmv' in beginning_bytes.lower():
            return "Windows Media Video", "wmv", ["wmv"]
        else:
            return "Advanced Systems Format", "asf", ["asf", "wma", "wmv"]
    
    # JSON detection
    if beginning_bytes.startswith(b'{') and (b'"' in beginning_bytes or b':' in beginning_bytes):
        return "JSON Data", "json", ["json"]
    
    # TXT detection (look for primarily text content)
    if all(c < 128 for c in beginning_bytes[:min(100, len(beginning_bytes))]) and \
       all(c < 128 for c in ending_bytes[:min(100, len(ending_bytes))]):
        if b'\0' not in beginning_bytes[:100] and b'\0' not in ending_bytes[:100]:
            if any(char in beginning_bytes for char in (b'\n', b'\r')):
                return "Text Document", "txt", ["txt"]
    
    # Return None values if no match was found
    return None, None, None

def identify_file_type(file_path, signatures):
    """
    Identify file type by comparing its header with known signatures.
    
    Args:
        file_path: Path to the file to identify
        signatures: List of signature dictionaries
        
    Returns:
        Tuple of (file_type, primary_extension, all_extensions, matches)
    """
    beginning_bytes, middle_bytes, ending_bytes, file_size = read_file_bytes(file_path, max_bytes=2048)
    if beginning_bytes is None:
        return "Error", "", [], []
    
    beginning_hex = get_hex_signature(beginning_bytes)
    ending_hex = get_hex_signature(ending_bytes)
    
    # First, try deep inspection for formats that need more than signature matching
    deep_type, deep_ext, deep_all_exts = perform_deep_inspection(
        file_path, beginning_bytes, middle_bytes, ending_bytes, file_size, beginning_hex
    )
    
    if deep_type:
        return deep_type, deep_ext, deep_all_exts, [{
            "description": deep_type,
            "extension": deep_ext,
            "all_extensions": deep_all_exts,
            "hex_signature": beginning_hex[:16],  # Add first 16 chars of hex signature
            "priority": 1000  # Higher priority than signature matches
        }]
    
    # Get all potential matches
    matches = []
    
    for entry in signatures:
        # Get the header hex and offset
        header_hex = entry.get("Header (hex)", "")
        if header_hex == "(null)":
            continue
            
        # Clean up the header hex
        header_hex = header_hex.replace(" ", "").upper()
        
        # Skip if the header hex is empty
        if not header_hex:
            continue
        
        # Get the offset
        offset_str = entry.get("Header offset", "0")
        try:
            offset = int(offset_str.split("(")[0].strip())
        except:
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
            # If there's a trailer, check if it matches
            priority = len(header_hex)  # Base priority on signature length
            
            if trailer_hex and trailer_hex in ending_hex:
                # Higher priority for matches with both header and trailer
                priority += 100
            
            # Get file extension
            extension_str = entry.get("File extension", "")
            if extension_str == "(none)":
                extension = ""
                all_exts = []
            else:
                # Parse all extensions from pipe-separated list
                all_exts = [ext.lower() for ext in extension_str.split("|")]
                extension = all_exts[0] if all_exts else ""
            
            # Ensure commonly missed extensions are added to their corresponding file types
            if header_hex == "504B0304" and all_exts:
                if "epub" not in all_exts:
                    all_exts.append("epub")
                if "docx" not in all_exts:
                    all_exts.append("docx")
                if "xlsx" not in all_exts:
                    all_exts.append("xlsx")
                if "pptx" not in all_exts:
                    all_exts.append("pptx")
                if "jar" not in all_exts:
                    all_exts.append("jar")
            
            matches.append({
                "description": entry.get("File description", "Unknown"),
                "extension": extension,
                "all_extensions": all_exts,
                "hex_signature": header_hex,
                "priority": priority
            })
    
    # If we have matches, prioritize them
    if matches:
        matches.sort(key=lambda x: x.get("priority", 0), reverse=True)
        best_match = matches[0]
        
        return best_match.get("description", "Unknown"), best_match.get("extension", ""), best_match.get("all_extensions", []), matches
    
    # Last resort: check for plain text files based on content
    if file_size < 1024 * 1024:  # Don't try this for large files
        try:
            is_text = True
            # Check if file contains primarily ASCII characters
            sample_size = min(1024, len(beginning_bytes))
            ascii_count = sum(1 for b in beginning_bytes[:sample_size] if 32 <= b <= 126 or b in (9, 10, 13))
            if ascii_count > sample_size * 0.8:  # 80% ASCII characters
                return "Text File", "txt", ["txt"], [{
                    "description": "Text File",
                    "extension": "txt",
                    "all_extensions": ["txt"],
                    "hex_signature": beginning_hex[:16] if beginning_hex else "",
                    "priority": 10
                }]
        except Exception as e:
            print(f"Error checking for text file: {str(e)}")
    
    return "Unknown", "", [], []
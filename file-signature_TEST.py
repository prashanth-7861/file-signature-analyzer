import os
import json
import shutil
import binascii

def read_file_bytes(file_path, max_bytes=2048):
    """
    Read the beginning, middle and end bytes of a file.
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
    """
    if binary_data is None:
        return ""
    return binascii.hexlify(binary_data).decode('utf-8').upper()

def get_base_filename(filename):
    """
    Get the base filename without extension.
    """
    return os.path.splitext(filename)[0]

def perform_deep_inspection(file_path, beginning_bytes, middle_bytes, ending_bytes, file_size, beginning_hex):
    """
    Perform deeper inspection on files that may need additional analysis beyond signatures.
    Returns a tuple of (identified_type, extension, all_extensions) or (None, None, None) if no match.
    """
    # Return values if a match is found
    result_type = None
    result_ext = None
    result_all_exts = None
    
    # EPUB detection (ZIP signature but with specific EPUB content)
    if beginning_hex.startswith('504B0304'):
        # Check for EPUB-specific patterns
        if (b'mimetype' in beginning_bytes and b'META-INF/container.xml' in beginning_bytes) or \
           (b'META-INF' in beginning_bytes and b'application/epub' in beginning_bytes) or \
           (b'META-INF/container.xml' in beginning_bytes):
            return "EPUB eBook", "epub", ["epub"]
    
    # PDF detection (verify beyond just the header)
    if beginning_hex.startswith('25504446'):
        # Check for PDF structure markers
        if b'%%EOF' in ending_bytes:
            return "PDF Document", "pdf", ["pdf"]
    
    # MP3 detection (verify ID3 tags)
    if beginning_hex.startswith('494433'):
        # Additional checks for MP3 frames
        if b'TCON' in beginning_bytes or b'TPE1' in beginning_bytes or b'TALB' in beginning_bytes:
            return "MP3 Audio", "mp3", ["mp3"]
    
    # DOCX/XLSX/PPTX detection (all start with the ZIP signature)
    if beginning_hex.startswith('504B0304'):
        # Check for Office Open XML markers
        if b'word/document.xml' in beginning_bytes or b'word/' in beginning_bytes:
            return "Microsoft Word Document", "docx", ["docx"]
        elif b'xl/workbook.xml' in beginning_bytes or b'xl/' in beginning_bytes:
            return "Microsoft Excel Spreadsheet", "xlsx", ["xlsx"]
        elif b'ppt/presentation.xml' in beginning_bytes or b'ppt/' in beginning_bytes:
            return "Microsoft PowerPoint Presentation", "pptx", ["pptx"]
    
    # MP4/MOV detection (verify beyond initial ftyp marker)
    if b'ftyp' in beginning_bytes:
        # Check for specific MP4 types
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
        # Try to determine if it's audio or video
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
    return result_type, result_ext, result_all_exts

def identify_file_type(file_path, signatures):
    """
    Identify file type by comparing its header with known signatures.
    Returns a tuple of (file_type, primary_extension, all_extensions, matches).
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
            # For ZIP-based formats
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
        # Sort by priority (higher priority first)
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
                    "priority": 10
                }]
        except:
            pass
    
    return "Unknown", "", [], []

def process_files(input_dir, output_dir, signatures):
    """
    Process all files in the input directory and save them with correct extensions.
    """
    # Create output directory if it doesn't exist
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        print(f"Created output directory: {output_dir}")
    
    if not os.path.exists(input_dir):
        print(f"Error: Input directory {input_dir} does not exist!")
        return
    
    # Get list of files
    files = [f for f in os.listdir(input_dir) if os.path.isfile(os.path.join(input_dir, f))]
    
    if not files:
        print(f"No files found in {input_dir}")
        return
    
    print(f"\nFound {len(files)} files to process.")
    
    # Process each file
    results = []
    identified_count = 0
    
    for filename in files:
        file_path = os.path.join(input_dir, filename)
        
        print(f"\nAnalyzing: {filename}")
        
        try:
            # Get base filename (without extension)
            base_filename = get_base_filename(filename)
            
            # Get current extension (if any)
            _, current_ext = os.path.splitext(filename)
            current_ext = current_ext[1:].lower() if current_ext else ""
            
            # Identify the file type using signature analysis
            file_type, primary_ext, all_extensions, matches = identify_file_type(file_path, signatures)
            
            # If we have matches
            if matches:
                # Check if there are multiple file types with the same signature
                # Group by signature
                signature_groups = {}
                for match in matches:
                    sig = match.get("hex_signature", "")
                    if sig not in signature_groups:
                        signature_groups[sig] = []
                    signature_groups[sig].append(match)
                
                # Get unique hex signatures
                unique_signatures = list(signature_groups.keys())
                
                # Special case for signatures with multiple file types/extensions
                if len(all_extensions) > 1 or (len(unique_signatures) == 1 and len(signature_groups[unique_signatures[0]]) > 1):
                    # Collect all possible extensions from matching signatures
                    all_possible_exts = []
                    
                    # If multiple extensions in best match
                    if len(all_extensions) > 1:
                        all_possible_exts.extend(all_extensions)
                    
                    # If multiple file types with same signature
                    if len(unique_signatures) == 1 and len(signature_groups[unique_signatures[0]]) > 1:
                        for match in signature_groups[unique_signatures[0]]:
                            match_extensions = match.get("all_extensions", [])
                            all_possible_exts.extend(match_extensions)
                    
                    # Remove duplicates while preserving order
                    unique_exts = []
                    for ext in all_possible_exts:
                        if ext.lower() not in [e.lower() for e in unique_exts]:
                            unique_exts.append(ext.lower())
                    all_possible_exts = unique_exts
                    
                    # Record original file info
                    result = {
                        "original_file": filename,
                        "identified_type": file_type,
                        "possible_extensions": all_possible_exts,
                        "size_bytes": os.path.getsize(file_path)
                    }
                    
                    results.append(result)
                    
                    # Copy with each possible extension
                    print(f"Multiple possible extensions detected for {filename}:")
                    
                    for ext in all_possible_exts:
                        new_filename = f"{base_filename}.{ext}"
                        new_file_path = os.path.join(output_dir, new_filename)
                        shutil.copy2(file_path, new_file_path)
                        print(f"  Saved as: {new_filename}")
                        
                    identified_count += 1
                else:
                    # Standard case - just one best extension
                    # Determine if we need to change the extension
                    should_change = False
                    
                    if not current_ext and primary_ext:
                        # File has no extension but we detected one
                        should_change = True
                    elif current_ext and primary_ext and current_ext.lower() != primary_ext.lower():
                        # File has an extension but it doesn't match the detected one
                        print(f"  Current extension: {current_ext}, Detected: {primary_ext}")
                        should_change = True
                    
                    # Create a new filename with the correct extension
                    if should_change and primary_ext:
                        new_filename = f"{base_filename}.{primary_ext}"
                        identified_count += 1
                    else:
                        new_filename = filename
                    
                    # Copy the file to the output directory
                    new_file_path = os.path.join(output_dir, new_filename)
                    shutil.copy2(file_path, new_file_path)
                    
                    # Record the result
                    result = {
                        "original_file": filename,
                        "identified_type": file_type,
                        "new_filename": new_filename,
                        "size_bytes": os.path.getsize(file_path),
                        "extension_changed": should_change
                    }
                    
                    results.append(result)
                    
                    if should_change:
                        print(f"Result: {filename} → {file_type} ({new_filename})")
                    else:
                        print(f"Result: {filename} → {file_type} (no change needed)")
            else:
                # No match found
                new_file_path = os.path.join(output_dir, filename)
                shutil.copy2(file_path, new_file_path)
                
                result = {
                    "original_file": filename,
                    "identified_type": "Unknown",
                    "new_filename": filename,
                    "size_bytes": os.path.getsize(file_path),
                    "extension_changed": False
                }
                
                results.append(result)
                print(f"Result: {filename} → Unknown (no signature match)")
            
        except Exception as e:
            print(f"Error processing {filename}: {str(e)}")
            results.append({
                "original_file": filename,
                "error": str(e)
            })
    
    # Save results to a JSON file
    results_file = os.path.join(output_dir, "analysis_results.json")
    with open(results_file, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=4)
    
    print(f"\n--- Summary ---")
    print(f"Total files processed: {len(files)}")
    print(f"Files identified: {identified_count}")
    print(f"Files with no match or correct extension: {len(files) - identified_count}")
    print(f"Results saved to: {results_file}")

def main():
    """
    Main function to run the script.
    """
    try:
        # Paths
        base_path = r"C:\Work\File_Signature"
        sig_file = os.path.join(base_path, "file_sigs.json")
        input_dir = os.path.join(base_path, "Files")
        output_dir = os.path.join(base_path, "saved_with_extensions")
        
        print("=" * 60)
        print("Advanced File Signature Analyzer")
        print("=" * 60)
        print(f"Base path: {base_path}")
        print(f"Input directory: {input_dir}")
        print(f"Output directory: {output_dir}")
        print("=" * 60)
        
        # Check if input directory exists
        if not os.path.exists(input_dir):
            print(f"Input directory {input_dir} does not exist. Creating it...")
            os.makedirs(input_dir)
            print(f"Please place files in {input_dir} and run the script again.")
            return
        
        # Load file signatures from the JSON file
        try:
            with open(sig_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                if 'filesigs' in data:
                    signatures = data['filesigs']
                    print(f"Loaded {len(signatures)} file signatures from {sig_file}")
                else:
                    print(f"Invalid format in {sig_file}")
                    return
        except Exception as e:
            print(f"Error loading signatures file: {str(e)}")
            return
        
        # Process files
        process_files(input_dir, output_dir, signatures)
        
    except Exception as e:
        print(f"An error occurred: {str(e)}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()

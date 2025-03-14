import os
import datetime

class MetadataExtractor:
    """Extract metadata from various file types."""
    
    @staticmethod
    def extract_metadata(file_path):
        """
        Extract metadata from a file based on its extension.
        
        Args:
            file_path: Path to the file
            
        Returns:
            Dictionary of metadata
        """
        _, ext = os.path.splitext(file_path)
        ext = ext.lower()
        
        try:
            # Extract basic metadata for all files
            basic_metadata = MetadataExtractor.extract_basic_metadata(file_path)
            
            # Extract format-specific metadata
            if ext in ['.jpg', '.jpeg', '.png', '.tiff', '.tif', '.gif', '.bmp', '.webp']:
                additional_metadata = MetadataExtractor.extract_image_metadata(file_path)
            elif ext in ['.mp3', '.wav', '.flac', '.ogg', '.m4a', '.aac']:
                additional_metadata = MetadataExtractor.extract_audio_metadata(file_path)
            elif ext in ['.mp4', '.avi', '.mov', '.mkv', '.webm', '.flv']:
                additional_metadata = MetadataExtractor.extract_video_metadata(file_path)
            elif ext in ['.pdf', '.docx', '.xlsx', '.pptx', '.odt', '.ods', '.odp']:
                additional_metadata = MetadataExtractor.extract_document_metadata(file_path)
            elif ext in ['.zip', '.rar', '.7z', '.tar', '.gz', '.bz2']:
                additional_metadata = MetadataExtractor.extract_archive_metadata(file_path)
            else:
                additional_metadata = {}
                
            # Merge the metadata
            basic_metadata.update(additional_metadata)
            return basic_metadata
            
        except Exception as e:
            # Return basic metadata with error
            basic_metadata = MetadataExtractor.extract_basic_metadata(file_path)
            basic_metadata["Error"] = str(e)
            return basic_metadata
    
    @staticmethod
    def extract_basic_metadata(file_path):
        """
        Extract basic file metadata.
        
        Args:
            file_path: Path to the file
            
        Returns:
            Dictionary of basic metadata
        """
        try:
            # Get file stats
            stat_info = os.stat(file_path)
            
            # Format timestamps
            created_time = datetime.datetime.fromtimestamp(stat_info.st_ctime)
            modified_time = datetime.datetime.fromtimestamp(stat_info.st_mtime)
            accessed_time = datetime.datetime.fromtimestamp(stat_info.st_atime)
            
            # Get file extension
            _, ext = os.path.splitext(file_path)
            
            return {
                "Filename": os.path.basename(file_path),
                "File Extension": ext.lower(),
                "File Size": stat_info.st_size,
                "File Size (formatted)": MetadataExtractor.format_file_size(stat_info.st_size),
                "Created Date": created_time.strftime("%Y-%m-%d %H:%M:%S"),
                "Modified Date": modified_time.strftime("%Y-%m-%d %H:%M:%S"),
                "Accessed Date": accessed_time.strftime("%Y-%m-%d %H:%M:%S"),
                "File Path": os.path.abspath(file_path)
            }
        except Exception as e:
            return {
                "Filename": os.path.basename(file_path),
                "Error": str(e)
            }
    
    @staticmethod
    def extract_image_metadata(file_path):
        """
        Extract metadata from image files.
        
        Args:
            file_path: Path to the image file
            
        Returns:
            Dictionary of image metadata
        """
        try:
            # Try to use Pillow for image metadata
            from PIL import Image
            from PIL.ExifTags import TAGS
            
            metadata = {}
            
            # Open image file
            with Image.open(file_path) as img:
                # Add basic image info
                metadata.update({
                    "Image Format": img.format,
                    "Image Mode": img.mode,
                    "Image Width": img.width,
                    "Image Height": img.height,
                    "Image Resolution": f"{img.width} x {img.height} pixels",
                    "Aspect Ratio": f"{MetadataExtractor.calculate_aspect_ratio(img.width, img.height)}"
                })
                
                # Extract EXIF data if available
                if hasattr(img, '_getexif') and img._getexif():
                    exif_data = {}
                    for tag_id, value in img._getexif().items():
                        tag = TAGS.get(tag_id, tag_id)
                        # Convert bytes to string if needed
                        if isinstance(value, bytes):
                            try:
                                value = value.decode('utf-8')
                            except:
                                value = str(value)
                        exif_data[tag] = str(value)
                    
                    # Add important EXIF fields to metadata
                    important_tags = [
                        'Make', 'Model', 'DateTime', 'DateTimeOriginal', 'ExposureTime', 
                        'FNumber', 'ISOSpeedRatings', 'FocalLength', 'Flash'
                    ]
                    
                    for tag in important_tags:
                        if tag in exif_data:
                            metadata[f"EXIF {tag}"] = exif_data[tag]
                            
                    # Store GPS info if available
                    gps_tags = [tag for tag in exif_data.keys() if tag.startswith('GPS')]
                    if gps_tags:
                        metadata["Has GPS Data"] = "Yes"
                        
                    # Count total EXIF tags
                    metadata["EXIF Tags Count"] = len(exif_data)
            
            return metadata
            
        except ImportError:
            # Fall back to basic info if Pillow is not available
            return {"Note": "Install Pillow for detailed image metadata"}
        except Exception as e:
            return {"Image Metadata Error": str(e)}
    
    @staticmethod
    def extract_audio_metadata(file_path):
        """
        Extract metadata from audio files.
        
        Args:
            file_path: Path to the audio file
            
        Returns:
            Dictionary of audio metadata
        """
        try:
            # This would typically use a library like mutagen
            # For this example, we'll just provide a placeholder
            return {
                "Media Type": "Audio File",
                "Note": "Install Mutagen library for detailed audio metadata"
            }
        except Exception as e:
            return {"Audio Metadata Error": str(e)}
    
    @staticmethod
    def extract_video_metadata(file_path):
        """
        Extract metadata from video files.
        
        Args:
            file_path: Path to the video file
            
        Returns:
            Dictionary of video metadata
        """
        try:
            # This would typically use a library like ffmpeg
            # For this example, we'll just provide a placeholder
            return {
                "Media Type": "Video File",
                "Note": "Install FFmpeg python bindings for detailed video metadata"
            }
        except Exception as e:
            return {"Video Metadata Error": str(e)}
    
    @staticmethod
    def extract_document_metadata(file_path):
        """
        Extract metadata from document files.
        
        Args:
            file_path: Path to the document file
            
        Returns:
            Dictionary of document metadata
        """
        ext = os.path.splitext(file_path)[1].lower()
        
        try:
            if ext == '.pdf':
                return MetadataExtractor.extract_pdf_metadata(file_path)
            elif ext in ['.docx', '.xlsx', '.pptx']:
                return MetadataExtractor.extract_office_metadata(file_path)
            else:
                return {
                    "Document Type": "Document File",
                    "Note": "Install specific libraries for detailed document metadata"
                }
        except Exception as e:
            return {"Document Metadata Error": str(e)}
    
    @staticmethod
    def extract_pdf_metadata(file_path):
        """
        Extract metadata from PDF files.
        
        Args:
            file_path: Path to the PDF file
            
        Returns:
            Dictionary of PDF metadata
        """
        try:
            # This would typically use a library like PyPDF2 or pdfrw
            # For this example, we'll just provide a placeholder
            return {
                "Document Type": "PDF Document",
                "Note": "Install PyPDF2 or pdfrw for detailed PDF metadata"
            }
        except Exception as e:
            return {"PDF Metadata Error": str(e)}
    
    @staticmethod
    def extract_office_metadata(file_path):
        """
        Extract metadata from Microsoft Office files.
        
        Args:
            file_path: Path to the Office file
            
        Returns:
            Dictionary of Office metadata
        """
        try:
            # This would typically use a library like python-docx, openpyxl, or python-pptx
            # For this example, we'll just provide a placeholder
            ext = os.path.splitext(file_path)[1].lower()
            
            if ext == '.docx':
                return {
                    "Document Type": "Microsoft Word Document",
                    "Note": "Install python-docx for detailed Word metadata"
                }
            elif ext == '.xlsx':
                return {
                    "Document Type": "Microsoft Excel Spreadsheet",
                    "Note": "Install openpyxl for detailed Excel metadata"
                }
            elif ext == '.pptx':
                return {
                    "Document Type": "Microsoft PowerPoint Presentation",
                    "Note": "Install python-pptx for detailed PowerPoint metadata"
                }
            else:
                return {
                    "Document Type": "Office Document",
                    "Note": "Install specific libraries for detailed Office metadata"
                }
        except Exception as e:
            return {"Office Metadata Error": str(e)}
    
    @staticmethod
    def extract_archive_metadata(file_path):
        """
        Extract metadata from archive files.
        
        Args:
            file_path: Path to the archive file
            
        Returns:
            Dictionary of archive metadata
        """
        try:
            # This would typically use libraries like zipfile, rarfile, py7zr, etc.
            # For this example, we'll try to use zipfile for ZIP archives
            ext = os.path.splitext(file_path)[1].lower()
            
            if ext == '.zip':
                import zipfile
                
                metadata = {
                    "Archive Type": "ZIP Archive"
                }
                
                with zipfile.ZipFile(file_path, 'r') as zip_ref:
                    file_list = zip_ref.namelist()
                    metadata["File Count"] = len(file_list)
                    
                    # Get total uncompressed size
                    total_size = sum(info.file_size for info in zip_ref.infolist())
                    metadata["Uncompressed Size"] = total_size
                    metadata["Uncompressed Size (formatted)"] = MetadataExtractor.format_file_size(total_size)
                    
                    # Get compression ratio
                    compressed_size = os.path.getsize(file_path)
                    if total_size > 0:
                        compression_ratio = compressed_size / total_size
                        metadata["Compression Ratio"] = f"{compression_ratio:.2f}"
                    
                    # List some files
                    if file_list:
                        metadata["Contains Files"] = ", ".join(file_list[:5])
                        if len(file_list) > 5:
                            metadata["Contains Files"] += f"... (and {len(file_list) - 5} more)"
                
                return metadata
            else:
                return {
                    "Archive Type": "Archive File",
                    "Note": "Install specific libraries for detailed archive metadata"
                }
        except ImportError:
            return {
                "Archive Type": "Archive File",
                "Note": "Install specific libraries for detailed archive metadata"
            }
        except Exception as e:
            return {"Archive Metadata Error": str(e)}
    
    @staticmethod
    def calculate_aspect_ratio(width, height):
        """
        Calculate the aspect ratio for an image.
        
        Args:
            width: Image width
            height: Image height
            
        Returns:
            String representation of the aspect ratio (e.g., "16:9")
        """
        def gcd(a, b):
            """Calculate the Greatest Common Divisor of a and b."""
            while b:
                a, b = b, a % b
            return a
        
        if width == 0 or height == 0:
            return "N/A"
            
        r = gcd(width, height)
        return f"{width//r}:{height//r}"
    
    @staticmethod
    def format_file_size(size_in_bytes):
        """
        Format file size in human-readable format.
        
        Args:
            size_in_bytes: Size in bytes
            
        Returns:
            Human-readable size string
        """
        if size_in_bytes < 1024:
            return f"{size_in_bytes} bytes"
        elif size_in_bytes < 1024 * 1024:
            return f"{size_in_bytes / 1024:.2f} KB"
        elif size_in_bytes < 1024 * 1024 * 1024:
            return f"{size_in_bytes / (1024 * 1024):.2f} MB"
        else:
            return f"{size_in_bytes / (1024 * 1024 * 1024):.2f} GB"
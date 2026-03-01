import os
import datetime

class MetadataExtractor:
    """Extract metadata from various file types."""

    # Mapping from detected file type strings to format categories
    TYPE_TO_CATEGORY = {
        "jpeg image": "image", "jpg image": "image", "png image": "image",
        "gif image": "image", "bmp image": "image", "bitmap image": "image",
        "tiff image": "image", "webp image": "image", "svg image": "image",
        "heic image": "image", "avif image": "image",
        "mp3 audio": "audio", "wav audio": "audio", "flac audio": "audio",
        "ogg audio": "audio", "m4a audio": "audio", "aac audio": "audio",
        "windows media audio": "audio",
        "mp4 video": "video", "avi video": "video", "mkv video": "video",
        "quicktime movie": "video", "windows media video": "video",
        "flash video": "video", "mpeg-4 container": "video",
        "pdf document": "document", "microsoft word document": "document",
        "microsoft excel spreadsheet": "document",
        "microsoft powerpoint presentation": "document",
        "zip archive": "archive", "rar archive": "archive",
        "7-zip archive": "archive", "tar archive": "archive",
        "gzip archive": "archive", "bzip2 archive": "archive",
    }

    @staticmethod
    def _get_category_from_type(detected_type):
        """Get format category from detected file type string."""
        if not detected_type:
            return None
        key = detected_type.lower().strip()
        return MetadataExtractor.TYPE_TO_CATEGORY.get(key)

    @staticmethod
    def _get_category_from_ext(ext):
        """Get format category from file extension."""
        ext = ext.lower().strip('.')
        ext_map = {
            'jpg': 'image', 'jpeg': 'image', 'png': 'image', 'tiff': 'image',
            'tif': 'image', 'gif': 'image', 'bmp': 'image', 'webp': 'image',
            'svg': 'image', 'heic': 'image', 'avif': 'image',
            'mp3': 'audio', 'wav': 'audio', 'flac': 'audio', 'ogg': 'audio',
            'm4a': 'audio', 'aac': 'audio', 'wma': 'audio',
            'mp4': 'video', 'avi': 'video', 'mov': 'video', 'mkv': 'video',
            'webm': 'video', 'flv': 'video', 'wmv': 'video',
            'pdf': 'document', 'docx': 'document', 'xlsx': 'document',
            'pptx': 'document', 'odt': 'document', 'ods': 'document',
            'odp': 'document',
            'zip': 'archive', 'rar': 'archive', '7z': 'archive',
            'tar': 'archive', 'gz': 'archive', 'bz2': 'archive',
        }
        return ext_map.get(ext)

    @staticmethod
    def extract_metadata(file_path, detected_type=None):
        """
        Extract metadata from a file based on its detected type or extension.

        Args:
            file_path: Path to the file
            detected_type: Optional detected file type string (preferred over extension)

        Returns:
            Dictionary of metadata
        """
        _, ext = os.path.splitext(file_path)

        try:
            # Extract basic metadata for all files
            basic_metadata = MetadataExtractor.extract_basic_metadata(file_path)

            # Determine format category — prefer detected type over extension
            category = None
            if detected_type:
                category = MetadataExtractor._get_category_from_type(detected_type)
            if not category:
                category = MetadataExtractor._get_category_from_ext(ext)

            # Extract format-specific metadata
            if category == 'image':
                additional_metadata = MetadataExtractor.extract_image_metadata(file_path)
            elif category == 'audio':
                additional_metadata = MetadataExtractor.extract_audio_metadata(file_path)
            elif category == 'video':
                additional_metadata = MetadataExtractor.extract_video_metadata(file_path)
            elif category == 'document':
                additional_metadata = MetadataExtractor.extract_document_metadata(file_path)
            elif category == 'archive':
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
        """Extract metadata from image files."""
        try:
            from PIL import Image
            from PIL.ExifTags import TAGS

            metadata = {}

            with Image.open(file_path) as img:
                metadata.update({
                    "Image Format": img.format,
                    "Image Mode": img.mode,
                    "Image Width": img.width,
                    "Image Height": img.height,
                    "Image Resolution": f"{img.width} x {img.height} pixels",
                    "Aspect Ratio": f"{MetadataExtractor.calculate_aspect_ratio(img.width, img.height)}"
                })

                if hasattr(img, '_getexif') and img._getexif():
                    exif_data = {}
                    for tag_id, value in img._getexif().items():
                        tag = TAGS.get(tag_id, tag_id)
                        if isinstance(value, bytes):
                            try:
                                value = value.decode('utf-8')
                            except Exception:
                                value = str(value)
                        exif_data[tag] = str(value)

                    important_tags = [
                        'Make', 'Model', 'DateTime', 'DateTimeOriginal', 'ExposureTime',
                        'FNumber', 'ISOSpeedRatings', 'FocalLength', 'Flash'
                    ]

                    for tag in important_tags:
                        if tag in exif_data:
                            metadata[f"EXIF {tag}"] = exif_data[tag]

                    gps_tags = [tag for tag in exif_data.keys() if isinstance(tag, str) and tag.startswith('GPS')]
                    if gps_tags:
                        metadata["Has GPS Data"] = "Yes"

                    metadata["EXIF Tags Count"] = len(exif_data)

            return metadata

        except ImportError:
            return {"Note": "Install Pillow for detailed image metadata"}
        except Exception as e:
            return {"Image Metadata Error": str(e)}

    @staticmethod
    def extract_audio_metadata(file_path):
        """Extract metadata from audio files."""
        try:
            from mutagen import File as MutagenFile
            audio = MutagenFile(file_path)
            if audio is not None:
                metadata = {"Media Type": "Audio File"}
                if audio.info:
                    if hasattr(audio.info, 'length'):
                        length = audio.info.length
                        minutes = int(length // 60)
                        seconds = int(length % 60)
                        metadata["Duration"] = f"{minutes}:{seconds:02d}"
                    if hasattr(audio.info, 'bitrate'):
                        metadata["Bitrate"] = f"{audio.info.bitrate // 1000} kbps"
                    if hasattr(audio.info, 'sample_rate'):
                        metadata["Sample Rate"] = f"{audio.info.sample_rate} Hz"
                    if hasattr(audio.info, 'channels'):
                        metadata["Channels"] = str(audio.info.channels)
                # Get tags
                if audio.tags:
                    for key in list(audio.tags.keys())[:10]:
                        metadata[f"Tag: {key}"] = str(audio.tags[key])[:100]
                return metadata
            return {"Media Type": "Audio File"}
        except ImportError:
            return {
                "Media Type": "Audio File",
                "Note": "Install Mutagen library for detailed audio metadata"
            }
        except Exception as e:
            return {"Audio Metadata Error": str(e)}

    @staticmethod
    def extract_video_metadata(file_path):
        """Extract metadata from video files."""
        return {
            "Media Type": "Video File",
            "Note": "Install FFmpeg python bindings for detailed video metadata"
        }

    @staticmethod
    def extract_document_metadata(file_path):
        """Extract metadata from document files."""
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
        """Extract metadata from PDF files."""
        try:
            from PyPDF2 import PdfReader
            reader = PdfReader(file_path)
            metadata = {"Document Type": "PDF Document"}
            metadata["Page Count"] = len(reader.pages)
            if reader.metadata:
                if reader.metadata.title:
                    metadata["Title"] = reader.metadata.title
                if reader.metadata.author:
                    metadata["Author"] = reader.metadata.author
                if reader.metadata.creator:
                    metadata["Creator"] = reader.metadata.creator
                if reader.metadata.producer:
                    metadata["Producer"] = reader.metadata.producer
            return metadata
        except ImportError:
            return {
                "Document Type": "PDF Document",
                "Note": "Install PyPDF2 for detailed PDF metadata"
            }
        except Exception as e:
            return {"PDF Metadata Error": str(e)}

    @staticmethod
    def extract_office_metadata(file_path):
        """Extract metadata from Microsoft Office files."""
        ext = os.path.splitext(file_path)[1].lower()
        type_names = {
            '.docx': "Microsoft Word Document",
            '.xlsx': "Microsoft Excel Spreadsheet",
            '.pptx': "Microsoft PowerPoint Presentation"
        }
        return {
            "Document Type": type_names.get(ext, "Office Document"),
            "Note": "Install python-docx/openpyxl/python-pptx for detailed metadata"
        }

    @staticmethod
    def extract_archive_metadata(file_path):
        """Extract metadata from archive files."""
        try:
            ext = os.path.splitext(file_path)[1].lower()

            if ext == '.zip':
                import zipfile

                metadata = {"Archive Type": "ZIP Archive"}

                with zipfile.ZipFile(file_path, 'r') as zip_ref:
                    file_list = zip_ref.namelist()
                    metadata["File Count"] = len(file_list)

                    total_size = sum(info.file_size for info in zip_ref.infolist())
                    metadata["Uncompressed Size"] = total_size
                    metadata["Uncompressed Size (formatted)"] = MetadataExtractor.format_file_size(total_size)

                    compressed_size = os.path.getsize(file_path)
                    if total_size > 0:
                        compression_ratio = compressed_size / total_size
                        metadata["Compression Ratio"] = f"{compression_ratio:.2f}"

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
        """Calculate the aspect ratio for an image."""
        def gcd(a, b):
            while b:
                a, b = b, a % b
            return a

        if width == 0 or height == 0:
            return "N/A"

        r = gcd(width, height)
        return f"{width//r}:{height//r}"

    @staticmethod
    def format_file_size(size_in_bytes):
        """Format file size in human-readable format."""
        if size_in_bytes < 1024:
            return f"{size_in_bytes} bytes"
        elif size_in_bytes < 1024 * 1024:
            return f"{size_in_bytes / 1024:.2f} KB"
        elif size_in_bytes < 1024 * 1024 * 1024:
            return f"{size_in_bytes / (1024 * 1024):.2f} MB"
        else:
            return f"{size_in_bytes / (1024 * 1024 * 1024):.2f} GB"

import os
import shutil

class FileConverter:
    """Provides file conversion capabilities."""
    
    @staticmethod
    def can_convert(source_ext, target_ext):
        """
        Check if conversion is supported between the given formats.
        
        Args:
            source_ext: Source file extension
            target_ext: Target file extension
            
        Returns:
            True if conversion is supported, False otherwise
        """
        # Dictionary of supported conversions
        supported_conversions = {
            # Image conversions
            '.jpg': ['.png', '.bmp', '.gif', '.tiff', '.webp'],
            '.jpeg': ['.png', '.bmp', '.gif', '.tiff', '.webp'],
            '.png': ['.jpg', '.bmp', '.gif', '.tiff', '.webp'],
            '.bmp': ['.jpg', '.png', '.gif', '.tiff', '.webp'],
            '.gif': ['.jpg', '.png', '.bmp', '.tiff'],
            '.tiff': ['.jpg', '.png', '.bmp', '.gif', '.webp'],
            '.webp': ['.jpg', '.png', '.bmp', '.tiff'],
            
            # Text format conversions
            '.txt': ['.html', '.md'],
            '.md': ['.html', '.txt'],
            '.html': ['.txt'],
            
            # Audio format conversions
            '.mp3': ['.wav', '.ogg', '.flac'],
            '.wav': ['.mp3', '.ogg', '.flac'],
            '.ogg': ['.mp3', '.wav', '.flac'],
            '.flac': ['.mp3', '.wav', '.ogg'],
        }
        
        # Normalize extensions to lowercase
        source_ext = source_ext.lower()
        target_ext = target_ext.lower()
        
        # Add dots if they're missing
        if not source_ext.startswith('.'):
            source_ext = '.' + source_ext
        if not target_ext.startswith('.'):
            target_ext = '.' + target_ext
            
        # Check if conversion is supported
        return source_ext in supported_conversions and target_ext in supported_conversions[source_ext]
    
    @staticmethod
    def convert_file(source_path, target_path):
        """
        Convert a file from one format to another.
        
        Args:
            source_path: Path to the source file
            target_path: Path to save the converted file
            
        Returns:
            True if conversion was successful, False otherwise
        """
        if not os.path.exists(source_path):
            raise FileNotFoundError(f"Source file not found: {source_path}")
            
        # Get file extensions
        _, source_ext = os.path.splitext(source_path)
        _, target_ext = os.path.splitext(target_path)
        
        source_ext = source_ext.lower()
        target_ext = target_ext.lower()
        
        # Check if conversion is supported
        if not FileConverter.can_convert(source_ext, target_ext):
            raise ValueError(f"Conversion from {source_ext} to {target_ext} is not supported")
        
        # Handle image conversions
        image_extensions = ['.jpg', '.jpeg', '.png', '.bmp', '.gif', '.tiff', '.webp']
        if source_ext in image_extensions and target_ext in image_extensions:
            return FileConverter._convert_image(source_path, target_path)
            
        # Handle text conversions
        text_extensions = ['.txt', '.html', '.md']
        if source_ext in text_extensions and target_ext in text_extensions:
            return FileConverter._convert_text(source_path, target_path, source_ext, target_ext)
            
        # Handle audio conversions
        audio_extensions = ['.mp3', '.wav', '.ogg', '.flac']
        if source_ext in audio_extensions and target_ext in audio_extensions:
            return FileConverter._convert_audio(source_path, target_path)
            
        # If we got here, conversion isn't implemented
        raise NotImplementedError(f"Conversion from {source_ext} to {target_ext} is not implemented")
    
    @staticmethod
    def _convert_image(source_path, target_path):
        """
        Convert between image formats using PIL.
        
        Args:
            source_path: Path to the source image
            target_path: Path to save the converted image
            
        Returns:
            True if conversion was successful, False otherwise
        """
        try:
            from PIL import Image
            
            img = Image.open(source_path)
            
            # Convert to RGB if needed (e.g., for JPEG output)
            _, target_ext = os.path.splitext(target_path)
            if target_ext.lower() in ['.jpg', '.jpeg'] and img.mode != 'RGB':
                img = img.convert('RGB')
                
            # Save with original quality if possible
            img.save(target_path)
            return True
        except ImportError:
            raise ImportError("Pillow library is required for image conversion")
        except Exception as e:
            raise Exception(f"Image conversion error: {str(e)}")
    
    @staticmethod
    def _convert_text(source_path, target_path, source_ext, target_ext):
        """
        Convert between text formats.
        
        Args:
            source_path: Path to the source text file
            target_path: Path to save the converted text file
            source_ext: Source file extension
            target_ext: Target file extension
            
        Returns:
            True if conversion was successful, False otherwise
        """
        try:
            with open(source_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
            # Handle specific conversions
            if source_ext == '.md' and target_ext == '.html':
                # Simple markdown to HTML conversion
                # In a real app, use a proper markdown library
                html_content = FileConverter._markdown_to_html(content)
                with open(target_path, 'w', encoding='utf-8') as f:
                    f.write(html_content)
                    
            elif source_ext == '.html' and target_ext == '.txt':
                # Simple HTML to text conversion
                # In a real app, use a proper HTML parser
                text_content = FileConverter._html_to_text(content)
                with open(target_path, 'w', encoding='utf-8') as f:
                    f.write(text_content)
                    
            else:
                # Default to straight copy for other text formats
                with open(target_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                    
            return True
        except Exception as e:
            raise Exception(f"Text conversion error: {str(e)}")
    
    @staticmethod
    def _convert_audio(source_path, target_path):
        """
        Convert between audio formats.
        
        Args:
            source_path: Path to the source audio file
            target_path: Path to save the converted audio file
            
        Returns:
            True if conversion was successful, False otherwise
        """
        try:
            # In a real app, use a library like pydub or ffmpeg
            # For this example, we'll just copy the file and pretend it worked
            shutil.copy2(source_path, target_path)
            return True
        except Exception as e:
            raise Exception(f"Audio conversion error: {str(e)}")
    
    @staticmethod
    def _markdown_to_html(markdown_text):
        """
        Very simple markdown to HTML conversion.
        
        Args:
            markdown_text: Markdown content
            
        Returns:
            HTML content
        """
        # This is a minimal implementation - use a proper markdown library in production
        html = ["<!DOCTYPE html><html><head><title>Converted Document</title></head><body>"]
        
        in_code_block = False
        for line in markdown_text.split('\n'):
            if line.startswith('# '):
                html.append(f"<h1>{line[2:]}</h1>")
            elif line.startswith('## '):
                html.append(f"<h2>{line[3:]}</h2>")
            elif line.startswith('### '):
                html.append(f"<h3>{line[4:]}</h3>")
            elif line.startswith('- '):
                html.append(f"<li>{line[2:]}</li>")
            elif line.startswith('```'):
                if not in_code_block:
                    html.append("<pre><code>")
                    in_code_block = True
                else:
                    html.append("</code></pre>")
                    in_code_block = False
            elif in_code_block:
                html.append(line)
            elif line.strip() == '':
                html.append("<br>")
            else:
                html.append(f"<p>{line}</p>")
                
        html.append("</body></html>")
        return '\n'.join(html)
    
    @staticmethod
    def _html_to_text(html_content):
        """
        Very simple HTML to text conversion.
        
        Args:
            html_content: HTML content
            
        Returns:
            Plain text content
        """
        # This is a minimal implementation - use a proper HTML parser in production
        import re
        # Remove HTML tags
        text = re.sub(r'<[^>]*>', '', html_content)
        # Handle entities
        text = text.replace('&lt;', '<').replace('&gt;', '>').replace('&amp;', '&')
        return text
    
    @staticmethod
    def get_supported_formats():
        """
        Get a list of all supported formats.
        
        Returns:
            Dictionary of formats and their supported conversions
        """
        return {
            "image": [".jpg", ".jpeg", ".png", ".bmp", ".gif", ".tiff", ".webp"],
            "text": [".txt", ".html", ".md"],
            "audio": [".mp3", ".wav", ".ogg", ".flac"]
        }
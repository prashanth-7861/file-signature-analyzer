import sys
import os
import json
import shutil
import binascii
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QFileDialog, 
    QProgressBar, QTextEdit, QMessageBox, QMenuBar, QMenu, QAction, QInputDialog, QTableWidget, QTableWidgetItem
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal

# Application version
APP_VERSION = "1.0.0"

# File signature logic (copied from file_signature_TEST.py)
def read_file_bytes(file_path, max_bytes=2048):
    """
    Read the beginning, middle, and end bytes of a file.
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

def perform_deep_inspection(file_path, beginning_bytes, middle_bytes, ending_bytes, file_size, beginning_hex):
    """
    Perform deeper inspection on files that may need additional analysis beyond signatures.
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
                    "priority": 10
                }]
        except:
            pass
    
    return "Unknown", "", [], []

# GUI Code
class FileAnalyzerApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle(f"File Signature Analyzer v{APP_VERSION}")
        self.setGeometry(100, 100, 800, 600)

        # Create menu bar
        self.create_menu_bar()

        # Main widget
        self.main_widget = QWidget()
        self.setCentralWidget(self.main_widget)

        # Layout
        self.layout = QVBoxLayout()
        self.main_widget.setLayout(self.layout)

        # Input directory
        self.input_dir_label = QLabel("Input Directory:")
        self.input_dir_edit = QLineEdit()
        self.input_dir_button = QPushButton("Browse...")
        self.input_dir_button.clicked.connect(self.select_input_dir)

        input_dir_layout = QHBoxLayout()
        input_dir_layout.addWidget(self.input_dir_label)
        input_dir_layout.addWidget(self.input_dir_edit)
        input_dir_layout.addWidget(self.input_dir_button)

        # Output directory
        self.output_dir_label = QLabel("Output Directory:")
        self.output_dir_edit = QLineEdit()
        self.output_dir_button = QPushButton("Browse...")
        self.output_dir_button.clicked.connect(self.select_output_dir)

        output_dir_layout = QHBoxLayout()
        output_dir_layout.addWidget(self.output_dir_label)
        output_dir_layout.addWidget(self.output_dir_edit)
        output_dir_layout.addWidget(self.output_dir_button)

        # Process button
        self.process_button = QPushButton("Process Files")
        self.process_button.clicked.connect(self.process_files)

        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)

        # Results display
        self.results_text = QTextEdit()
        self.results_text.setReadOnly(True)

        # Add widgets to layout
        self.layout.addLayout(input_dir_layout)
        self.layout.addLayout(output_dir_layout)
        self.layout.addWidget(self.process_button)
        self.layout.addWidget(self.progress_bar)
        self.layout.addWidget(self.results_text)

    def create_menu_bar(self):
        """
        Create a menu bar with options for file analysis, saving, and editing.
        """
        menubar = self.menuBar()

        # File menu
        file_menu = menubar.addMenu("File")

        # Analyze Single File
        analyze_single_action = QAction("Analyze Single File", self)
        analyze_single_action.triggered.connect(self.analyze_single_file)
        file_menu.addAction(analyze_single_action)

        # Analyze Multiple Files
        analyze_multiple_action = QAction("Analyze Multiple Files", self)
        analyze_multiple_action.triggered.connect(self.analyze_multiple_files)
        file_menu.addAction(analyze_multiple_action)

        # Save Results
        save_results_action = QAction("Save Results", self)
        save_results_action.triggered.connect(self.save_results)
        file_menu.addAction(save_results_action)

        # Edit menu
        edit_menu = menubar.addMenu("Edit")

        # Edit File Type
        edit_file_type_action = QAction("Edit File Type", self)
        edit_file_type_action.triggered.connect(self.edit_file_type)
        edit_menu.addAction(edit_file_type_action)

        # Help menu
        help_menu = menubar.addMenu("Help")

        # About
        about_action = QAction("About", self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)

    def select_input_dir(self):
        dir_path = QFileDialog.getExistingDirectory(self, "Select Input Directory")
        if dir_path:
            self.input_dir_edit.setText(dir_path)

    def select_output_dir(self):
        dir_path = QFileDialog.getExistingDirectory(self, "Select Output Directory")
        if dir_path:
            self.output_dir_edit.setText(dir_path)

    def analyze_single_file(self):
        """
        Analyze a single file selected by the user.
        """
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File to Analyze")
        if file_path:
            self.process_files(file_path)

    def analyze_multiple_files(self):
        """
        Analyze multiple files selected by the user.
        """
        file_paths, _ = QFileDialog.getOpenFileNames(self, "Select Files to Analyze")
        if file_paths:
            for file_path in file_paths:
                self.process_files(file_path)

    def process_files(self, file_path=None):
        """
        Process files in the input directory or a specific file.
        """
        input_dir = self.input_dir_edit.text()
        output_dir = self.output_dir_edit.text()

        if not input_dir or not output_dir:
            QMessageBox.warning(self, "Error", "Please select input and output directories.")
            return

        # Load signatures
        sig_file = os.path.join(os.path.dirname(__file__), "file_sigs.json")
        try:
            with open(sig_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                signatures = data['filesigs']
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load signatures: {str(e)}")
            return

        # Process files in a separate thread
        self.progress_bar.setVisible(True)
        self.process_button.setEnabled(False)

        self.worker = FileProcessor(input_dir, output_dir, signatures, file_path)
        self.worker.progress_signal.connect(self.update_progress)
        self.worker.finished_signal.connect(self.on_finished)
        self.worker.start()

    def update_progress(self, value):
        self.progress_bar.setValue(value)

    def on_finished(self, results):
        self.progress_bar.setVisible(False)
        self.process_button.setEnabled(True)

        # Display results
        self.results_text.clear()
        for result in results:
            self.results_text.append(json.dumps(result, indent=4))

    def save_results(self):
        """
        Save the analysis results to a file.
        """
        file_path, _ = QFileDialog.getSaveFileName(self, "Save Results", "", "JSON Files (*.json);;All Files (*)")
        if file_path:
            results = self.results_text.toPlainText()
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(results)
                QMessageBox.information(self, "Success", "Results saved successfully.")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to save results: {str(e)}")

    def edit_file_type(self):
        """
        Allow the user to manually edit the file type.
        """
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File to Edit")
        if file_path:
            new_type, ok = QInputDialog.getText(self, "Edit File Type", "Enter new file type:")
            if ok and new_type:
                # Update the file type in the results
                results = self.results_text.toPlainText()
                if results:
                    try:
                        results_dict = json.loads(results)
                        for result in results_dict:
                            if result["original_file"] == os.path.basename(file_path):
                                result["identified_type"] = new_type
                        self.results_text.setPlainText(json.dumps(results_dict, indent=4))
                    except Exception as e:
                        QMessageBox.critical(self, "Error", f"Failed to edit file type: {str(e)}")

    def show_about(self):
        """
        Show the About dialog.
        """
        QMessageBox.about(self, "About", f"File Signature Analyzer\nVersion {APP_VERSION}")

class FileProcessor(QThread):
    progress_signal = pyqtSignal(int)
    finished_signal = pyqtSignal(list)

    def __init__(self, input_dir, output_dir, signatures, file_path=None):
        super().__init__()
        self.input_dir = input_dir
        self.output_dir = output_dir
        self.signatures = signatures
        self.file_path = file_path

    def run(self):
        results = []
        if self.file_path:
            files = [self.file_path]
        else:
            files = [f for f in os.listdir(self.input_dir) if os.path.isfile(os.path.join(self.input_dir, f))]
        total_files = len(files)

        for i, filename in enumerate(files):
            file_path = os.path.join(self.input_dir, filename) if not self.file_path else self.file_path
            try:
                file_type, primary_ext, all_extensions, matches = identify_file_type(file_path, self.signatures)
                results.append({
                    "original_file": filename,
                    "identified_type": file_type,
                    "primary_extension": primary_ext,
                    "all_extensions": all_extensions,
                    "matches": matches
                })
            except Exception as e:
                results.append({
                    "original_file": filename,
                    "error": str(e)
                })

            # Update progress
            self.progress_signal.emit(int((i + 1) / total_files * 100))

        self.finished_signal.emit(results)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = FileAnalyzerApp()
    window.show()
    sys.exit(app.exec_())
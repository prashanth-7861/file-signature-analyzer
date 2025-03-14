import os
from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QFormLayout,
    QLineEdit, QPushButton, QLabel, QComboBox, QFileDialog,
    QGroupBox, QCheckBox, QMessageBox, QProgressBar
)
from PyQt5.QtCore import Qt

class ConvertFileDialog(QDialog):
    """
    Dialog for converting a file to another format.
    """
    def __init__(self, file_path, parent=None):
        super().__init__(parent)
        self.file_path = file_path
        self.output_path = ""
        self.setup_ui()
        
    def setup_ui(self):
        self.setWindowTitle("Convert File")
        self.setMinimumWidth(600)
        
        layout = QVBoxLayout()
        self.setLayout(layout)
        
        # Title
        title_label = QLabel("Convert File Format")
        title_label.setAlignment(Qt.AlignCenter)
        title_label.setStyleSheet("font-size: 16px; font-weight: bold;")
        layout.addWidget(title_label)
        
        # Create form layout
        form = QFormLayout()
        
        # Source file
        self.source_label = QLabel(self.file_path)
        self.source_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        source_info_label = QLabel(f"Size: {self.format_size(os.path.getsize(self.file_path))}")
        
        source_layout = QVBoxLayout()
        source_layout.addWidget(self.source_label)
        source_layout.addWidget(source_info_label)
        
        form.addRow("Source File:", source_layout)
        
        # Get source extension
        _, source_ext = os.path.splitext(self.file_path)
        source_ext = source_ext.lower()
        
        # Available target formats
        format_group = QGroupBox("Target Format")
        format_layout = QVBoxLayout()
        
        self.format_combo = QComboBox()
        self.populate_formats(source_ext)
        
        format_description = QLabel("Select the format you want to convert to:")
        format_layout.addWidget(format_description)
        format_layout.addWidget(self.format_combo)
        
        format_group.setLayout(format_layout)
        layout.addWidget(format_group)
        
        # Output file
        output_group = QGroupBox("Output Settings")
        output_layout = QVBoxLayout()
        
        output_file_layout = QHBoxLayout()
        self.output_edit = QLineEdit()
        self.output_edit.setReadOnly(True)
        browse_button = QPushButton("Browse...")
        browse_button.clicked.connect(self.select_output_file)
        output_file_layout.addWidget(self.output_edit)
        output_file_layout.addWidget(browse_button)
        
        # Options
        options_layout = QVBoxLayout()
        self.overwrite_check = QCheckBox("Overwrite existing file")
        self.overwrite_check.setChecked(True)
        
        options_layout.addWidget(self.overwrite_check)
        
        # Add layouts to output group
        output_layout.addLayout(output_file_layout)
        output_layout.addLayout(options_layout)
        
        output_group.setLayout(output_layout)
        layout.addWidget(output_group)
        
        # Progress bar (hidden initially)
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        
        # Add conversion info
        info_label = QLabel(
            "Note: Conversion between some formats may result in loss of quality or features."
        )
        info_label.setWordWrap(True)
        info_label.setStyleSheet("color: #666; font-style: italic;")
        layout.addWidget(info_label)
        
        # Add buttons
        button_layout = QHBoxLayout()
        self.convert_button = QPushButton("Convert")
        cancel_button = QPushButton("Cancel")
        
        self.convert_button.clicked.connect(self.convert_file)
        cancel_button.clicked.connect(self.reject)
        
        button_layout.addStretch()
        button_layout.addWidget(self.convert_button)
        button_layout.addWidget(cancel_button)
        layout.addLayout(button_layout)
        
        # Set default output path
        self.update_output_path()
        
        # Connect format change to update output path
        self.format_combo.currentIndexChanged.connect(self.update_output_path)
        
    def populate_formats(self, source_ext):
        """Populate the format dropdown with available target formats."""
        # Get supported formats for this source format
        supported_formats = []
        
        # Hard-coded for now - in a real implementation this would use FileConverter.get_supported_formats()
        if source_ext in ['.jpg', '.jpeg', '.png', '.bmp', '.gif', '.tiff']:
            # Image formats
            for ext in ['.jpg', '.png', '.bmp', '.gif', '.tiff', '.webp']:
                if ext != source_ext:
                    supported_formats.append(ext)
        elif source_ext in ['.txt', '.html', '.md']:
            # Text formats
            for ext in ['.txt', '.html', '.md']:
                if ext != source_ext:
                    supported_formats.append(ext)
        elif source_ext in ['.mp3', '.wav', '.ogg', '.flac']:
            # Audio formats
            for ext in ['.mp3', '.wav', '.ogg', '.flac']:
                if ext != source_ext:
                    supported_formats.append(ext)
                
        if not supported_formats:
            self.format_combo.addItem("No supported conversion formats")
            self.convert_button.setEnabled(False)
        else:
            for fmt in supported_formats:
                self.format_combo.addItem(fmt)
                
    def update_output_path(self):
        """Update the suggested output path based on selected format."""
        if self.format_combo.count() == 0 or self.format_combo.currentText() == "No supported conversion formats":
            return
            
        # Get base filename without extension
        basename = os.path.splitext(os.path.basename(self.file_path))[0]
        new_ext = self.format_combo.currentText()
        
        # Create suggested filename
        suggested_filename = f"{basename}{new_ext}"
        
        # Use same directory as source
        dir_name = os.path.dirname(self.file_path)
        suggested_path = os.path.join(dir_name, suggested_filename)
        
        # Update the output field
        self.output_edit.setText(suggested_path)
        self.output_path = suggested_path
        
    def select_output_file(self):
        """Let user select output file location."""
        current_path = self.output_edit.text()
        dir_name = os.path.dirname(current_path) if current_path else os.path.dirname(self.file_path)
        
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save Converted File", 
            dir_name, 
            f"All Files (*.*)"
        )
        
        if file_path:
            self.output_edit.setText(file_path)
            self.output_path = file_path
        
    def convert_file(self):
        """Perform the file conversion."""
        output_path = self.output_edit.text()
        
        if not output_path:
            QMessageBox.warning(self, "Error", "Please specify an output file.")
            return
            
        # Check if file exists and should be overwritten
        if os.path.exists(output_path) and not self.overwrite_check.isChecked():
            QMessageBox.warning(
                self, "File Exists", 
                "The output file already exists. Enable 'Overwrite existing file' or choose a different location."
            )
            return
            
        # Show progress
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        
        # In a real application, this would be done in a separate thread
        # with proper progress updates
        try:
            # Simple conversion for demo purposes
            # A real application would use proper conversion libraries
            if output_path.lower().endswith(('.jpg', '.jpeg', '.png', '.bmp', '.gif', '.tiff', '.webp')):
                # Image conversion
                self.progress_bar.setValue(20)
                from PIL import Image
                img = Image.open(self.file_path)
                self.progress_bar.setValue(60)
                
                # Convert to RGB if needed (e.g., for JPEG output)
                if output_path.lower().endswith(('.jpg', '.jpeg')) and img.mode != 'RGB':
                    img = img.convert('RGB')
                
                # Save with original quality if possible
                img.save(output_path)
                self.progress_bar.setValue(100)
                
            elif output_path.lower().endswith(('.txt', '.html', '.md')):
                # Text conversion
                self.progress_bar.setValue(20)
                with open(self.file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    
                self.progress_bar.setValue(50)
                
                # Simple conversion - in a real app, use proper parsers
                if self.file_path.lower().endswith('.md') and output_path.lower().endswith('.html'):
                    # Convert markdown to HTML (very simplified)
                    html_content = ["<!DOCTYPE html><html><head><title>Converted Document</title></head><body>"]
                    for line in content.split('\n'):
                        if line.startswith('# '):
                            html_content.append(f"<h1>{line[2:]}</h1>")
                        elif line.startswith('## '):
                            html_content.append(f"<h2>{line[3:]}</h2>")
                        elif line.startswith('- '):
                            html_content.append(f"<li>{line[2:]}</li>")
                        else:
                            html_content.append(f"<p>{line}</p>")
                    html_content.append("</body></html>")
                    content = '\n'.join(html_content)
                    
                elif self.file_path.lower().endswith('.html') and output_path.lower().endswith('.txt'):
                    # Strip HTML tags (very simplified)
                    import re
                    content = re.sub(r'<[^>]*>', '', content)
                    content = content.replace('&lt;', '<').replace('&gt;', '>').replace('&amp;', '&')
                
                self.progress_bar.setValue(80)
                
                # Write output
                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                    
                self.progress_bar.setValue(100)
            else:
                # Unsupported conversion
                raise NotImplementedError(f"Conversion to {os.path.splitext(output_path)[1]} is not implemented")
            
            QMessageBox.information(self, "Success", f"File converted successfully to {output_path}")
            self.accept()
            
        except Exception as e:
            self.progress_bar.setVisible(False)
            QMessageBox.critical(self, "Conversion Error", f"Failed to convert file: {str(e)}")
        
    def format_size(self, size):
        """
        Format file size in human-readable format.
        """
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.2f} {unit}"
            size /= 1024.0
        return f"{size:.2f} TB"
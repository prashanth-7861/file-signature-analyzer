from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QFormLayout,
    QLineEdit, QTextEdit, QPushButton, QLabel, QComboBox, 
    QMessageBox, QGroupBox, QCheckBox
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont

class SignatureEditorDialog(QDialog):
    """
    Dialog for adding or editing file signatures.
    """
    def __init__(self, signature=None, parent=None):
        super().__init__(parent)
        self.signature = signature or {}  # Use empty dict for new signatures
        self.setup_ui()
        
    def setup_ui(self):
        self.setWindowTitle("Edit Signature" if self.signature else "Add New Signature")
        self.setMinimumWidth(600)
        
        layout = QVBoxLayout()
        
        # Title
        title_label = QLabel("File Signature Editor")
        title_label.setAlignment(Qt.AlignCenter)
        title_label.setFont(QFont("Arial", 14, QFont.Bold))
        layout.addWidget(title_label)
        
        # Create form layout
        form = QFormLayout()
        
        # Description field
        self.description_edit = QLineEdit(self.signature.get("File description", ""))
        form.addRow("File Description:", self.description_edit)
        
        # Extension field
        self.extension_edit = QLineEdit(self.signature.get("File extension", ""))
        extension_info = QLabel("Separate multiple extensions with | (e.g., 'jpg|jpeg|jpe')")
        extension_info.setStyleSheet("color: gray; font-size: 10px;")
        form.addRow("File Extensions:", self.extension_edit)
        form.addRow("", extension_info)
        
        # Category dropdown
        self.category_combo = QComboBox()
        categories = ["Document", "Image", "Audio", "Video", "Archive", "Executable", "Other"]
        self.category_combo.addItems(categories)
        current_category = self.signature.get("Category", "Other")
        self.category_combo.setCurrentText(current_category)
        form.addRow("Category:", self.category_combo)
        
        # Header hex field
        self.header_edit = QLineEdit(self.signature.get("Header (hex)", ""))
        header_info = QLabel("Hexadecimal bytes that identify the file format (e.g., '504B0304' for ZIP files)")
        header_info.setStyleSheet("color: gray; font-size: 10px;")
        form.addRow("Header (hex):", self.header_edit)
        form.addRow("", header_info)
        
        # Header offset field
        self.offset_edit = QLineEdit(self.signature.get("Header offset", "0"))
        offset_info = QLabel("Byte offset where the header signature starts (usually 0)")
        offset_info.setStyleSheet("color: gray; font-size: 10px;")
        form.addRow("Header Offset:", self.offset_edit)
        form.addRow("", offset_info)
        
        # Trailer hex field
        self.trailer_edit = QLineEdit(self.signature.get("Trailer (hex)", ""))
        trailer_info = QLabel("Optional: Hexadecimal bytes found at the end of the file (leave empty if unknown)")
        trailer_info.setStyleSheet("color: gray; font-size: 10px;")
        form.addRow("Trailer (hex):", self.trailer_edit)
        form.addRow("", trailer_info)
        
        # MIME type field
        self.mime_edit = QLineEdit(self.signature.get("MIME type", ""))
        mime_info = QLabel("Optional: MIME type for this file format (e.g., 'application/zip')")
        mime_info.setStyleSheet("color: gray; font-size: 10px;")
        form.addRow("MIME Type:", self.mime_edit)
        form.addRow("", mime_info)
        
        # Add form to main layout
        form_group = QGroupBox("Signature Information")
        form_group.setLayout(form)
        layout.addWidget(form_group)
        
        # Add advanced options section
        advanced_group = QGroupBox("Advanced Options")
        advanced_layout = QVBoxLayout()
        
        # Deep inspection checkbox
        self.deep_inspection_check = QCheckBox("Require Deep Inspection")
        self.deep_inspection_check.setChecked(self.signature.get("Deep inspection", False))
        self.deep_inspection_check.setToolTip("Enable this if the format requires content analysis beyond the header")
        
        # Header pattern vs. exact match
        self.exact_match_check = QCheckBox("Exact Match Required")
        self.exact_match_check.setChecked(self.signature.get("Exact match", True))
        self.exact_match_check.setToolTip("If checked, the header must match exactly. Otherwise, it's treated as a pattern.")
        
        advanced_layout.addWidget(self.deep_inspection_check)
        advanced_layout.addWidget(self.exact_match_check)
        
        advanced_group.setLayout(advanced_layout)
        layout.addWidget(advanced_group)
        
        # Notes section
        notes_group = QGroupBox("Notes")
        notes_layout = QVBoxLayout()
        
        self.notes_edit = QTextEdit(self.signature.get("Notes", ""))
        self.notes_edit.setPlaceholderText("Enter any additional notes about this signature...")
        notes_layout.addWidget(self.notes_edit)
        
        notes_group.setLayout(notes_layout)
        layout.addWidget(notes_group)
        
        # Add validation info
        validation_label = QLabel(
            "Header must be a valid hexadecimal string (e.g., '504B0304'). "
            "Extensions should be pipe-separated (e.g., 'docx|doc')."
        )
        validation_label.setWordWrap(True)
        validation_label.setStyleSheet("color: #666; font-style: italic;")
        layout.addWidget(validation_label)
        
        # Add buttons
        button_layout = QHBoxLayout()
        save_button = QPushButton("Save")
        cancel_button = QPushButton("Cancel")
        validate_button = QPushButton("Validate")
        
        save_button.clicked.connect(self.save_signature)
        cancel_button.clicked.connect(self.reject)
        validate_button.clicked.connect(self.validate_signature)
        
        button_layout.addWidget(validate_button)
        button_layout.addStretch()
        button_layout.addWidget(save_button)
        button_layout.addWidget(cancel_button)
        layout.addLayout(button_layout)
        
        self.setLayout(layout)
        
    def validate_signature(self):
        """
        Validate signature fields without saving.
        """
        # Check required fields
        if not self.description_edit.text().strip():
            QMessageBox.warning(self, "Missing Description", "Please enter a file description.")
            self.description_edit.setFocus()
            return False
            
        if not self.extension_edit.text().strip():
            if not QMessageBox.question(
                self, "No Extension", 
                "This signature has no file extensions specified. Continue?",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No
            ) == QMessageBox.Yes:
                self.extension_edit.setFocus()
                return False
                
        header_hex = self.header_edit.text().strip()
        if not header_hex:
            QMessageBox.warning(self, "Missing Header", "Please enter a header signature in hexadecimal.")
            self.header_edit.setFocus()
            return False
            
        # Validate header hex format
        if not self.validate_hex(header_hex):
            QMessageBox.warning(
                self, "Invalid Header", 
                "Header must be a valid hexadecimal string with an even number of digits."
            )
            self.header_edit.setFocus()
            return False
            
        # Validate trailer hex format if provided
        trailer_hex = self.trailer_edit.text().strip()
        if trailer_hex and not self.validate_hex(trailer_hex):
            QMessageBox.warning(
                self, "Invalid Trailer", 
                "Trailer must be a valid hexadecimal string with an even number of digits."
            )
            self.trailer_edit.setFocus()
            return False
            
        # Validate offset
        try:
            offset = int(self.offset_edit.text().strip())
            if offset < 0:
                raise ValueError("Offset must be non-negative")
        except ValueError:
            QMessageBox.warning(self, "Invalid Offset", "Offset must be a non-negative integer.")
            self.offset_edit.setFocus()
            return False
            
        # Success
        QMessageBox.information(self, "Validation", "All signature fields are valid!")
        return True
        
    def save_signature(self):
        """
        Validate and save the signature.
        """
        if not self.validate_signature():
            return
            
        # Update signature data
        self.signature = {
            "File description": self.description_edit.text().strip(),
            "File extension": self.extension_edit.text().strip(),
            "Category": self.category_combo.currentText(),
            "Header (hex)": self.header_edit.text().strip().upper(),
            "Header offset": self.offset_edit.text().strip(),
            "Trailer (hex)": self.trailer_edit.text().strip().upper() or "(null)",
            "MIME type": self.mime_edit.text().strip(),
            "Deep inspection": self.deep_inspection_check.isChecked(),
            "Exact match": self.exact_match_check.isChecked(),
            "Notes": self.notes_edit.toPlainText()
        }
        
        self.accept()
        
    def validate_hex(self, hex_string):
        """Validate hexadecimal string."""
        if not hex_string:
            return False
            
        # Remove spaces for validation
        hex_string = hex_string.replace(" ", "")
        
        # Check if all characters are valid hex digits
        try:
            int(hex_string, 16)
            # Check if length is even (complete bytes)
            return len(hex_string) % 2 == 0
        except ValueError:
            return False
        
    def get_signature(self):
        """Return the edited signature."""
        return self.signature
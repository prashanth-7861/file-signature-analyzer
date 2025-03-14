import os
from PyQt5.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
    QTextEdit, QLineEdit, QPushButton, QMessageBox, QComboBox
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont, QTextCursor

class HexViewerWindow(QMainWindow):
    """
    Window for displaying a hex dump of a file.
    """
    def __init__(self, file_path, parent=None):
        super().__init__(parent)
        self.file_path = file_path
        self.initUI()
        self.load_file()
        
    def initUI(self):
        self.setWindowTitle(f"Hex Dump - {os.path.basename(self.file_path)}")
        self.setGeometry(150, 150, 900, 600)
        
        # Central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout()
        central_widget.setLayout(layout)
        
        # File info
        info_layout = QHBoxLayout()
        self.file_info_label = QLabel()
        info_layout.addWidget(self.file_info_label)
        
        # Hex dump display
        self.hex_text = QTextEdit()
        self.hex_text.setReadOnly(True)
        self.hex_text.setFont(QFont("Courier New", 10))
        
        # Navigation controls
        nav_layout = QHBoxLayout()
        
        # Offset input
        offset_layout = QHBoxLayout()
        self.offset_label = QLabel("Offset:")
        self.offset_edit = QLineEdit("0")
        self.offset_edit.setFixedWidth(100)
        go_button = QPushButton("Go")
        go_button.clicked.connect(self.go_to_offset)
        
        offset_layout.addWidget(self.offset_label)
        offset_layout.addWidget(self.offset_edit)
        offset_layout.addWidget(go_button)
        
        # View mode
        mode_layout = QHBoxLayout()
        mode_label = QLabel("View Mode:")
        self.mode_combo = QComboBox()
        self.mode_combo.addItems(["Hex", "ASCII", "Both"])
        self.mode_combo.setCurrentIndex(2)  # Default to Both
        self.mode_combo.currentIndexChanged.connect(self.change_view_mode)
        
        mode_layout.addWidget(mode_label)
        mode_layout.addWidget(self.mode_combo)
        
        # Add layouts to nav_layout
        nav_layout.addLayout(offset_layout)
        nav_layout.addStretch()
        nav_layout.addLayout(mode_layout)
        
        # Add controls to view next/previous chunks
        control_layout = QHBoxLayout()
        prev_button = QPushButton("Previous Chunk")
        next_button = QPushButton("Next Chunk")
        prev_button.clicked.connect(self.show_previous_chunk)
        next_button.clicked.connect(self.show_next_chunk)
        
        self.chunk_size_label = QLabel("Chunk Size:")
        self.chunk_size_combo = QComboBox()
        self.chunk_size_combo.addItems(["256 bytes", "512 bytes", "1 KB", "4 KB"])
        self.chunk_size_combo.setCurrentIndex(1)  # Default to 512 bytes
        self.chunk_size_combo.currentIndexChanged.connect(self.change_chunk_size)
        
        control_layout.addWidget(prev_button)
        control_layout.addWidget(next_button)
        control_layout.addStretch()
        control_layout.addWidget(self.chunk_size_label)
        control_layout.addWidget(self.chunk_size_combo)
        
        # Add copy buttons
        copy_layout = QHBoxLayout()
        copy_hex_button = QPushButton("Copy Hex Values")
        copy_text_button = QPushButton("Copy as Text")
        copy_hex_button.clicked.connect(self.copy_hex)
        copy_text_button.clicked.connect(self.copy_text)
        
        copy_layout.addWidget(copy_hex_button)
        copy_layout.addWidget(copy_text_button)
        copy_layout.addStretch()
        
        # Search
        search_layout = QHBoxLayout()
        search_label = QLabel("Search:")
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("Enter hex or text...")
        search_button = QPushButton("Find")
        search_button.clicked.connect(self.search_hex)
        
        search_hex_radio = QComboBox()
        search_hex_radio.addItems(["Hex", "Text"])
        
        search_layout.addWidget(search_label)
        search_layout.addWidget(self.search_edit)
        search_layout.addWidget(search_hex_radio)
        search_layout.addWidget(search_button)
        
        # Add layouts to main layout
        layout.addLayout(info_layout)
        layout.addWidget(self.hex_text)
        layout.addLayout(nav_layout)
        layout.addLayout(control_layout)
        layout.addLayout(copy_layout)
        layout.addLayout(search_layout)
        
        # Initialize values
        self.current_offset = 0
        self.chunk_size = 512  # Bytes per page
        self.view_mode = "Both"  # Default view mode
        
    def load_file(self):
        """
        Load the file and display hex dump of first chunk.
        """
        try:
            file_size = os.path.getsize(self.file_path)
            self.file_size = file_size
            self.file_info_label.setText(f"File: {os.path.basename(self.file_path)} | Size: {self.format_size(file_size)}")
            
            # Show first chunk
            self.show_hex_dump(0)
        except Exception as e:
            self.hex_text.setText(f"Error loading file: {str(e)}")
            
    def show_hex_dump(self, offset):
        """
        Display hex dump starting at the specified offset.
        """
        try:
            with open(self.file_path, 'rb') as f:
                f.seek(offset)
                data = f.read(self.chunk_size)
                
            if not data:
                QMessageBox.warning(self, "End of File", "You have reached the end of the file.")
                return
                
            self.current_offset = offset
            self.current_data = data
            
            # Update the offset field
            self.offset_edit.setText(str(offset))
            
            # Format the hex dump based on view mode
            if self.view_mode == "Hex":
                self.show_hex_only(data, offset)
            elif self.view_mode == "ASCII":
                self.show_ascii_only(data, offset)
            else:  # Both
                self.show_hex_and_ascii(data, offset)
            
        except Exception as e:
            self.hex_text.setText(f"Error reading file at offset {offset}: {str(e)}")
            
    def show_hex_only(self, data, offset):
        """Display hex values only."""
        hex_dump = []
        
        hex_dump.append(f"Offset    | Hexadecimal Values\n")
        hex_dump.append(f"-" * 60 + "\n")
        
        for i in range(0, len(data), 16):
            chunk = data[i:i+16]
            hex_values = [f"{b:02X}" for b in chunk]
            
            # Format the line
            line = f"{offset + i:08X} | {' '.join(hex_values)}\n"
            hex_dump.append(line)
            
        self.hex_text.setText(''.join(hex_dump))
        
    def show_ascii_only(self, data, offset):
        """Display ASCII representation only."""
        hex_dump = []
        
        hex_dump.append(f"Offset    | ASCII Text\n")
        hex_dump.append(f"-" * 60 + "\n")
        
        for i in range(0, len(data), 16):
            chunk = data[i:i+16]
            
            # Create ASCII representation
            ascii_repr = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
            
            # Format the line
            line = f"{offset + i:08X} | {ascii_repr}\n"
            hex_dump.append(line)
            
        self.hex_text.setText(''.join(hex_dump))
        
    def show_hex_and_ascii(self, data, offset):
        """Display both hex and ASCII representation."""
        hex_dump = []
        
        hex_dump.append(f"Offset    | 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F | ASCII\n")
        hex_dump.append(f"-" * 78 + "\n")
        
        for i in range(0, len(data), 16):
            chunk = data[i:i+16]
            hex_values = [f"{b:02X}" for b in chunk]
            
            # Pad hex values to ensure alignment
            while len(hex_values) < 16:
                hex_values.append("  ")
                
            # Create ASCII representation
            ascii_repr = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
            
            # Format the line
            line = f"{offset + i:08X} | {' '.join(hex_values)} | {ascii_repr}\n"
            hex_dump.append(line)
            
        self.hex_text.setText(''.join(hex_dump))
            
    def go_to_offset(self):
        """
        Go to the specified offset in the file.
        """
        try:
            offset_text = self.offset_edit.text()
            
            # Handle hexadecimal offsets
            if offset_text.startswith("0x"):
                offset = int(offset_text, 16)
            else:
                offset = int(offset_text)
                
            # Check if offset is valid
            if offset < 0:
                raise ValueError("Offset cannot be negative")
            
            if offset >= self.file_size:
                QMessageBox.warning(self, "Invalid Offset", "Offset is beyond the end of the file.")
                return
                
            self.show_hex_dump(offset)
        except ValueError:
            QMessageBox.warning(self, "Invalid Offset", "Please enter a valid decimal or hexadecimal (0x...) offset.")
            
    def show_next_chunk(self):
        """
        Show the next chunk of the file.
        """
        new_offset = self.current_offset + self.chunk_size
        
        # Check if new offset is valid
        if new_offset >= self.file_size:
            QMessageBox.information(self, "End of File", "You have reached the end of the file.")
            return
            
        self.show_hex_dump(new_offset)
        
    def show_previous_chunk(self):
        """
        Show the previous chunk of the file.
        """
        new_offset = max(0, self.current_offset - self.chunk_size)
        self.show_hex_dump(new_offset)
        
    def change_view_mode(self):
        """
        Change the view mode based on the combobox selection.
        """
        self.view_mode = self.mode_combo.currentText()
        self.show_hex_dump(self.current_offset)
        
    def change_chunk_size(self):
        """
        Change the chunk size based on the combobox selection.
        """
        chunk_text = self.chunk_size_combo.currentText()
        
        if chunk_text == "256 bytes":
            self.chunk_size = 256
        elif chunk_text == "512 bytes":
            self.chunk_size = 512
        elif chunk_text == "1 KB":
            self.chunk_size = 1024
        elif chunk_text == "4 KB":
            self.chunk_size = 4096
            
        self.show_hex_dump(self.current_offset)
        
    def copy_hex(self):
        """
        Copy the hex values to clipboard.
        """
        from PyQt5.QtWidgets import QApplication
        
        if hasattr(self, 'current_data'):
            hex_string = ' '.join(f"{b:02X}" for b in self.current_data)
            QApplication.clipboard().setText(hex_string)
            self.statusBar().showMessage("Hex values copied to clipboard", 2000)
        
    def copy_text(self):
        """
        Copy the ASCII representation to clipboard.
        """
        from PyQt5.QtWidgets import QApplication
        
        if hasattr(self, 'current_data'):
            text = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in self.current_data)
            QApplication.clipboard().setText(text)
            self.statusBar().showMessage("Text copied to clipboard", 2000)
        
    def search_hex(self):
        """
        Search for a hex pattern in the file.
        """
        # Placeholder for search functionality
        QMessageBox.information(self, "Feature Coming Soon", "Search functionality will be implemented in a future version.")
        
    def format_size(self, size):
        """
        Format file size in human-readable format.
        """
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.2f} {unit}"
            size /= 1024.0
        return f"{size:.2f} TB"
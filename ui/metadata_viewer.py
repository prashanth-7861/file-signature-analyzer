import os
from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QTableWidget, 
    QTableWidgetItem, QPushButton, QTabWidget, QTreeWidget, 
    QTreeWidgetItem, QSplitter, QWidget
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont

class MetadataViewer(QDialog):
    """
    Dialog for displaying file metadata.
    """
    def __init__(self, metadata, parent=None):
        super().__init__(parent)
        self.metadata = metadata
        self.setWindowTitle("File Metadata")
        self.setMinimumSize(600, 400)
        self.initUI()
        
    def initUI(self):
        self.setWindowTitle("File Metadata")
        self.setGeometry(200, 200, 800, 600)
        
        layout = QVBoxLayout()
        self.setLayout(layout)
        
        # Create tabs for different views
        tab_widget = QTabWidget()
        layout.addWidget(tab_widget)
        
        # Table view tab
        table_widget = QWidget()
        table_layout = QVBoxLayout()
        table_widget.setLayout(table_layout)
        
        # Create table
        self.table = QTableWidget(0, 2)
        self.table.setHorizontalHeaderLabels(["Property", "Value"])
        self.table.horizontalHeader().setStretchLastSection(True)
        table_layout.addWidget(self.table)
        
        # Tree view tab
        tree_widget = QWidget()
        tree_layout = QVBoxLayout()
        tree_widget.setLayout(tree_layout)
        
        # Create tree
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Property", "Value"])
        self.tree.header().setStretchLastSection(True)
        tree_layout.addWidget(self.tree)
        
        # Add tabs
        tab_widget.addTab(table_widget, "Table View")
        tab_widget.addTab(tree_widget, "Tree View")
        
        # Buttons
        button_layout = QHBoxLayout()
        copy_button = QPushButton("Copy to Clipboard")
        copy_button.clicked.connect(self.copy_metadata)
        export_button = QPushButton("Export")
        export_button.clicked.connect(self.export_metadata)
        close_button = QPushButton("Close")
        close_button.clicked.connect(self.close)
        
        button_layout.addWidget(copy_button)
        button_layout.addWidget(export_button)
        button_layout.addStretch()
        button_layout.addWidget(close_button)
        
        layout.addLayout(button_layout)
        
        # Populate data
        self.populate_data()
        
    def populate_data(self):
        """
        Populate the table and tree with metadata.
        """
        # Populate table
        self.table.setRowCount(0)
        for key, value in sorted(self.metadata.items()):
            if isinstance(value, dict):
                # Skip nested structures in table view
                continue
                
            row = self.table.rowCount()
            self.table.insertRow(row)
            self.table.setItem(row, 0, QTableWidgetItem(str(key)))
            self.table.setItem(row, 1, QTableWidgetItem(str(value)))
        
        # Resize rows to content
        self.table.resizeRowsToContents()
        
        # Populate tree
        self.tree.clear()
        for key, value in sorted(self.metadata.items()):
            if isinstance(value, dict):
                # Handle nested structures
                parent = QTreeWidgetItem(self.tree, [str(key), ""])
                self.add_dict_to_tree(parent, value)
            else:
                QTreeWidgetItem(self.tree, [str(key), str(value)])
                
        # Expand all items
        self.tree.expandAll()
        
    def add_dict_to_tree(self, parent, dictionary):
        """
        Add a dictionary to the tree as child items.
        """
        for key, value in sorted(dictionary.items()):
            if isinstance(value, dict):
                child = QTreeWidgetItem(parent, [str(key), ""])
                self.add_dict_to_tree(child, value)
            else:
                QTreeWidgetItem(parent, [str(key), str(value)])
                
    def copy_metadata(self):
        """
        Copy metadata to clipboard.
        """
        from PyQt5.QtWidgets import QApplication
        
        # Format metadata as text
        text = []
        for key, value in sorted(self.metadata.items()):
            if isinstance(value, dict):
                text.append(f"{key}:")
                for k, v in sorted(value.items()):
                    text.append(f"  {k}: {v}")
            else:
                text.append(f"{key}: {value}")
                
        # Copy to clipboard
        QApplication.clipboard().setText("\n".join(text))
        
    def export_metadata(self):
        """
        Export metadata to a file.
        """
        from PyQt5.QtWidgets import QFileDialog
        import json
        
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Export Metadata", "", "JSON Files (*.json);;Text Files (*.txt);;All Files (*.*)"
        )
        
        if not file_path:
            return
            
        try:
            # Export based on file extension
            if file_path.lower().endswith('.json'):
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(self.metadata, f, indent=4)
            else:
                # Default to text format
                with open(file_path, 'w', encoding='utf-8') as f:
                    for key, value in sorted(self.metadata.items()):
                        if isinstance(value, dict):
                            f.write(f"{key}:\n")
                            for k, v in sorted(value.items()):
                                f.write(f"  {k}: {v}\n")
                        else:
                            f.write(f"{key}: {value}\n")
                            
            from PyQt5.QtWidgets import QMessageBox
            QMessageBox.information(self, "Success", f"Metadata exported to {file_path}")
        except Exception as e:
            from PyQt5.QtWidgets import QMessageBox
            QMessageBox.critical(self, "Error", f"Failed to export metadata: {str(e)}")
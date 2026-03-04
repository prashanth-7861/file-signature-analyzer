#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
File Signature Analyzer v2.0.0
A tool to identify file types based on binary signatures regardless of file extension.
Now with ML-based classification, file comparison, and enhanced analysis.
"""

import sys
import os
import json
import shutil
import hashlib
import zipfile
import tarfile
from datetime import datetime

# Optional external packages
try:
    import rarfile
except ImportError:
    rarfile = None

try:
    import py7zr
except ImportError:
    py7zr = None

# Optional matplotlib for charts
try:
    from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
    from matplotlib.figure import Figure
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QLineEdit, QPushButton, QFileDialog, QMessageBox, QTableWidget,
    QTableWidgetItem, QGroupBox, QTabWidget, QSplitter, QFrame, QAction,
    QMenu, QProgressBar, QComboBox, QCheckBox, QTextEdit, QInputDialog,
    QDialog, QDialogButtonBox, QHeaderView, QTreeWidgetItem, QSpinBox,
    QTreeWidget,
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QUrl
from PyQt5.QtGui import QIcon, QDesktopServices, QFont


def resource_path(relative_path):
    """Get absolute path to resource, works for dev and PyInstaller"""
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)


# Create necessary directories if they don't exist
os.makedirs(resource_path("ui"), exist_ok=True)
os.makedirs(resource_path("core"), exist_ok=True)
os.makedirs(resource_path("resources"), exist_ok=True)

# Import custom modules
from ui.hex_viewer import HexViewerWindow
from ui.about_dialog import AboutDialog
from ui.contact_dialog import ContactDialog
from ui.signature_editor import SignatureEditorDialog
from ui.metadata_viewer import MetadataViewer
from ui.convert_dialog import ConvertFileDialog
from core.file_analyzer import identify_file_type, calculate_entropy
from core.batch_processor import BatchFileProcessor
from core.metadata_extractor import MetadataExtractor
from core.ml_classifier import MLFileClassifier
from core.model_registry import ModelRegistry

# Application version
APP_VERSION = "2.0.0"

class FileAnalyzerApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.single_file_table = None
        self.batch_table = None
        self.database_table = None
        self.current_results = None
        self.analyzed_file_path = None
        self.batch_results = None
        self.signatures = []
        self.setAcceptDrops(True)

        # Initialize ML classifier
        try:
            self.ml_classifier = MLFileClassifier()
        except Exception:
            self.ml_classifier = None

        # Initialize model registry
        try:
            self.model_registry = ModelRegistry()
            # Load active model from registry if available
            active_path = self.model_registry.get_active_model_path()
            if active_path and os.path.exists(active_path):
                if self.ml_classifier:
                    self.ml_classifier.load_model(active_path)
                else:
                    self.ml_classifier = MLFileClassifier(model_path=active_path)
        except Exception:
            self.model_registry = None

        self.initUI()
        self.load_signatures()
        self.update_recent_files_menu()

        # Background check for model updates on startup
        self._start_update_check()

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event):
        urls = event.mimeData().urls()
        if urls:
            file_path = urls[0].toLocalFile()
            if os.path.isfile(file_path):
                self.tabs.setCurrentIndex(0)
                self.file_path_edit.setText(file_path)
                self.analyzed_file_path = file_path
                self.analyze_current_file()
                self.add_recent_file(file_path)

    def initUI(self):
        self.setWindowTitle(f"File Signature Analyzer v{APP_VERSION}")
        self.setGeometry(100, 100, 1100, 850)

        icon_path = resource_path(os.path.join("resources", "icons", "app_icon.png"))
        if os.path.exists(icon_path):
            self.setWindowIcon(QIcon(icon_path))
        else:
            os.makedirs(resource_path(os.path.join("resources", "icons")), exist_ok=True)

        self.create_menu_bar()
        self.statusBar().showMessage("Ready")

        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)

        # Tab 1: Single File Analysis
        self.single_file_tab = QWidget()
        self.tabs.addTab(self.single_file_tab, "Single File Analysis")
        self.setup_single_file_tab()

        # Tab 2: Batch Processing
        self.batch_tab = QWidget()
        self.tabs.addTab(self.batch_tab, "Batch Processing")
        self.setup_batch_tab()

        # Tab 3: File Type Database
        self.database_tab = QWidget()
        self.tabs.addTab(self.database_tab, "File Type Database")
        self.setup_database_tab()

        # Tab 4: ML Insights
        self.ml_tab = QWidget()
        self.tabs.addTab(self.ml_tab, "ML Insights")
        self.setup_ml_tab()

        # Tab 5: File Comparison
        self.compare_tab = QWidget()
        self.tabs.addTab(self.compare_tab, "File Comparison")
        self.setup_compare_tab()

    def check_module_availability(self):
        """
        Check which archive modules are available and update UI accordingly.
        """
        modules = {
            'zipfile': True,  # Standard library
            'tarfile': True,  # Standard library
            'rarfile': False, 
            'py7zr': False
        }
        
        # Check for optional modules
        try:
            import rarfile
            modules['rarfile'] = True
        except ImportError:
            pass
            
        try:
            import py7zr
            modules['py7zr'] = True
        except ImportError:
            pass
        
        # Update UI based on available modules
        if not (modules['rarfile'] or modules['py7zr']):
            # Add a notice to the UI if modules are missing
            self.module_notice = QLabel("Note: Install 'rarfile' and 'py7zr' for full archive support")
            self.module_notice.setStyleSheet("color: #FF6600;")
            # Add this label to your layout where appropriate
        
        return modules

    def create_menu_bar(self):
        """
        Create a menu bar with options for file analysis, saving, and editing.
        """
        menubar = self.menuBar()

        # File menu
        file_menu = menubar.addMenu("File")

        # New submenu
        new_menu = QMenu("New", self)
        
        # New Analysis
        new_analysis_action = QAction("New Analysis", self)
        new_analysis_action.setShortcut("Ctrl+N")
        new_analysis_action.triggered.connect(self.new_analysis)
        new_menu.addAction(new_analysis_action)
        
        # New Batch
        new_batch_action = QAction("New Batch Process", self)
        new_batch_action.triggered.connect(self.new_batch)
        new_menu.addAction(new_batch_action)
        
        file_menu.addMenu(new_menu)
        
        # Open submenu
        open_menu = QMenu("Open", self)
        
        # Analyze Single File
        analyze_single_action = QAction("Analyze Single File", self)
        analyze_single_action.setShortcut("Ctrl+O")
        analyze_single_action.triggered.connect(self.analyze_single_file)
        open_menu.addAction(analyze_single_action)

        # Analyze Multiple Files
        analyze_multiple_action = QAction("Analyze Multiple Files", self)
        analyze_multiple_action.setShortcut("Ctrl+M")
        analyze_multiple_action.triggered.connect(self.analyze_multiple_files)
        open_menu.addAction(analyze_multiple_action)
        
        # Open Recent
        self.recent_menu = QMenu("Open Recent", self)
        self.update_recent_files_menu()
        open_menu.addMenu(self.recent_menu)
        
        file_menu.addMenu(open_menu)

        # Save menu
        save_menu = QMenu("Save", self)
        
        # Save Results
        save_results_action = QAction("Save Results", self)
        save_results_action.setShortcut("Ctrl+S")
        save_results_action.triggered.connect(self.save_results)
        save_menu.addAction(save_results_action)
        
        # Save As
        save_as_action = QAction("Save As...", self)
        save_as_action.setShortcut("Ctrl+Shift+S")
        save_as_action.triggered.connect(self.save_file_as)
        save_menu.addAction(save_as_action)
        
        file_menu.addMenu(save_menu)
        
        file_menu.addSeparator()
        
        # Export
        export_menu = QMenu("Export", self)
        
        # Export Results as CSV
        export_csv_action = QAction("Export Results as CSV", self)
        export_csv_action.triggered.connect(lambda: self.export_results("csv"))
        export_menu.addAction(export_csv_action)
        
        # Export Results as JSON
        export_json_action = QAction("Export Results as JSON", self)
        export_json_action.triggered.connect(lambda: self.export_results("json"))
        export_menu.addAction(export_json_action)
        
        # Export Signature Database
        export_db_action = QAction("Export Signature Database", self)
        export_db_action.triggered.connect(self.export_database)
        export_menu.addAction(export_db_action)
        
        file_menu.addMenu(export_menu)
        
         # Import
        import_menu = QMenu("Import", self)
    
        # Import Signature Database
        import_sig_action = QAction("Import Signature Database", self)
        import_sig_action.triggered.connect(self.import_comprehensive_signatures)
        import_menu.addAction(import_sig_action)
    
        # Import Default Signatures
        import_default_action = QAction("Reset to Default Signatures", self)
        import_default_action.triggered.connect(self.reset_to_default_signatures)
        import_menu.addAction(import_default_action)
    
        file_menu.addMenu(import_menu)
    
        
        file_menu.addSeparator()

        # Exit
        exit_action = QAction("Exit", self)
        exit_action.setShortcut("Ctrl+Q")
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        # Edit menu
        edit_menu = menubar.addMenu("Edit")

        # Edit File Type
        edit_file_type_action = QAction("Edit File Type", self)
        edit_file_type_action.setShortcut("Ctrl+E")
        edit_file_type_action.triggered.connect(self.edit_file_type)
        edit_menu.addAction(edit_file_type_action)
        
        # Rename File
        rename_file_action = QAction("Rename File", self)
        rename_file_action.setShortcut("F2")
        rename_file_action.triggered.connect(self.rename_file)
        edit_menu.addAction(rename_file_action)
        
        edit_menu.addSeparator()
        
        # Signature Database
        sig_db_menu = QMenu("Signature Database", self)
        
        # Add Signature
        add_sig_action = QAction("Add Signature", self)
        add_sig_action.triggered.connect(self.add_signature)
        sig_db_menu.addAction(add_sig_action)
        
        # Edit Signature
        edit_sig_action = QAction("Edit Signature", self)
        edit_sig_action.triggered.connect(self.edit_signature)
        sig_db_menu.addAction(edit_sig_action)
        
        # Delete Signature
        delete_sig_action = QAction("Delete Signature", self)
        delete_sig_action.triggered.connect(self.delete_signature)
        sig_db_menu.addAction(delete_sig_action)
        
        # Import Comprehensive Signatures
        import_comp_action = QAction("Import Comprehensive Signatures", self)
        import_comp_action.triggered.connect(self.import_comprehensive_signatures)
        sig_db_menu.addAction(import_comp_action)
    
        # Download Signatures
        download_sig_action = QAction("Download Signature Database", self)
        download_sig_action.triggered.connect(self.download_signature_database)
        sig_db_menu.addAction(download_sig_action)
        
        edit_menu.addMenu(sig_db_menu)
        
        edit_menu.addSeparator()
        
        # Preferences
        preferences_action = QAction("Preferences", self)
        preferences_action.triggered.connect(self.show_preferences)
        edit_menu.addAction(preferences_action)

        # View menu
        view_menu = menubar.addMenu("View")
        
        # View Hex Dump
        hex_dump_action = QAction("View Hex Dump", self)
        hex_dump_action.setShortcut("Ctrl+H")
        hex_dump_action.triggered.connect(self.view_hex_dump)
        view_menu.addAction(hex_dump_action)
        
        # View Metadata
        metadata_action = QAction("View Metadata", self)
        metadata_action.setShortcut("Ctrl+D")
        metadata_action.triggered.connect(self.view_metadata)
        view_menu.addAction(metadata_action)
        
        # View File Structure
        structure_action = QAction("View File Structure", self)
        structure_action.triggered.connect(self.view_file_structure)
        view_menu.addAction(structure_action)
        
        view_menu.addSeparator()
        
        # Visualizations
        viz_menu = QMenu("Visualizations", self)
        
        # Type Distribution
        type_dist_action = QAction("File Type Distribution", self)
        type_dist_action.triggered.connect(lambda: self.show_visualization("type"))
        viz_menu.addAction(type_dist_action)
        
        # Extension Analysis
        ext_analysis_action = QAction("Extension Analysis", self)
        ext_analysis_action.triggered.connect(lambda: self.show_visualization("extension"))
        viz_menu.addAction(ext_analysis_action)
        
        view_menu.addMenu(viz_menu)

        view_menu.addSeparator()

        # ML Insights
        ml_insights_action = QAction("ML Insights", self)
        ml_insights_action.triggered.connect(lambda: self.tabs.setCurrentIndex(3))
        view_menu.addAction(ml_insights_action)

        # Tools menu
        tools_menu = menubar.addMenu("Tools")

        # Convert File
        convert_file_action = QAction("Convert File Format", self)
        convert_file_action.triggered.connect(self.convert_file)
        tools_menu.addAction(convert_file_action)
        
        # Repair File
        repair_file_action = QAction("Repair File", self)
        repair_file_action.triggered.connect(self.repair_file)
        tools_menu.addAction(repair_file_action)
        
        # Extract Content
        extract_action = QAction("Extract Content", self)
        extract_action.triggered.connect(self.extract_content)
        tools_menu.addAction(extract_action)
        
        tools_menu.addSeparator()
        
        # Generate Report
        report_action = QAction("Generate Report", self)
        report_action.triggered.connect(self.generate_report)
        tools_menu.addAction(report_action)

        tools_menu.addSeparator()

        # ML Model submenu
        ml_menu = tools_menu.addMenu("ML Model")

        ml_train_action = QAction("Train Model...", self)
        ml_train_action.triggered.connect(self.train_ml_model)
        ml_menu.addAction(ml_train_action)

        ml_load_action = QAction("Load Model...", self)
        ml_load_action.triggered.connect(self.load_ml_model)
        ml_menu.addAction(ml_load_action)

        ml_export_action = QAction("Export Model...", self)
        ml_export_action.triggered.connect(self.export_ml_model)
        ml_menu.addAction(ml_export_action)

        ml_menu.addSeparator()

        ml_check_update_action = QAction("Check for Updates...", self)
        ml_check_update_action.triggered.connect(self.check_model_updates)
        ml_menu.addAction(ml_check_update_action)

        ml_upload_action = QAction("Upload Model to GitHub...", self)
        ml_upload_action.triggered.connect(self.upload_model_to_github)
        ml_menu.addAction(ml_upload_action)

        # File Comparison
        file_compare_action = QAction("File Comparison", self)
        file_compare_action.triggered.connect(lambda: self.tabs.setCurrentIndex(4))
        tools_menu.addAction(file_compare_action)

        # Help menu
        help_menu = menubar.addMenu("Help")

        # Help Contents
        help_contents_action = QAction("Help Contents", self)
        help_contents_action.setShortcut("F1")
        help_contents_action.triggered.connect(self.show_help)
        help_menu.addAction(help_contents_action)
        
        # Check for Updates
        update_action = QAction("Check for Updates", self)
        update_action.triggered.connect(self.check_for_updates)
        help_menu.addAction(update_action)
        
        help_menu.addSeparator()

        # About
        about_action = QAction("About", self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)
        
        # Contact
        contact_action = QAction("Contact Developer", self)
        contact_action.triggered.connect(self.show_contact)
        help_menu.addAction(contact_action)
        
        
    def reset_to_default_signatures(self):
        """Reset to default signatures."""
        reply = QMessageBox.question(
            self, "Reset Signatures", 
            "This will replace all current signatures with the default set. Continue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, 
            QMessageBox.StandardButton.No
        )
    
        if reply == QMessageBox.StandardButton.Yes:
            self.signatures = self.create_default_signatures()
            self.save_signatures_to_disk()
            self.update_signatures_table()
            QMessageBox.information(
                self, "Signatures Reset", 
                f"Signature database has been reset to {len(self.signatures)} default signatures."
            )

    def download_signature_database(self):
        """
        Download a comprehensive signature database from an online source.
        """
        from PyQt5.QtWidgets import QDialog, QVBoxLayout, QRadioButton, QGroupBox, QDialogButtonBox, QLabel
    
        class SourceDialog(QDialog):
            def __init__(self, parent=None):
                super().__init__(parent)
                self.setWindowTitle("Select Signature Source")
                self.resize(400, 300)
            
                layout = QVBoxLayout(self)
            
                #Description
                label = QLabel(
                    "Select a source to download a comprehensive file signature database. "
                    "These sources provide extensive collections of file signatures that can "
                    "greatly improve file type identification."
                )
                label.setWordWrap(True)
                layout.addWidget(label)
            
                # Sources group
                group = QGroupBox("Available Sources")
                group_layout = QVBoxLayout()
            
                self.source1 = QRadioButton("Gary Kessler's File Signatures Database")
                self.source1.setChecked(True)
                self.source2 = QRadioButton("TrID File Type Definitions")
                self.source3 = QRadioButton("PRONOM Database (UK National Archives)")
            
                group_layout.addWidget(self.source1)
                group_layout.addWidget(self.source2)
                group_layout.addWidget(self.source3)
                group.setLayout(group_layout)
            
                layout.addWidget(group)
            
                # Note about conversion
                note = QLabel(
                    "Note: The selected database will be downloaded and converted to the format "
                    "required by this application. This may take a few minutes depending on "
                    "the size of the database."
                )
                note.setWordWrap(True)
                layout.addWidget(note)
            
                # Buttons
                buttons = QDialogButtonBox(
                    QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
                )
                buttons.accepted.connect(self.accept)
                buttons.rejected.connect(self.reject)
                layout.addWidget(buttons)
                
                
            def get_selected_source(self):
                if self.source1.isChecked():
                    return "kessler"
                elif self.source2.isChecked():
                    return "trid"
                elif self.source3.isChecked():
                    return "pronom"
                return None
    
        # Show dialog to select source
        dialog = SourceDialog(self)
        if dialog.exec_() != QDialog.Accepted:
            return
        
        source = dialog.get_selected_source()
    
        # Create a progress dialog
        from PyQt5.QtWidgets import QProgressDialog
        progress = QProgressDialog("Downloading signature database...", "Cancel", 0, 100, self)
        progress.setWindowTitle("Downloading Signatures")
        progress.setMinimumDuration(0)
        progress.setValue(0)
        progress.show()
    
        # Download in a separate thread to avoid freezing the UI
        class DownloadThread(QThread):
            progress_signal = pyqtSignal(int)
            finished_signal = pyqtSignal(bool, str)
            
            def __init__(self, source):
                super().__init__()
                self.source = source
            
            def run(self):
                try:
                    import requests
                    import tempfile
                
                    self.progress_signal.emit(10)
                
                    # URLs for different sources
                    if self.source == "kessler":
                        url = "https://www.garykessler.net/library/file_sigs.json"
                        headers = {}
                    elif self.source == "trid":
                        url = "https://mark0.net/download/triddefs_xml.7z"
                        headers = {}
                    elif self.source == "pronom":
                        url = "https://www.nationalarchives.gov.uk/pronom/pronom.json"
                        headers = {}
                    else:
                        self.finished_signal.emit(False, "Invalid source selected")
                        return
                
                    self.progress_signal.emit(20)
                
                    # Download the file
                    response = requests.get(url, headers=headers, stream=True)
                    if response.status_code != 200:
                        self.finished_signal.emit(False, f"Failed to download: HTTP {response.status_code}")
                        return
                
                    self.progress_signal.emit(40)
                
                    # Save to a temporary file
                    with tempfile.NamedTemporaryFile(delete=False) as tmp:
                        tmp_path = tmp.name
                        for chunk in response.iter_content(chunk_size=8192):
                            tmp.write(chunk)
                
                    self.progress_signal.emit(60)
                
                    # Import the file
                    signatures = []
                
                    if self.source == "kessler":
                        # Direct JSON import
                        with open(tmp_path, 'r', encoding='utf-8') as f:
                            data = json.load(f)
                        if isinstance(data, dict) and "filesigs" in data:
                            signatures = data["filesigs"]
                        elif isinstance(data, list):
                            signatures = data
                
                    elif self.source == "trid":
                        # Process TrID defs (requires py7zr and xml parsing)
                        try:
                            import py7zr
                            import xml.etree.ElementTree as ET
                        
                            # Extract the 7z file
                            extract_dir = tempfile.mkdtemp()
                            with py7zr.SevenZipFile(tmp_path, mode='r') as z:
                                z.extractall(extract_dir)
                        
                            # Process XML files
                            for xml_file in os.listdir(extract_dir):
                                if xml_file.endswith(".xml"):
                                    try:
                                        tree = ET.parse(os.path.join(extract_dir, xml_file))
                                        root = tree.getroot()
                                    
                                        # Extract signature info from TrID XML format
                                        sig = {}
                                        sig["File description"] = root.findtext("FileType", "Unknown")
                                        sig["File extension"] = root.findtext("Extension", "")
                                        sig["Category"] = "Other"
                                    
                                        # Extract binary signature
                                        pattern = root.find("HexPattern")
                                        if pattern is not None:
                                            sig["Header (hex)"] = pattern.text.replace(" ", "")
                                            sig["Header offset"] = root.findtext("Offset", "0")
                                            signatures.append(sig)
                                    except Exception as e:
                                        pass
                        except ImportError:
                            self.finished_signal.emit(False, "Required libraries missing: py7zr")
                            return
                
                    elif self.source == "pronom":
                        # Process PRONOM data
                        with open(tmp_path, 'r', encoding='utf-8') as f:
                            data = json.load(f)
                    
                        for fmt in data.get("formats", []):
                            sig = {}
                            sig["File description"] = fmt.get("name", "Unknown")
                            sig["File extension"] = "|".join(fmt.get("extensions", []))
                            sig["Category"] = fmt.get("category", "Other")
                        
                            # Extract signature from PRONOM format
                            for signature in fmt.get("signatures", []):
                                if "pattern" in signature:
                                    sig["Header (hex)"] = signature["pattern"].replace(" ", "")
                                    sig["Header offset"] = str(signature.get("offset", 0))
                                    signatures.append(sig.copy())
                
                    self.progress_signal.emit(80)
                
                    # Clean up temp files
                    os.unlink(tmp_path)
                
                    self.progress_signal.emit(90)
                
                    # Return the signatures
                    self.finished_signal.emit(True, signatures)
                
                except Exception as e:
                    self.finished_signal.emit(False, str(e))
    
        # Create and start the download thread
        self.download_thread = DownloadThread(source)
        self.download_thread.progress_signal.connect(progress.setValue)
        
        def handle_download_finished(success, result):
            progress.hide()
        
            if not success:
                QMessageBox.critical(self, "Download Failed", f"Failed to download signatures: {result}")
                return
            
            if isinstance(result, list):
                # Success with signatures list
                reply = QMessageBox.question(
                    self, "Import Signatures", 
                    f"Downloaded {len(result)} signatures. Replace existing or merge?",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No | QMessageBox.StandardButton.Cancel,
                    QMessageBox.StandardButton.Yes
                )
            
                if reply == QMessageBox.StandardButton.Cancel:
                    return
                
                if reply == QMessageBox.StandardButton.Yes:
                    # Replace
                    self.signatures = result
                else:
                    # Merge
                    existing_sigs = {(sig.get("Header (hex)", ""), sig.get("Header offset", "0")): sig 
                                    for sig in self.signatures}
                added = 0
                
                for sig in result:
                    key = (sig.get("Header (hex)", ""), sig.get("Header offset", "0"))
                    if key not in existing_sigs:
                        self.signatures.append(sig)
                        added += 1
                        
                QMessageBox.information(self, "Signatures Merged", f"Added {added} new signatures.")
                
                # Save and update
                self.save_signatures_to_comprehensive_file()
                self.update_signatures_table()
            
                QMessageBox.information(
                    self, "Download Complete", 
                    f"Successfully downloaded and imported {len(result)} signatures."
                )
    
        self.download_thread.finished_signal.connect(handle_download_finished)
        self.download_thread.start()
        
        
        # Replace the following methods in your code:

    def setup_single_file_tab(self):
        """
        Set up the tab for single file analysis.
        """
        layout = QVBoxLayout()
    
        # File selection
        file_group = QGroupBox("File Selection")
        file_layout = QVBoxLayout()
        file_group.setLayout(file_layout)

        # File path input
        file_select_layout = QHBoxLayout()
        self.file_path_edit = QLineEdit()
        self.file_path_edit.setPlaceholderText("Select a file to analyze...")
        self.file_path_edit.setReadOnly(True)
        file_select_button = QPushButton("Browse...")
        file_select_button.clicked.connect(self.select_file)
        file_select_layout.addWidget(self.file_path_edit)
        file_select_layout.addWidget(file_select_button)
        file_layout.addLayout(file_select_layout)
        
        # Advanced options for file analysis
        advanced_options_layout = QHBoxLayout()
        
        # Archive handling options
        self.archive_check = QCheckBox("Process archives")
        self.archive_check.setToolTip("Analyze contents of archive files (ZIP, RAR, etc.)")
        self.archive_check.setChecked(True)

        # Subdirectory option
        self.subdir_check = QCheckBox("Process subdirectories")
        self.subdir_check.setToolTip("Process files within subdirectories when analyzing a directory")

        depth_label = QLabel("Max Depth:")
        self.depth_spin = QSpinBox()
        self.depth_spin.setRange(1, 10)
        self.depth_spin.setValue(3)
        self.depth_spin.setToolTip("Maximum subdirectory depth to process")

        advanced_options_layout.addWidget(self.archive_check)
        advanced_options_layout.addWidget(self.subdir_check)
        advanced_options_layout.addWidget(depth_label)
        advanced_options_layout.addWidget(self.depth_spin)
        advanced_options_layout.addStretch()

        file_layout.addLayout(advanced_options_layout)

        # Analyze button
        analyze_button = QPushButton("Analyze File")
        analyze_button.setStyleSheet("background-color: #4CAF50; color: white; font-weight: bold;")
        analyze_button.clicked.connect(self.analyze_current_file)  # Changed from analyze_single_file
        file_layout.addWidget(analyze_button)

        layout.addWidget(file_group)

        # Results splitter
        splitter = QSplitter(Qt.Vertical)

        # Basic results section
        basic_results_group = QGroupBox("File Information")
        basic_results_layout = QVBoxLayout()
        basic_results_group.setLayout(basic_results_layout)

        self.file_info_table = QTableWidget(5, 2)
        self.file_info_table.setHorizontalHeaderLabels(["Property", "Value"])
        self.file_info_table.verticalHeader().setVisible(False)
        self.file_info_table.setItem(0, 0, QTableWidgetItem("File Name"))
        self.file_info_table.setItem(1, 0, QTableWidgetItem("File Size"))
        self.file_info_table.setItem(2, 0, QTableWidgetItem("Identified Type"))
        self.file_info_table.setItem(3, 0, QTableWidgetItem("Extension"))
        self.file_info_table.setItem(4, 0, QTableWidgetItem("Path"))
        self.file_info_table.horizontalHeader().setStretchLastSection(True)

        basic_results_layout.addWidget(self.file_info_table)

        # Confidence bar
        conf_layout = QHBoxLayout()
        conf_layout.addWidget(QLabel("Confidence:"))
        self.confidence_bar = QProgressBar()
        self.confidence_bar.setRange(0, 100)
        self.confidence_bar.setValue(0)
        self.confidence_bar.setTextVisible(True)
        self.confidence_bar.setFormat("%v%")
        self.confidence_bar.setStyleSheet(
            "QProgressBar { border: 1px solid grey; border-radius: 3px; text-align: center; }"
            "QProgressBar::chunk { background-color: #4CAF50; }"
        )
        conf_layout.addWidget(self.confidence_bar)
        basic_results_layout.addLayout(conf_layout)

        # Entropy and hash display
        info_layout = QHBoxLayout()
        self.entropy_label = QLabel("Entropy: --")
        self.entropy_label.setStyleSheet("font-weight: bold;")
        info_layout.addWidget(self.entropy_label)
        self.md5_label = QLabel("MD5: --")
        self.md5_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        info_layout.addWidget(self.md5_label)
        self.sha256_label = QLabel("SHA256: --")
        self.sha256_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        info_layout.addWidget(self.sha256_label)
        basic_results_layout.addLayout(info_layout)

        # Action buttons
        action_layout = QHBoxLayout()
        save_as_button = QPushButton("Save As...")
        save_as_button.clicked.connect(self.save_file_as)
        rename_button = QPushButton("Rename & Fix Extension")
        rename_button.clicked.connect(self.rename_file)
        hex_view_button = QPushButton("View Hex")
        hex_view_button.clicked.connect(self.view_hex_dump)
        meta_button = QPushButton("View Metadata")
        meta_button.clicked.connect(self.view_metadata)
        copy_md5_btn = QPushButton("Copy MD5")
        copy_md5_btn.clicked.connect(lambda: QApplication.clipboard().setText(
            self.current_results.get("md5", "")) if self.current_results else None)
        copy_sha_btn = QPushButton("Copy SHA256")
        copy_sha_btn.clicked.connect(lambda: QApplication.clipboard().setText(
            self.current_results.get("sha256", "")) if self.current_results else None)

        action_layout.addWidget(save_as_button)
        action_layout.addWidget(rename_button)
        action_layout.addWidget(hex_view_button)
        action_layout.addWidget(meta_button)
        action_layout.addWidget(copy_md5_btn)
        action_layout.addWidget(copy_sha_btn)
        basic_results_layout.addLayout(action_layout)

        # Detailed matches section
        detailed_results_group = QGroupBox("Detailed Signature Matches")
        detailed_results_layout = QVBoxLayout()
        detailed_results_group.setLayout(detailed_results_layout)

        self.matches_table = QTableWidget(0, 4)
        self.matches_table.setHorizontalHeaderLabels(["File Type", "Extension", "Hex Signature", "Priority"])
        self.matches_table.horizontalHeader().setStretchLastSection(True)
        detailed_results_layout.addWidget(self.matches_table)

        # Archive contents section (initially hidden)
        self.archive_contents_group = QGroupBox("Archive Contents")
        self.archive_contents_group.setVisible(False)
        archive_contents_layout = QVBoxLayout()
        self.archive_contents_group.setLayout(archive_contents_layout)

        # Create archive contents tree view
        self.archive_tree = QTreeWidget()
        self.archive_tree.setHeaderLabels(["Filename", "Size", "Type"])
        self.archive_tree.setColumnWidth(0, 300)
        archive_contents_layout.addWidget(self.archive_tree)
        
        # Archive action buttons
        archive_action_layout = QHBoxLayout()
        extract_button = QPushButton("Extract Selected")
        extract_button.clicked.connect(self.extract_selected)
        analyze_selected_button = QPushButton("Analyze Selected")
        analyze_selected_button.clicked.connect(self.analyze_selected_archive_item)
        archive_action_layout.addWidget(extract_button)
        archive_action_layout.addWidget(analyze_selected_button)
        archive_action_layout.addStretch()
        archive_contents_layout.addLayout(archive_action_layout)

        # Add the widgets to the splitter
        splitter.addWidget(basic_results_group)
        splitter.addWidget(detailed_results_group)
        splitter.setSizes([300, 300])  # Default sizes for the two sections

        layout.addWidget(splitter)
        layout.addWidget(self.archive_contents_group)

        # Add metadata section (hidden initially)
        self.metadata_group = QGroupBox("File Metadata")
        self.metadata_group.setVisible(False)
        metadata_layout = QVBoxLayout()
        self.metadata_group.setLayout(metadata_layout)

        self.metadata_table = QTableWidget(0, 2)
        self.metadata_table.setHorizontalHeaderLabels(["Property", "Value"])
        self.metadata_table.horizontalHeader().setStretchLastSection(True)
        metadata_layout.addWidget(self.metadata_table)

        layout.addWidget(self.metadata_group)
    
        self.single_file_tab.setLayout(layout)

    def setup_batch_tab(self):
        """
        Set up the tab for batch file processing.
        """
        layout = QVBoxLayout()
    
        # Input directory
        input_group = QGroupBox("Input Settings")
        input_layout = QVBoxLayout()
        input_group.setLayout(input_layout)

        input_dir_layout = QHBoxLayout()
        self.input_dir_label = QLabel("Input Directory:")
        self.input_dir_edit = QLineEdit()
        self.input_dir_button = QPushButton("Browse...")
        self.input_dir_button.clicked.connect(self.select_input_dir)
        input_dir_layout.addWidget(self.input_dir_label)
        input_dir_layout.addWidget(self.input_dir_edit)
        input_dir_layout.addWidget(self.input_dir_button)
        input_layout.addLayout(input_dir_layout)

        # Output directory
        output_dir_layout = QHBoxLayout()
        self.output_dir_label = QLabel("Output Directory:")
        self.output_dir_edit = QLineEdit()
        self.output_dir_button = QPushButton("Browse...")
        self.output_dir_button.clicked.connect(self.select_output_dir)
        output_dir_layout.addWidget(self.output_dir_label)
        output_dir_layout.addWidget(self.output_dir_edit)
        output_dir_layout.addWidget(self.output_dir_button)
        input_layout.addLayout(output_dir_layout)

        # Processing options
        options_layout = QHBoxLayout()
        self.recursive_check = QCheckBox("Process Subdirectories")
        self.rename_check = QCheckBox("Rename Files with Correct Extensions")
        self.rename_check.setChecked(True)
        options_layout.addWidget(self.recursive_check)
        options_layout.addWidget(self.rename_check)
        input_layout.addLayout(options_layout)

        layout.addWidget(input_group)

        # Process and Cancel buttons
        btn_layout = QHBoxLayout()
        self.process_button = QPushButton("Process Files")
        self.process_button.clicked.connect(self.process_batch_files)
        self.process_button.setStyleSheet("background-color: #4CAF50; color: white; font-weight: bold;")
        btn_layout.addWidget(self.process_button)

        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.setStyleSheet("background-color: #f44336; color: white; font-weight: bold;")
        self.cancel_button.setVisible(False)
        self.cancel_button.clicked.connect(self.cancel_batch)
        btn_layout.addWidget(self.cancel_button)
        layout.addLayout(btn_layout)

        # Current file label
        self.current_file_label = QLabel("")
        self.current_file_label.setStyleSheet("color: #666; font-style: italic;")
        layout.addWidget(self.current_file_label)

        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)

        # Results display
        results_group = QGroupBox("Batch Results")
        results_layout = QVBoxLayout()
        results_group.setLayout(results_layout)
    
        self.batch_results_table = QTableWidget(0, 4)
        self.batch_results_table.setHorizontalHeaderLabels(["Filename", "Identified Type", "New Filename", "Status"])
        self.batch_results_table.horizontalHeader().setStretchLastSection(True)
    
        results_layout.addWidget(self.batch_results_table)
    
        # Results actions
        results_actions_layout = QHBoxLayout()
        save_results_button = QPushButton("Save Results to JSON")
        save_results_button.clicked.connect(self.save_batch_results)
        export_csv_button = QPushButton("Export as CSV")
        export_csv_button.clicked.connect(lambda: self.export_results("csv"))
        report_button = QPushButton("Generate Report")
        report_button.clicked.connect(self.generate_report)
    
        results_actions_layout.addWidget(save_results_button)
        results_actions_layout.addWidget(export_csv_button)
        results_actions_layout.addWidget(report_button)
        results_layout.addLayout(results_actions_layout)
    
        layout.addWidget(results_group)
    
        # Visualization section
        viz_group = QGroupBox("Results Visualization")
        viz_layout = QVBoxLayout()
        viz_group.setLayout(viz_layout)
    
        # Chart type selection
        chart_type_layout = QHBoxLayout()
        chart_type_label = QLabel("Visualization Type:")
        self.chart_type_combo = QComboBox()
        self.chart_type_combo.addItems(["File Type Distribution", "Extension Match Analysis"])
        self.chart_type_combo.currentIndexChanged.connect(self.update_chart)
    
        chart_type_layout.addWidget(chart_type_label)
        chart_type_layout.addWidget(self.chart_type_combo)
        viz_layout.addLayout(chart_type_layout)
    
        # Create visualization placeholder
        self.viz_placeholder = QLabel("Visualization will appear here after processing files")
        self.viz_placeholder.setAlignment(Qt.AlignCenter)
        self.viz_placeholder.setStyleSheet("background-color: #f0f0f0; padding: 20px;")
        self.viz_placeholder.setMinimumHeight(200)
        viz_layout.addWidget(self.viz_placeholder)
    
        layout.addWidget(viz_group)
    
        # Set the layout for the tab (ONLY HERE, not in other methods)
        self.batch_tab.setLayout(layout)

    def setup_database_tab(self):
        """
        Set up the tab for viewing and managing the file type database.
        Enhanced with better filtering and information display.
        """
        layout = QVBoxLayout()
    
        # Search/filter area
        filter_group = QGroupBox("Filter Options")
        filter_layout = QVBoxLayout()
    
        # Text filter
        text_filter_layout = QHBoxLayout()
        filter_label = QLabel("Filter Signatures:")
        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText("Type to filter by name, extension, or hex signature...")
        self.filter_edit.textChanged.connect(self.filter_signatures)
        text_filter_layout.addWidget(filter_label)
        text_filter_layout.addWidget(self.filter_edit)
        filter_layout.addLayout(text_filter_layout)

        # Category and extension filters
        category_ext_layout = QHBoxLayout()
    
        # Category filter
        category_label = QLabel("Filter by Category:")
        self.category_combo = QComboBox()
        self.category_combo.addItem("All Categories")
        self.category_combo.addItems(["Document", "Image", "Audio", "Video", "Archive", "Executable", "Other"])
        self.category_combo.currentIndexChanged.connect(self.filter_signatures)
        category_ext_layout.addWidget(category_label)
        category_ext_layout.addWidget(self.category_combo)
    
        # Extension filter
        ext_label = QLabel("Filter by Extension:")
        self.ext_edit = QLineEdit()
        self.ext_edit.setPlaceholderText("e.g. pdf, jpg, doc...")
        self.ext_edit.textChanged.connect(self.filter_signatures)
        category_ext_layout.addWidget(ext_label)
        category_ext_layout.addWidget(self.ext_edit)
    
        filter_layout.addLayout(category_ext_layout)
        filter_group.setLayout(filter_layout)
        layout.addWidget(filter_group)

        # Database stats
        stats_layout = QHBoxLayout()
        self.db_stats_label = QLabel("Database Statistics: Loading...")
        stats_layout.addWidget(self.db_stats_label)
    
        # Quick action buttons
        refresh_button = QPushButton("Refresh")
        refresh_button.clicked.connect(self.update_signatures_table)
        import_button = QPushButton("Import Signatures")
        import_button.clicked.connect(self.import_comprehensive_signatures)
        download_button = QPushButton("Download Signatures")
        download_button.clicked.connect(self.download_signature_database)

        stats_layout.addStretch()
        stats_layout.addWidget(refresh_button)
        stats_layout.addWidget(import_button)
        stats_layout.addWidget(download_button)
    
        layout.addLayout(stats_layout)

        # Signatures table
        self.signatures_table = QTableWidget(0, 5)
        self.signatures_table.setHorizontalHeaderLabels(["File Type", "Extensions", "Header (hex)", "Offset", "Category"])
        self.signatures_table.horizontalHeader().setStretchLastSection(True)
        self.signatures_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.signatures_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
    
        # Enable sorting
        self.signatures_table.setSortingEnabled(True)
    
        # Enable selection of rows
        self.signatures_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.signatures_table.setSelectionMode(QTableWidget.SingleSelection)
    
        # Enable alternating row colors
        self.signatures_table.setAlternatingRowColors(True)
    
        # Connect double-click to edit
        self.signatures_table.cellDoubleClicked.connect(self.on_signature_double_clicked)
    
        layout.addWidget(self.signatures_table)

        # Database actions
        actions_layout = QHBoxLayout()
        add_sig_button = QPushButton("Add Signature")
        add_sig_button.clicked.connect(self.add_signature)
        edit_sig_button = QPushButton("Edit Signature")
        edit_sig_button.clicked.connect(self.edit_signature)
        delete_sig_button = QPushButton("Delete Signature")
        delete_sig_button.clicked.connect(self.delete_signature)
        export_button = QPushButton("Export Database")
        export_button.clicked.connect(self.export_database)
        actions_layout.addWidget(add_sig_button)
        actions_layout.addWidget(edit_sig_button)
        actions_layout.addWidget(delete_sig_button)
        actions_layout.addWidget(export_button)
        layout.addLayout(actions_layout)
    
        # Set the layout for the tab
        self.database_tab.setLayout(layout)
    
        # Update the table when setting up
        self.update_signatures_table()

    def on_signature_double_clicked(self, row, column):
        """Handle double-click on a signature in the table."""
        self.edit_signature()
    
    def load_signatures(self):
        """Load file signatures from the JSON file."""
        default_sig_file = resource_path(os.path.join("resources", "file_sigs.json"))
        comprehensive_sig_file = resource_path(os.path.join("resources", "comprehensive_sigs.json"))

        signatures_loaded = False

        try:
            if os.path.exists(comprehensive_sig_file):
                with open(comprehensive_sig_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    if "filesigs" in data:
                        self.signatures = data.get('filesigs', [])
                        signatures_loaded = True
                        self.statusBar().showMessage(f"Loaded {len(self.signatures)} signatures from comprehensive database")

            if not signatures_loaded and os.path.exists(default_sig_file):
                with open(default_sig_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    if "filesigs" in data:
                        self.signatures = data.get('filesigs', [])
                        signatures_loaded = True
                        self.statusBar().showMessage(f"Loaded {len(self.signatures)} signatures from default database")
        
            # If no signatures loaded yet, create them
            if not signatures_loaded:
                self.signatures = self.create_default_signatures()
                self.save_signatures_to_disk()
                signatures_loaded = True
                self.statusBar().showMessage(f"Created default signature database with {len(self.signatures)} signatures")

            self.update_signatures_table()

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load signatures: {str(e)}")
            self.signatures = []
            self.save_signatures_to_disk()

    def import_comprehensive_signatures(self):
        """
        Import a comprehensive file signature database.
        This can be called from a menu option or button.
        """
        file_path, _ = QFileDialog.getOpenFileName(
        self, "Import Signature Database", "", "JSON Files (*.json);;All Files (*.*)"
        )
    
        if not file_path:
            return
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
         
            # Check if the file has the expected format
            if "filesigs" not in data:
                # Try to convert from other formats
                if isinstance(data, list):
                    # Simple list format
                    imported_sigs = data
                elif isinstance(data, dict) and any(isinstance(data.get(k), list) for k in data):
                    # Find the first list in the dictionary
                    for k, v in data.items():
                        if isinstance(v, list) and len(v) > 0:
                            imported_sigs = v
                            break
                    else:
                        imported_sigs = []
                else:
                    imported_sigs = []
                
                if not imported_sigs:
                    QMessageBox.warning(self, "Invalid Format", "The selected file does not contain a valid signature database.")
                    return
            else:
                imported_sigs = data.get("filesigs", [])
            
            # Normalize the imported signatures
            normalized_sigs = []
            for sig in imported_sigs:
                # Convert to our expected format
                normalized_sig = {
                    "File description": sig.get("name", sig.get("File description", sig.get("description", "Unknown"))),
                    "File extension": sig.get("extension", sig.get("File extension", sig.get("ext", ""))),
                    "Header (hex)": sig.get("signature", sig.get("Header (hex)", sig.get("hex", ""))),
                    "Header offset": str(sig.get("offset", sig.get("Header offset", "0"))),
                    "Category": sig.get("category", sig.get("Category", "Other")),
                    "Priority": int(sig.get("priority", sig.get("Priority", 50)))
                }
            
                # Skip entries with no signature
                if not normalized_sig["Header (hex)"]:
                    continue
                
                normalized_sigs.append(normalized_sig)
            
            # Ask if user wants to replace or merge
            if self.signatures:
                reply = QMessageBox.question(
                    self, "Import Signatures", 
                    f"Found {len(normalized_sigs)} signatures. Do you want to replace the existing {len(self.signatures)} signatures or merge them?",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No | QMessageBox.StandardButton.Cancel
                )
            
                if reply == QMessageBox.StandardButton.Cancel:
                    return
                elif reply == QMessageBox.StandardButton.Yes:
                    # Replace
                    self.signatures = normalized_sigs
                else:
                    # Merge - add only signatures that don't duplicate existing ones
                    existing_sigs = {(sig.get("Header (hex)", ""), sig.get("Header offset", "0")): sig for sig in self.signatures}
                    added = 0
                
                    for sig in normalized_sigs:
                        key = (sig.get("Header (hex)", ""), sig.get("Header offset", "0"))
                        if key not in existing_sigs:
                            self.signatures.append(sig)
                            added += 1
                        
                    QMessageBox.information(self, "Signatures Merged", f"Added {added} new signatures.")
            else:
                # No existing signatures, just add the new ones
                self.signatures = normalized_sigs
            
            # Save the updated signatures
            self.save_signatures_to_comprehensive_file()
        
            # Update the UI
            self.update_signatures_table()
            self.statusBar().showMessage(f"Loaded {len(self.signatures)} signatures")
        
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to import signatures: {str(e)}")
    
    def save_signatures_to_comprehensive_file(self):
        """
        Save the signatures to a comprehensive file.
        """
        try:
            os.makedirs("resources", exist_ok=True)
            sig_file = resource_path(os.path.join("resources", "comprehensive_sigs.json"))
        
            with open(sig_file, 'w', encoding='utf-8') as f:
                json.dump({"filesigs": self.signatures}, f, indent=4)
            
            self.statusBar().showMessage(f"Saved {len(self.signatures)} signatures to comprehensive database")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save comprehensive signatures: {str(e)}")
    
    def create_default_signatures(self):
        """
        Create a default set of common file signatures if none exist.
        """
        return [
            {
                "File description": "JPEG Image",
                "File extension": "jpg|jpeg|jpe",
                "Header (hex)": "FFD8FF",
                "Header offset": "0",
                "Category": "Image",
                "Priority": 50
            },
            {
                "File description": "PNG Image",
                "File extension": "png",
                "Header (hex)": "89504E470D0A1A0A",
                "Header offset": "0",
                "Category": "Image",
                "Priority": 50
            },
            {
                "File description": "GIF Image",
                "File extension": "gif",
                "Header (hex)": "474946383761",
                "Header offset": "0",
                "Category": "Image",
                "Priority": 50
            },
            {
                "File description": "PDF Document",
                "File extension": "pdf",
                "Header (hex)": "25504446",
                "Header offset": "0",
                "Category": "Document",
                "Priority": 50
            },
            {
                "File description": "ZIP Archive",
                "File extension": "zip",
                "Header (hex)": "504B0304",
                "Header offset": "0",
                "Category": "Archive",
                "Priority": 40
            },
            {
                "File description": "MP3 Audio",
                "File extension": "mp3",
                "Header (hex)": "494433",
                "Header offset": "0",
                "Category": "Audio",
                "Priority": 50
            },
            {
                "File description": "Microsoft Office Document",
                "File extension": "docx|xlsx|pptx",
                "Header (hex)": "504B0304",
                "Header offset": "0",
                "Category": "Document",
                "Priority": 45
            }
        ]

    def update_signatures_table(self):
        """
        Update the signatures table in the database tab.
        """
        self.signatures_table.setRowCount(0)
        
        filter_text = self.filter_edit.text().lower()
        category_filter = self.category_combo.currentText()
        
        for i, sig in enumerate(self.signatures):
            description = sig.get("File description", "")
            extensions = sig.get("File extension", "")
            header = sig.get("Header (hex)", "")
            offset = sig.get("Header offset", "")
            category = sig.get("Category", "Other")
            
            # Apply filters
            if filter_text and not (filter_text in description.lower() or 
                                   filter_text in extensions.lower()):
                continue
                
            if category_filter != "All Categories" and category != category_filter:
                continue
                
            # Add to table
            row = self.signatures_table.rowCount()
            self.signatures_table.insertRow(row)
            self.signatures_table.setItem(row, 0, QTableWidgetItem(description))
            self.signatures_table.setItem(row, 1, QTableWidgetItem(extensions))
            self.signatures_table.setItem(row, 2, QTableWidgetItem(header))
            self.signatures_table.setItem(row, 3, QTableWidgetItem(offset))
            self.signatures_table.setItem(row, 4, QTableWidgetItem(category))

    def download_sample_signatures(self):
        """
        Download a sample set of comprehensive signatures.
        """
        import requests
    
        # Create a progress dialog
        progress = QProgressDialog("Downloading sample signatures...", "Cancel", 0, 100, self)
        progress.setWindowTitle("Downloading")
        progress.setMinimumDuration(0)
        progress.setValue(0)
        progress.show()
    
        try:
            # This URL should be replaced with an actual hosted file
            url = "https://raw.githubusercontent.com/your-username/file-signatures/main/comprehensive_sigs.json"
        
            progress.setValue(20)
        
            response = requests.get(url)
            if response.status_code != 200:
                QMessageBox.critical(self, "Download Failed", f"Failed to download: HTTP {response.status_code}")
                progress.close()
                return
            
            progress.setValue(70)
        
            # Save the downloaded file
            os.makedirs("resources", exist_ok=True)
            with open(resource_path(os.path.join("resources", "comprehensive_sigs.json")), 'w', encoding='utf-8') as f:
                f.write(response.text)
            
            progress.setValue(90)
        
            # Try to load the signatures
            try:
                data = json.loads(response.text)
                if "filesigs" in data:
                    self.signatures = data["filesigs"]
                    self.update_signatures_table()
                
                    QMessageBox.information(
                        self, "Download Complete", 
                        f"Successfully downloaded and loaded {len(self.signatures)} signatures."
                    )
                else:
                    QMessageBox.warning(self, "Invalid Format", "The downloaded file has an invalid format.")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to parse downloaded file: {str(e)}")
            
            progress.setValue(100)
        
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to download signatures: {str(e)}")
        
        finally:
            progress.close()

    def filter_signatures(self):
        """
        Filter the signatures table based on user input.
        """
        self.update_signatures_table()

    def select_file(self):
        """
        Select a single file for analysis.
        """
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File to Analyze")
        if file_path and os.path.exists(file_path):
            self.file_path_edit.setText(file_path)
            self.analyzed_file_path = file_path
    
            # Clear current results
            self.clear_single_file_results()
    
            # Auto-analyze the file when selected
            # self.analyze_current_file() # Comment out this line
    
            # Add to recent files
            self.add_recent_file(file_path)

    def analyze_single_file(self):
        """
        Analyze a single file selected by the user through the menu.
        """
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File to Analyze")
        if file_path:
            # Switch to the single file tab
            self.tabs.setCurrentIndex(0)
            # Update the file path field
            self.file_path_edit.setText(file_path)
            self.analyzed_file_path = file_path
            # Analyze the file
            self.analyze_current_file()
            # Add to recent files
            self.add_recent_file(file_path)

    def analyze_current_file(self):
        """Analyze the currently selected file."""
        file_path = self.file_path_edit.text()

        if not file_path or not os.path.exists(file_path):
            QMessageBox.warning(self, "Error", "Please select a valid file to analyze.")
            return

        try:
            file_size = os.path.getsize(file_path)
            file_name = os.path.basename(file_path)

            file_type, primary_ext, all_extensions, matches = identify_file_type(file_path, self.signatures)

            # Extract metadata using detected type
            metadata = MetadataExtractor.extract_metadata(file_path, detected_type=file_type)

            # Calculate entropy
            try:
                with open(file_path, 'rb') as f:
                    file_data = f.read(65536)
                entropy = calculate_entropy(file_data)
            except Exception:
                entropy = 0.0

            # Calculate hashes
            try:
                md5_hash = hashlib.md5()
                sha256_hash = hashlib.sha256()
                with open(file_path, 'rb') as f:
                    for chunk in iter(lambda: f.read(8192), b''):
                        md5_hash.update(chunk)
                        sha256_hash.update(chunk)
                md5_str = md5_hash.hexdigest()
                sha256_str = sha256_hash.hexdigest()
            except Exception:
                md5_str = "Error"
                sha256_str = "Error"

            # Get confidence from best match
            confidence = 0
            if matches:
                confidence = matches[0].get("confidence", matches[0].get("priority", 50))

            self.current_results = {
                "file_path": file_path,
                "file_name": file_name,
                "file_size": file_size,
                "file_type": file_type,
                "primary_ext": primary_ext,
                "all_extensions": all_extensions,
                "matches": matches,
                "metadata": metadata,
                "entropy": entropy,
                "md5": md5_str,
                "sha256": sha256_str,
                "confidence": confidence,
            }

            # Update the basic info table
            self.file_info_table.setItem(0, 1, QTableWidgetItem(file_name))
            self.file_info_table.setItem(1, 1, QTableWidgetItem(self.format_file_size(file_size)))
            self.file_info_table.setItem(2, 1, QTableWidgetItem(file_type))
            self.file_info_table.setItem(3, 1, QTableWidgetItem(primary_ext))
            self.file_info_table.setItem(4, 1, QTableWidgetItem(file_path))

            # Update confidence bar
            if hasattr(self, 'confidence_bar'):
                self.confidence_bar.setValue(min(confidence, 100))

            # Update entropy label
            if hasattr(self, 'entropy_label'):
                color = "#4CAF50" if entropy < 4 else "#FF9800" if entropy < 7 else "#f44336"
                self.entropy_label.setText(f"Entropy: {entropy:.3f}")
                self.entropy_label.setStyleSheet(f"color: {color}; font-weight: bold;")

            # Update hash labels
            if hasattr(self, 'md5_label'):
                self.md5_label.setText(f"MD5: {md5_str}")
            if hasattr(self, 'sha256_label'):
                self.sha256_label.setText(f"SHA256: {sha256_str}")

            # Update the matches table
            self.matches_table.setRowCount(0)
            for match in matches:
                row = self.matches_table.rowCount()
                self.matches_table.insertRow(row)
                self.matches_table.setItem(row, 0, QTableWidgetItem(match.get("description", "")))
                extensions = match.get("all_extensions", [])
                ext_str = ", ".join(extensions) if isinstance(extensions, list) else str(extensions)
                self.matches_table.setItem(row, 1, QTableWidgetItem(ext_str))
                self.matches_table.setItem(row, 2, QTableWidgetItem(match.get("hex_signature", "")))
                self.matches_table.setItem(row, 3, QTableWidgetItem(str(match.get("priority", 0))))

            self.update_metadata_table(metadata)

            # Check if archive
            self.archive_contents_group.setVisible(False)
            self.archive_tree.clear()

            is_archive = False
            if self.archive_check.isChecked():
                if primary_ext.lower() in ["zip", "rar", "7z", "tar", "gz", "bz2"] or "archive" in file_type.lower():
                    is_archive = True
                    self.process_archive_file(file_path, primary_ext.lower())

            if is_archive:
                self.statusBar().showMessage(f"File analyzed: {file_name} - {file_type} (Archive contents available)")
            else:
                self.statusBar().showMessage(f"File analyzed: {file_name} - {file_type}")

            # Update ML tab
            if self.ml_classifier:
                ml_predictions = self.ml_classifier.predict(file_path)
                self.update_ml_tab(file_path, file_type, entropy, confidence, ml_predictions)

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to analyze file: {str(e)}")
            
    def process_archive_file(self, file_path, extension):
        """Process an archive file and display its contents."""
        try:
            # Clear previous data
            self.archive_tree.clear()
            
            # Display the archive contents section
            self.archive_contents_group.setVisible(True)
            
            # Create root item
            root = QTreeWidgetItem(self.archive_tree, [os.path.basename(file_path), 
                                self.format_file_size(os.path.getsize(file_path)), "Archive"])
            root.setExpanded(True)
            
            # Process based on archive type
            if extension in ["zip", "docx", "xlsx", "pptx", "epub"]:
                self.process_zip_archive(file_path, root)
            elif extension == "rar":
                # Try to process RAR, but handle missing module
                try:
                    import rarfile
                    self.process_rar_archive(file_path, root)
                except ImportError:
                    QTreeWidgetItem(root, ["RAR support requires 'rarfile' module", "", ""])
                    QTreeWidgetItem(root, ["Install with: pip install rarfile", "", ""])
            elif extension in ["7z"]:
                # Try to process 7Z, but handle missing module
                try:
                    import py7zr
                    self.process_7z_archive(file_path, root)
                except ImportError:
                    QTreeWidgetItem(root, ["7Z support requires 'py7zr' module", "", ""])
                    QTreeWidgetItem(root, ["Install with: pip install py7zr", "", ""])
            elif extension in ["tar", "gz", "bz2"]:
                self.process_tar_archive(file_path, root)
            else:
                QTreeWidgetItem(root, ["Unsupported archive format", "", ""])
                
        except Exception as e:
            QMessageBox.warning(self, "Archive Processing Error", f"Failed to process archive: {str(e)}")
        
    def extract_temp_from_zip(self, archive_path, item_path, temp_dir):
        """
        Extract a file from a ZIP archive to a temporary directory.
        """
        try:
            import zipfile
        
            # Generate a unique output path to avoid conflicts
            filename = os.path.basename(item_path)
            output_path = os.path.join(temp_dir, filename)
        
            with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                # Check if the file exists in the archive
                if item_path in zip_ref.namelist():
                    # Extract the file
                    with zip_ref.open(item_path) as source:
                        with open(output_path, 'wb') as target:
                            shutil.copyfileobj(source, target)
                    return output_path
        
            return None
        except Exception as e:
            return None
        
    def extract_temp_from_rar(self, archive_path, item_path, temp_dir):
        """
        Extract a file from a RAR archive to a temporary directory.
        """
        try:
            import rarfile
            
            # Generate a unique output path to avoid conflicts
            filename = os.path.basename(item_path)
            output_path = os.path.join(temp_dir, filename)
            
            with rarfile.RarFile(archive_path) as rar_ref:
                # Check if the file exists in the archive
                if item_path in rar_ref.namelist():
                    # Extract the file
                    with rar_ref.open(item_path) as source:
                        with open(output_path, 'wb') as target:
                            shutil.copyfileobj(source, target)
                    return output_path
            
            return None
        except ImportError:
            return None
        except Exception as e:
            return None

    def extract_temp_from_7z(self, archive_path, item_path, temp_dir):
        """
        Extract a file from a 7z archive to a temporary directory.
        """
        try:
            import py7zr
            
            # Generate a unique output path to avoid conflicts
            filename = os.path.basename(item_path)
            output_path = os.path.join(temp_dir, filename)
            
            with py7zr.SevenZipFile(archive_path, 'r') as sz_ref:
                # 7z has different extraction method
                targets = [item_path]
                sz_ref.extract(path=temp_dir, targets=targets)
                
                # Check if file was extracted
                extracted_path = os.path.join(temp_dir, item_path)
                if os.path.exists(extracted_path):
                    return extracted_path
                
            return None
        except ImportError:
            return None
        except Exception as e:
            return None

    def extract_temp_from_tar(self, archive_path, item_path, temp_dir):
        """
        Extract a file from a TAR archive to a temporary directory.
        """
        try:
            import tarfile
            
            # Generate a unique output path to avoid conflicts
            filename = os.path.basename(item_path)
            output_path = os.path.join(temp_dir, filename)
            
            with tarfile.open(archive_path, 'r:*') as tar_ref:
                # Check if the file exists in the archive
                try:
                    member = tar_ref.getmember(item_path)
                    with tar_ref.extractfile(member) as source:
                        with open(output_path, 'wb') as target:
                            shutil.copyfileobj(source, target)
                    return output_path
                except KeyError:
                    pass
            
            return None
        except Exception as e:
            return None    
        
    def process_zip_archive(self, file_path, parent_item):
        """
        Process a ZIP archive and display its contents.
        """
        try:
            import zipfile
        
            with zipfile.ZipFile(file_path, 'r') as zip_ref:
                # Get all files in the archive
                file_list = zip_ref.namelist()
            
                # Create a dictionary to store folder structure
                folders = {}
            
                # Process each file
                for file in file_list:
                    # Skip directories in the listing
                    if file.endswith('/'):
                        continue
                    
                    # Split path components
                    path_parts = file.split('/')
                    filename = path_parts[-1]
                
                    # Create folder structure
                    current_path = ""
                    current_parent = parent_item
                
                    # Process folders
                    for i in range(len(path_parts) - 1):
                        folder_name = path_parts[i]
                        if current_path:
                            current_path += '/' + folder_name
                        else:
                            current_path = folder_name
                        
                        # Create folder item if it doesn't exist
                        if current_path not in folders:
                            folder_item = QTreeWidgetItem(current_parent, [folder_name, "", "Folder"])
                            folders[current_path] = folder_item
                            current_parent = folder_item
                        else:
                            current_parent = folders[current_path]
                
                    # Get file info
                    info = zip_ref.getinfo(file)
                    file_size = info.file_size
                
                    # Guess file type based on extension
                    file_ext = os.path.splitext(filename)[1].lower().strip('.')
                    file_type = self.guess_file_type_from_extension(file_ext)
                
                    # Add file item
                    QTreeWidgetItem(current_parent, [filename, self.format_file_size(file_size), file_type])
                
        except ImportError:
            QTreeWidgetItem(parent_item, ["zipfile module not available", "", ""])
        except Exception as e:
            QTreeWidgetItem(parent_item, [f"Error processing ZIP: {str(e)}", "", ""])

    def process_rar_archive(self, file_path, parent_item):
        """
        Process a RAR archive and display its contents.
        """
        try:
            # Try to import rarfile module
            import rarfile
            
            # Process RAR file
            with rarfile.RarFile(file_path) as rar_ref:
                # Create a dictionary to store folder structure
                folders = {}
                
                # Process each file
                for info in rar_ref.infolist():
                    # Skip directories in the listing
                    if info.isdir():
                        continue
                        
                    # Get file info
                    filename = os.path.basename(info.filename)
                    file_size = info.file_size
                    
                    # Split path components
                    path_parts = info.filename.replace('\\', '/').split('/')
                    
                    # Create folder structure
                    current_path = ""
                    current_parent = parent_item
                    
                    # Process folders
                    for i in range(len(path_parts) - 1):
                        folder_name = path_parts[i]
                        if current_path:
                            current_path += '/' + folder_name
                        else:
                            current_path = folder_name
                            
                        # Create folder item if it doesn't exist
                        if current_path not in folders:
                            folder_item = QTreeWidgetItem(current_parent, [folder_name, "", "Folder"])
                            folders[current_path] = folder_item
                            current_parent = folder_item
                        else:
                            current_parent = folders[current_path]
                    
                    # Guess file type based on extension
                    file_ext = os.path.splitext(filename)[1].lower().strip('.')
                    file_type = self.guess_file_type_from_extension(file_ext)
                    
                    # Add file item
                    QTreeWidgetItem(current_parent, [filename, self.format_file_size(file_size), file_type])
                    
        except ImportError:
            QTreeWidgetItem(parent_item, ["rarfile module not available. Install it with 'pip install rarfile'", "", ""])
        except Exception as e:
            QTreeWidgetItem(parent_item, [f"Error processing RAR: {str(e)}", "", ""])

    def process_7z_archive(self, file_path, parent_item):
        """
        Process a 7z archive and display its contents.
        """
        try:
            # Try to import py7zr module
            import py7zr
            
            # Process 7z file
            with py7zr.SevenZipFile(file_path, 'r') as sz_ref:
                # Get archive info
                file_list = sz_ref.getnames()
                
                # Create a dictionary to store folder structure
                folders = {}
                
                # Process each file
                for file in file_list:
                    # Skip directories in the listing
                    if file.endswith('/') or file.endswith('\\'):
                        continue
                        
                    # Replace backslashes with forward slashes for consistency
                    file = file.replace('\\', '/')
                    
                    # Split path components
                    path_parts = file.split('/')
                    filename = path_parts[-1]
                    
                    # Create folder structure
                    current_path = ""
                    current_parent = parent_item
                    
                    # Process folders
                    for i in range(len(path_parts) - 1):
                        folder_name = path_parts[i]
                        if current_path:
                            current_path += '/' + folder_name
                        else:
                            current_path = folder_name
                            
                        # Create folder item if it doesn't exist
                        if current_path not in folders:
                            folder_item = QTreeWidgetItem(current_parent, [folder_name, "", "Folder"])
                            folders[current_path] = folder_item
                            current_parent = folder_item
                        else:
                            current_parent = folders[current_path]
                    
                    # Guess file type based on extension
                    file_ext = os.path.splitext(filename)[1].lower().strip('.')
                    file_type = self.guess_file_type_from_extension(file_ext)
                    
                    # Add file item - Note: Size information may not be directly available
                    QTreeWidgetItem(current_parent, [filename, "", file_type])
                    
        except ImportError:
            QTreeWidgetItem(parent_item, ["py7zr module not available. Install it with 'pip install py7zr'", "", ""])
        except Exception as e:
            QTreeWidgetItem(parent_item, [f"Error processing 7z: {str(e)}", "", ""])

    def process_tar_archive(self, file_path, parent_item):
        """
        Process a TAR archive and display its contents.
        """
        try:
            import tarfile
            
            # Open and process tar file
            with tarfile.open(file_path, 'r:*') as tar_ref:
                # Create a dictionary to store folder structure
                folders = {}
                
                # Process each file
                for member in tar_ref.getmembers():
                    # Skip directories
                    if member.isdir():
                        continue
                    
                    # Get file info
                    file_path = member.name
                    file_size = member.size
                    
                    # Replace backslashes with forward slashes for consistency
                    file_path = file_path.replace('\\', '/')
                    
                    # Split path components
                    path_parts = file_path.split('/')
                    filename = path_parts[-1]
                    
                    # Create folder structure
                    current_path = ""
                    current_parent = parent_item
                    
                    # Process folders
                    for i in range(len(path_parts) - 1):
                        folder_name = path_parts[i]
                        if current_path:
                            current_path += '/' + folder_name
                        else:
                            current_path = folder_name
                            
                        # Create folder item if it doesn't exist
                        if current_path not in folders:
                            folder_item = QTreeWidgetItem(current_parent, [folder_name, "", "Folder"])
                            folders[current_path] = folder_item
                            current_parent = folder_item
                        else:
                            current_parent = folders[current_path]
                    
                    # Guess file type based on extension
                    file_ext = os.path.splitext(filename)[1].lower().strip('.')
                    file_type = self.guess_file_type_from_extension(file_ext)
                    
                    # Add file item
                    QTreeWidgetItem(current_parent, [filename, self.format_file_size(file_size), file_type])
                    
        except Exception as e:
            QTreeWidgetItem(parent_item, [f"Error processing TAR: {str(e)}", "", ""])

    def guess_file_type_from_extension(self, extension):
        """
        Guess file type based on extension.
        """
        extension = extension.lower()
        
        # Common file types
        ext_types = {
            # Images
            'jpg': 'JPEG Image',
            'jpeg': 'JPEG Image',
            'png': 'PNG Image',
            'gif': 'GIF Image',
            'bmp': 'Bitmap Image',
            'tif': 'TIFF Image',
            'tiff': 'TIFF Image',
            'webp': 'WebP Image',
            
            # Documents
            'pdf': 'PDF Document',
            'doc': 'Word Document',
            'docx': 'Word Document',
            'xls': 'Excel Spreadsheet',
            'xlsx': 'Excel Spreadsheet',
            'ppt': 'PowerPoint Presentation',
            'pptx': 'PowerPoint Presentation',
            'txt': 'Text File',
            'rtf': 'Rich Text Document',
            'md': 'Markdown Document',
            'html': 'HTML Document',
            'htm': 'HTML Document',
            'xml': 'XML Document',
            'json': 'JSON Data',
            
            # Audio
            'mp3': 'MP3 Audio',
            'wav': 'WAV Audio',
            'ogg': 'OGG Audio',
            'flac': 'FLAC Audio',
            'aac': 'AAC Audio',
            'm4a': 'M4A Audio',
            
            # Video
            'mp4': 'MP4 Video',
            'avi': 'AVI Video',
            'mkv': 'MKV Video',
            'mov': 'QuickTime Video',
            'wmv': 'Windows Media Video',
            'flv': 'Flash Video',
            
            # Archives
            'zip': 'ZIP Archive',
            'rar': 'RAR Archive',
            '7z': '7-Zip Archive',
            'tar': 'TAR Archive',
            'gz': 'GZIP Archive',
            'bz2': 'BZIP2 Archive',
            
            # Code
            'py': 'Python Source',
            'js': 'JavaScript Source',
            'java': 'Java Source',
            'c': 'C Source',
            'cpp': 'C++ Source',
            'cs': 'C# Source',
            'php': 'PHP Source',
            'rb': 'Ruby Source',
            'go': 'Go Source',
            'swift': 'Swift Source',
            
            # Executables
            'exe': 'Windows Executable',
            'dll': 'Windows DLL',
            'so': 'Shared Library',
            'app': 'macOS Application',
            'apk': 'Android Package',
            'dmg': 'macOS Disk Image',
            
            # Other
            'sqlite': 'SQLite Database',
            'db': 'Database File',
            'log': 'Log File',
            'ini': 'Configuration File',
            'csv': 'CSV Data',
            'iso': 'Disk Image',
        }
        
        return ext_types.get(extension, f"{extension.upper()} File" if extension else "Unknown")

    def extract_selected(self):
        """
        Extract selected items from an archive.
        """
        # Get selected items
        selected_items = self.archive_tree.selectedItems()
        
        if not selected_items:
            QMessageBox.information(self, "Extract", "Please select files to extract.")
            return
            
        # Get destination directory
        dest_dir = QFileDialog.getExistingDirectory(self, "Select Extraction Directory")
        if not dest_dir:
            return
            
        # Get archive file path
        file_path = self.file_path_edit.text()
        ext = os.path.splitext(file_path)[1].lower().strip('.')
        
        # Extract based on archive type
        if ext in ["zip", "docx", "xlsx", "pptx", "epub"]:
            self.extract_from_zip(file_path, selected_items, dest_dir)
        else:
            QMessageBox.information(self, "Extract", "Extraction is currently supported only for ZIP archives.")

    def extract_from_zip(self, archive_path, selected_items, dest_dir):
        """
        Extract files from a ZIP archive.
        """
        try:
            import zipfile
            
            # Get list of selected file paths
            selected_paths = []
            for item in selected_items:
                path = self.get_item_full_path(item)
                selected_paths.append(path)
            
            # Extract files
            with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                for file in zip_ref.namelist():
                    # Check if file should be extracted
                    for selected_path in selected_paths:
                        if file == selected_path or file.startswith(selected_path + '/'):
                            # Extract file
                            zip_ref.extract(file, dest_dir)
                            break
                            
            QMessageBox.information(self, "Extract", "Files extracted successfully.")
        except Exception as e:
            QMessageBox.critical(self, "Extract Error", f"Failed to extract files: {str(e)}")

    def get_item_full_path(self, item):
        """
        Get the full path of a tree item.
        """
        path_parts = []
        
        # Traverse up the tree to get all path components
        current = item
        while current is not None:
            path_parts.insert(0, current.text(0))
            current = current.parent()
        
        # Skip the first component (the archive itself)
        if len(path_parts) > 1:
            path_parts = path_parts[1:]
            
        # Join path parts
        return '/'.join(path_parts)

    def analyze_selected_archive_item(self):
        """
        Analyze selected item from an archive.
        """
        # Get selected item
        selected_items = self.archive_tree.selectedItems()
        
        if not selected_items or len(selected_items) != 1:
            QMessageBox.information(self, "Analyze", "Please select a single file to analyze.")
            return
        
        item = selected_items[0]
        
        # Check if it's a file (not a folder)
        if item.text(2) == "Folder":
            QMessageBox.information(self, "Analyze", "Please select a file, not a folder.")
            return
        
        # Get file path
        file_path = self.file_path_edit.text()
        item_path = self.get_item_full_path(item)
        
        # Extract to temporary directory
        import tempfile
        temp_dir = tempfile.mkdtemp()
        
        try:
            # Extract based on archive type
            ext = os.path.splitext(file_path)[1].lower().strip('.')
            extracted_path = None
            
            if ext in ["zip", "docx", "xlsx", "pptx", "epub"]:
                extracted_path = self.extract_temp_from_zip(file_path, item_path, temp_dir)
            elif ext == "rar":
                extracted_path = self.extract_temp_from_rar(file_path, item_path, temp_dir)
            elif ext == "7z":
                extracted_path = self.extract_temp_from_7z(file_path, item_path, temp_dir)
            elif ext in ["tar", "gz", "bz2"]:
                extracted_path = self.extract_temp_from_tar(file_path, item_path, temp_dir)
            
            if extracted_path and os.path.exists(extracted_path):
                # Analyze the extracted file
                self.file_path_edit.setText(extracted_path)
                self.analyze_current_file()
            else:
                QMessageBox.warning(self, "Analyze", "Failed to extract the selected file.")
                
        except Exception as e:
            QMessageBox.critical(self, "Analysis Error", f"Failed to analyze file: {str(e)}")
        
    # Don't delete temp directory as it's needed for analysis
            
    def update_metadata_table(self, metadata):
        """
        Update the metadata table with extracted metadata.
        """
        self.metadata_table.setRowCount(0)
        
        # Add metadata items
        for key, value in metadata.items():
            # Skip complex nested objects
            if isinstance(value, dict):
                continue
                
            row = self.metadata_table.rowCount()
            self.metadata_table.insertRow(row)
            self.metadata_table.setItem(row, 0, QTableWidgetItem(str(key)))
            self.metadata_table.setItem(row, 1, QTableWidgetItem(str(value)))
        
        # Resize rows to content
        self.metadata_table.resizeRowsToContents()

    def clear_single_file_results(self):
        """
        Clear the current results in the single file tab.
        """
        # Check if widgets exist and are valid before trying to access them
        if hasattr(self, 'file_info_table') and self.file_info_table is not None:
        # Make sure the object is still valid
            try:
            # Clear basic info table
                for row in range(5):
                    self.file_info_table.setItem(row, 1, QTableWidgetItem(""))
            except RuntimeError:
            # Widget has been deleted, just ignore
                pass
    
        if hasattr(self, 'matches_table') and self.matches_table is not None:
            try:
                # Clear matches table
                self.matches_table.setRowCount(0)
            except RuntimeError:
                pass
    
        if hasattr(self, 'metadata_table') and self.metadata_table is not None:
            try:
                # Clear metadata table
                self.metadata_table.setRowCount(0)
            except RuntimeError:
                pass
    
        # Hide metadata section
        if hasattr(self, 'metadata_group') and self.metadata_group is not None:
            try:
                self.metadata_group.setVisible(False)
            except RuntimeError:
                pass
    
    # Clear stored results
        self.current_results = None

    def select_input_dir(self):
        """
        Select input directory for batch processing.
        """
        dir_path = QFileDialog.getExistingDirectory(self, "Select Input Directory")
        if dir_path:
            self.input_dir_edit.setText(dir_path)
            
            # Suggest output directory if it's not set
            if not self.output_dir_edit.text():
                suggested_output = os.path.join(dir_path, "processed")
                self.output_dir_edit.setText(suggested_output)

    def select_output_dir(self):
        """
        Select output directory for batch processing.
        """
        dir_path = QFileDialog.getExistingDirectory(self, "Select Output Directory")
        if dir_path:
            self.output_dir_edit.setText(dir_path)

    def analyze_multiple_files(self):
        """Analyze multiple files selected by the user."""
        file_paths, _ = QFileDialog.getOpenFileNames(self, "Select Files to Analyze")
        if not file_paths:
            return
            
        # Switch to the batch tab
        self.tabs.setCurrentIndex(1)
        
        # Create a temporary directory for processing
        import tempfile
        temp_dir = tempfile.mkdtemp()
        output_dir = os.path.join(temp_dir, "analyzed")
        os.makedirs(output_dir, exist_ok=True)

        input_dir = os.path.join(temp_dir, "input")
        os.makedirs(input_dir, exist_ok=True)

        for file_path in file_paths:
            filename = os.path.basename(file_path)
            shutil.copy2(file_path, os.path.join(input_dir, filename))
        
        # Set up the batch processing
        self.input_dir_edit.setText(input_dir)
        self.output_dir_edit.setText(output_dir)
        
        # Start processing
        self.process_batch_files()

    def process_batch_files(self):
        """
        Process files in the input directory for batch processing.
        """
        input_dir = self.input_dir_edit.text()
        output_dir = self.output_dir_edit.text()

        if not input_dir or not output_dir:
            QMessageBox.warning(self, "Error", "Please select input and output directories.")
            return

        if not os.path.exists(input_dir):
            QMessageBox.warning(self, "Error", f"Input directory {input_dir} does not exist.")
            return

        if not os.path.exists(output_dir):
            try:
                os.makedirs(output_dir)
            except Exception as e:
                QMessageBox.warning(self, "Error", f"Could not create output directory: {str(e)}")
                return

        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.process_button.setEnabled(False)
        self.cancel_button.setVisible(True)
        self.batch_results_table.setRowCount(0)

        self.worker = BatchFileProcessor(
            input_dir,
            output_dir,
            self.signatures,
            recursive=self.recursive_check.isChecked(),
            rename_files=self.rename_check.isChecked()
        )
        self.worker.progress_signal.connect(self.update_progress)
        self.worker.file_processed_signal.connect(self.add_batch_result)
        self.worker.current_file_signal.connect(self.update_current_file)
        self.worker.finished_signal.connect(self.on_batch_finished)
        self.worker.start()

    def update_progress(self, value):
        """
        Update the progress bar during batch processing.
        """
        self.progress_bar.setValue(value)
        
    def add_batch_result(self, result):
        """
        Add a single file result to the batch results table.
        """
        row = self.batch_results_table.rowCount()
        self.batch_results_table.insertRow(row)
        
        # Add result data to the table
        self.batch_results_table.setItem(row, 0, QTableWidgetItem(result.get("original_file", "")))
        self.batch_results_table.setItem(row, 1, QTableWidgetItem(result.get("identified_type", "")))
        self.batch_results_table.setItem(row, 2, QTableWidgetItem(result.get("new_filename", "")))
        
        # Set status cell with color
        status_text = "Success"
        if "error" in result:
            status_text = f"Error: {result['error']}"
            status_cell = QTableWidgetItem(status_text)
            status_cell.setBackground(Qt.red)
            status_cell.setForeground(Qt.white)
        elif result.get("extension_changed", False):
            status_text = "Extension Changed"
            status_cell = QTableWidgetItem(status_text)
            status_cell.setBackground(Qt.green)
        else:
            status_cell = QTableWidgetItem(status_text)
            
        self.batch_results_table.setItem(row, 3, status_cell)
        
    def on_batch_finished(self, results):
        """Handle batch processing completion."""
        self.progress_bar.setVisible(False)
        self.process_button.setEnabled(True)
        self.cancel_button.setVisible(False)
        self.current_file_label.setText("")
        
        # Store the results for potential saving
        self.batch_results = results
        
        # Update visualization
        self.update_chart()
        
        # Show summary
        total = len(results)
        errors = sum(1 for r in results if "error" in r)
        changed = sum(1 for r in results if r.get("extension_changed", False))
        
        QMessageBox.information(
            self, "Batch Processing Complete",
            f"Processed {total} files\n"
            f"Changed extensions: {changed}\n"
            f"Errors: {errors}"
        )

    def update_chart(self):
        """
        Update the visualization chart based on batch results.
        """
        if not hasattr(self, 'batch_results') or not self.batch_results:
            return
            
        chart_type = self.chart_type_combo.currentText()
        
        # Create visualization for batch results
        # (This would normally use matplotlib or another library)
        # For now, we'll just update the placeholder
        self.viz_placeholder.setText(f"Visualization: {chart_type}\n\n" + 
                                   f"Total files: {len(self.batch_results)}\n" +
                                   f"Files with changed extensions: {sum(1 for r in self.batch_results if r.get('extension_changed', False))}\n" +
                                   f"Files with errors: {sum(1 for r in self.batch_results if 'error' in r)}")

    def save_results(self):
        """
        Save the analysis results to a file.
        """
        # Determine which tab is active
        current_tab = self.tabs.currentIndex()
        
        if current_tab == 0:  # Single file tab
            # Save single file analysis results
            if not self.current_results:
                QMessageBox.warning(self, "Error", "No results to save.")
                return
                
            file_path, _ = QFileDialog.getSaveFileName(
                self, "Save Results", "", "JSON Files (*.json);;All Files (*)"
            )
            
            if file_path:
                try:
                    with open(file_path, 'w', encoding='utf-8') as f:
                        json.dump(self.current_results, f, indent=4)
                    QMessageBox.information(self, "Success", "Results saved successfully.")
                except Exception as e:
                    QMessageBox.critical(self, "Error", f"Failed to save results: {str(e)}")
                    
        elif current_tab == 1:  # Batch tab
            self.save_batch_results()
            
    def save_batch_results(self):
        """
        Save batch processing results to a file.
        """
        if not hasattr(self, 'batch_results') or not self.batch_results:
            QMessageBox.warning(self, "Error", "No batch results to save.")
            return
            
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save Batch Results", "", "JSON Files (*.json);;CSV Files (*.csv);;All Files (*)"
        )
        
        if not file_path:
            return
            
        try:
            # Save as JSON or CSV based on extension
            if file_path.lower().endswith('.csv'):
                self.export_results("csv", file_path)
            else:
                # Default to JSON
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(self.batch_results, f, indent=4)
                    
            QMessageBox.information(self, "Success", "Batch results saved successfully.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save batch results: {str(e)}")

    def export_results(self, format_type, custom_path=None):
        """
        Export results to a specified format.
        """
        # Determine which tab is active
        current_tab = self.tabs.currentIndex()
        
        if current_tab == 0:  # Single file tab
            results = self.current_results
            if not results:
                QMessageBox.warning(self, "Error", "No results to export.")
                return
                
            # Choose file path if not provided
            if not custom_path:
                if format_type == "csv":
                    file_path, _ = QFileDialog.getSaveFileName(
                        self, "Export Results as CSV", "", "CSV Files (*.csv);;All Files (*)"
                    )
                else:
                    file_path, _ = QFileDialog.getSaveFileName(
                        self, "Export Results as JSON", "", "JSON Files (*.json);;All Files (*)"
                    )
            else:
                file_path = custom_path
                
            if not file_path:
                return
                
            try:
                if format_type == "csv":
                    import csv
                    with open(file_path, 'w', newline='', encoding='utf-8') as f:
                        writer = csv.writer(f)
                        # Write header
                        writer.writerow(['Property', 'Value'])
                        # Write file info
                        writer.writerow(['File Name', results.get('file_name', '')])
                        writer.writerow(['File Size', results.get('file_size', '')])
                        writer.writerow(['Identified Type', results.get('file_type', '')])
                        writer.writerow(['Primary Extension', results.get('primary_ext', '')])
                        writer.writerow(['All Extensions', ', '.join(results.get('all_extensions', []))])
                        writer.writerow(['Path', results.get('file_path', '')])
                        
                        # Write matches
                        writer.writerow([])
                        writer.writerow(['Matches', ''])
                        writer.writerow(['File Type', 'Extensions', 'Hex Signature', 'Priority'])
                        for match in results.get('matches', []):
                            writer.writerow([
                                match.get('description', ''),
                                ', '.join(match.get('all_extensions', [])),
                                match.get('hex_signature', ''),
                                match.get('priority', 0)
                            ])
                            
                        # Write metadata
                        if 'metadata' in results:
                            writer.writerow([])
                            writer.writerow(['Metadata', ''])
                            for key, value in results['metadata'].items():
                                if not isinstance(value, dict):
                                    writer.writerow([key, value])
                else:
                    # JSON format
                    with open(file_path, 'w', encoding='utf-8') as f:
                        json.dump(results, f, indent=4)
                        
                QMessageBox.information(self, "Success", f"Results exported to {file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to export results: {str(e)}")
                
        elif current_tab == 1:  # Batch tab
            if not hasattr(self, 'batch_results') or not self.batch_results:
                QMessageBox.warning(self, "Error", "No batch results to export.")
                return
                
            # Choose file path if not provided
            if not custom_path:
                if format_type == "csv":
                    file_path, _ = QFileDialog.getSaveFileName(
                        self, "Export Batch Results as CSV", "", "CSV Files (*.csv);;All Files (*)"
                    )
                else:
                    file_path, _ = QFileDialog.getSaveFileName(
                        self, "Export Batch Results as JSON", "", "JSON Files (*.json);;All Files (*)"
                    )
            else:
                file_path = custom_path
                
            if not file_path:
                return
                
            try:
                if format_type == "csv":
                    import csv
                    with open(file_path, 'w', newline='', encoding='utf-8') as f:
                        writer = csv.writer(f)
                        # Write header
                        writer.writerow(['Original File', 'Identified Type', 'New Filename', 'Extension Changed', 'Error'])
                        # Write data
                        for result in self.batch_results:
                            writer.writerow([
                                result.get('original_file', ''),
                                result.get('identified_type', ''),
                                result.get('new_filename', ''),
                                result.get('extension_changed', False),
                                result.get('error', '')
                            ])
                else:
                    # JSON format
                    with open(file_path, 'w', encoding='utf-8') as f:
                        json.dump(self.batch_results, f, indent=4)
                        
                QMessageBox.information(self, "Success", f"Batch results exported to {file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to export batch results: {str(e)}")

    def save_file_as(self):
        """
        Save the analyzed file with a new name/extension.
        """
        if not self.current_results:
            QMessageBox.warning(self, "Error", "Please analyze a file first.")
            return
            
        original_file = self.current_results["file_path"]
        suggested_ext = self.current_results["primary_ext"]
        
        # Create a suggested filename with the correct extension
        base_name = os.path.splitext(os.path.basename(original_file))[0]
        suggested_name = f"{base_name}.{suggested_ext}" if suggested_ext else base_name
        
        # Get destination file path
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save File As", suggested_name, "All Files (*.*)"
        )
        
        if file_path:
            try:
                # Copy the file to the new location
                shutil.copy2(original_file, file_path)
                QMessageBox.information(self, "Success", f"File saved as: {file_path}")
                
                # Optionally ask if the user wants to analyze the new file
                reply = QMessageBox.question(
                    self, "Analyze New File?", 
                    "Would you like to analyze the newly saved file?",
                    QMessageBox.Yes | QMessageBox.No, QMessageBox.No
                )
                
                if reply == QMessageBox.Yes:
                    self.file_path_edit.setText(file_path)
                    self.analyze_single_file()
                    
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to save file: {str(e)}")

    def rename_file(self):
        """
        Rename the file with the correct extension based on analysis.
        """
        if not self.current_results:
            QMessageBox.warning(self, "Error", "Please analyze a file first.")
            return
            
        original_file = self.current_results["file_path"]
        suggested_ext = self.current_results["primary_ext"]
        
        if not suggested_ext:
            QMessageBox.warning(self, "Error", "No extension was identified for this file.")
            return
            
        # Create a new filename with the correct extension
        dir_name = os.path.dirname(original_file)
        base_name = os.path.splitext(os.path.basename(original_file))[0]
        new_filename = f"{base_name}.{suggested_ext}"
        new_path = os.path.join(dir_name, new_filename)

        if os.path.exists(new_path) and new_path != original_file:
            reply = QMessageBox.question(
                self, "File Exists", 
                f"File {new_filename} already exists. Overwrite?",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No
            )
            
            if reply == QMessageBox.No:
                return
        
        try:
            # Rename the file
            shutil.move(original_file, new_path)
            QMessageBox.information(self, "Success", f"File renamed to: {new_filename}")
            
            # Update the current file path
            self.file_path_edit.setText(new_path)
            self.analyzed_file_path = new_path
            
            # Update the displayed file information
            self.file_info_table.setItem(0, 1, QTableWidgetItem(new_filename))
            self.file_info_table.setItem(4, 1, QTableWidgetItem(new_path))
            
            # Update stored results
            self.current_results["file_path"] = new_path
            self.current_results["file_name"] = new_filename
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to rename file: {str(e)}")

    def edit_file_type(self):
        """
        Allow the user to manually edit the file type for the current file.
        """
        current_tab = self.tabs.currentIndex()
        
        if current_tab == 0:  # Single file tab
            if not self.current_results:
                QMessageBox.warning(self, "Error", "Please analyze a file first.")
                return
                
            # Get new file type from user
            new_type, ok = QInputDialog.getText(
                self, "Edit File Type", 
                "Enter new file type:", 
                text=self.current_results.get("file_type", "")
            )
            
            if ok and new_type:
                # Update the displayed file information
                self.file_info_table.setItem(2, 1, QTableWidgetItem(new_type))
                
                # Update stored results
                self.current_results["file_type"] = new_type
                
                # Ask if user wants to set a new extension
                new_ext, ok = QInputDialog.getText(
                    self, "Edit Extension", 
                    "Enter new file extension (without dot):",
                    text=self.current_results.get("primary_ext", "")
                )
                
                if ok and new_ext:
                    # Update extension in results
                    self.current_results["primary_ext"] = new_ext
                    self.file_info_table.setItem(3, 1, QTableWidgetItem(new_ext))
        
        elif current_tab == 1:  # Batch tab
            # Get selected row in batch results table
            selected_rows = self.batch_results_table.selectedItems()
            if not selected_rows:
                QMessageBox.warning(self, "Error", "Please select a file in the results table.")
                return
                
            row = selected_rows[0].row()
            original_file = self.batch_results_table.item(row, 0).text()
            
            # Get new file type from user
            current_type = self.batch_results_table.item(row, 1).text()
            new_type, ok = QInputDialog.getText(
                self, "Edit File Type", 
                f"Enter new file type for {original_file}:", 
                text=current_type
            )
            
            if ok and new_type:
                # Update the displayed information
                self.batch_results_table.setItem(row, 1, QTableWidgetItem(new_type))
                
                # Update stored results if available
                if hasattr(self, 'batch_results'):
                    for result in self.batch_results:
                        if result.get("original_file") == original_file:
                            result["identified_type"] = new_type

    def view_hex_dump(self):
        """
        Display a hex dump of the current file.
        """
        # Get the current file path based on the active tab
        file_path = None
        
        if self.tabs.currentIndex() == 0:  # Single file tab
            if self.current_results:
                file_path = self.current_results["file_path"]
        
        # If no file is selected, allow user to choose one
        if not file_path:
            file_path, _ = QFileDialog.getOpenFileName(self, "Select File for Hex Dump")
            
        if not file_path:
            return
            
        try:
            # Create hex dump window
            hex_dump = HexViewerWindow(file_path, parent=self)
            hex_dump.show()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to create hex dump: {str(e)}")

    def view_metadata(self):
        """
        View metadata for the current file.
        """
        if not self.current_results or "metadata" not in self.current_results:
            QMessageBox.warning(self, "Error", "No metadata available. Please analyze a file first.")
            return
            
        # Toggle metadata section visibility
        self.metadata_group.setVisible(not self.metadata_group.isVisible())
        
        # Alternative: Show in a separate window
        metadata_viewer = MetadataViewer(self.current_results["metadata"], parent=self)
        metadata_viewer.show()

    def view_file_structure(self):
        """
        View the structure of the current file.
        """
        if not self.current_results:
            QMessageBox.warning(self, "Error", "Please analyze a file first.")
            return
            
        QMessageBox.information(
            self, "Feature Coming Soon", 
            "File structure visualization will be added in a future version."
        )

    def convert_file(self):
        """
        Convert the current file to another format.
        """
        if not self.current_results:
            # If no file is analyzed, let user select one
            file_path, _ = QFileDialog.getOpenFileName(self, "Select File to Convert")
            if not file_path:
                return
        else:
            file_path = self.current_results["file_path"]
        
        # Open the conversion dialog
        dialog = ConvertFileDialog(file_path, parent=self)
        
        if dialog.exec_() == QDialog.Accepted:
            # If file was converted successfully, ask if user wants to analyze the new file
            reply = QMessageBox.question(
                self, "Analyze Converted File?", 
                "Would you like to analyze the newly converted file?",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No
            )
            
            if reply == QMessageBox.Yes:
                # Get the output path from the dialog
                new_path = dialog.output_path
                self.file_path_edit.setText(new_path)
                self.analyze_single_file()

    def repair_file(self):
        """
        Attempt to repair a corrupted file.
        """
        QMessageBox.information(
            self, "Feature Coming Soon", 
            "File repair functionality will be added in a future version."
        )

    def extract_content(self):
        """
        Extract content from container files like archives.
        """
        QMessageBox.information(
            self, "Feature Coming Soon", 
            "Content extraction will be added in a future version."
        )

    def generate_report(self):
        """
        Generate a detailed report for the current analysis.
        """
        current_tab = self.tabs.currentIndex()
        
        if current_tab == 0:  # Single file tab
            if not self.current_results:
                QMessageBox.warning(self, "Error", "Please analyze a file first.")
                return
                
            # Get destination file path
            file_path, _ = QFileDialog.getSaveFileName(
                self, "Save Report", "report.html", "HTML Files (*.html);;All Files (*.*)"
            )
            
            if not file_path:
                return
                
            try:
                # Generate HTML report
                self.generate_html_report(file_path, single_file=True)
                
                # Ask if user wants to open the report
                reply = QMessageBox.question(
                    self, "Open Report?", 
                    "Would you like to open the generated report?",
                    QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes
                )
                
                if reply == QMessageBox.Yes:
                    QDesktopServices.openUrl(QUrl.fromLocalFile(file_path))
                    
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to generate report: {str(e)}")
                
        elif current_tab == 1:  # Batch tab
            if not hasattr(self, 'batch_results') or not self.batch_results:
                QMessageBox.warning(self, "Error", "No batch results to report on.")
                return
                
            # Get destination file path
            file_path, _ = QFileDialog.getSaveFileName(
                self, "Save Batch Report", "batch_report.html", "HTML Files (*.html);;All Files (*.*)"
            )
            
            if not file_path:
                return
                
            try:
                # Generate HTML report
                self.generate_html_report(file_path, single_file=False)
                
                # Ask if user wants to open the report
                reply = QMessageBox.question(
                    self, "Open Report?", 
                    "Would you like to open the generated report?",
                    QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes
                )
                
                if reply == QMessageBox.Yes:
                    QDesktopServices.openUrl(QUrl.fromLocalFile(file_path))
                    
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to generate report: {str(e)}")

    def generate_html_report(self, file_path, single_file=True):
        """
        Generate an HTML report of the analysis.
        """
        if single_file:
            # Generate report for single file analysis
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write("""
                <!DOCTYPE html>
                <html>
                <head>
                    <title>File Analysis Report</title>
                    <style>
                        body { font-family: Arial, sans-serif; margin: 20px; }
                        h1 { color: #2c3e50; }
                        h2 { color: #3498db; margin-top: 30px; }
                        table { border-collapse: collapse; width: 100%; margin: 15px 0; }
                        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                        th { background-color: #f2f2f2; }
                        tr:nth-child(even) { background-color: #f9f9f9; }
                        .footer { margin-top: 30px; font-size: 12px; color: #7f8c8d; text-align: center; }
                    </style>
                </head>
                <body>
                    <h1>File Analysis Report</h1>
                    <p>Generated on: """ + self.get_current_time() + """</p>
                    
                    <h2>File Information</h2>
                    <table>
                        <tr><th>Property</th><th>Value</th></tr>
                        <tr><td>File Name</td><td>""" + self.current_results.get("file_name", "") + """</td></tr>
                        <tr><td>File Size</td><td>""" + self.format_file_size(self.current_results.get("file_size", 0)) + """</td></tr>
                        <tr><td>Identified Type</td><td>""" + self.current_results.get("file_type", "") + """</td></tr>
                        <tr><td>Primary Extension</td><td>""" + self.current_results.get("primary_ext", "") + """</td></tr>
                        <tr><td>All Possible Extensions</td><td>""" + ", ".join(self.current_results.get("all_extensions", [])) + """</td></tr>
                        <tr><td>File Path</td><td>""" + self.current_results.get("file_path", "") + """</td></tr>
                    </table>
                    
                    <h2>Signature Matches</h2>
                    <table>
                        <tr><th>File Type</th><th>Extensions</th><th>Hex Signature</th><th>Priority</th></tr>
                """)
                
                # Add matches
                for match in self.current_results.get("matches", []):
                    f.write(f"""
                        <tr>
                            <td>{match.get("description", "")}</td>
                            <td>{", ".join(match.get("all_extensions", []))}</td>
                            <td>{match.get("hex_signature", "")}</td>
                            <td>{match.get("priority", 0)}</td>
                        </tr>
                    """)
                
                # Add metadata section if available
                if "metadata" in self.current_results:
                    f.write("""
                    </table>
                    
                    <h2>File Metadata</h2>
                    <table>
                        <tr><th>Property</th><th>Value</th></tr>
                    """)
                    
                    for key, value in self.current_results["metadata"].items():
                        if not isinstance(value, dict):
                            f.write(f"""
                                <tr>
                                    <td>{str(key)}</td>
                                    <td>{str(value)}</td>
                                </tr>
                            """)
                
                # Close tags
                f.write("""
                    </table>
                    
                    <div class="footer">
                        <p>Generated by File Signature Analyzer v""" + APP_VERSION + """</p>
                    </div>
                </body>
                </html>
                """)
        else:
            # Generate report for batch analysis
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write("""
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Batch Analysis Report</title>
                    <style>
                        body { font-family: Arial, sans-serif; margin: 20px; }
                        h1 { color: #2c3e50; }
                        h2 { color: #3498db; margin-top: 30px; }
                        table { border-collapse: collapse; width: 100%; margin: 15px 0; }
                        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                        th { background-color: #f2f2f2; }
                        tr:nth-child(even) { background-color: #f9f9f9; }
                        .success { background-color: #dff0d8; }
                        .warning { background-color: #fcf8e3; }
                        .error { background-color: #f2dede; }
                        .footer { margin-top: 30px; font-size: 12px; color: #7f8c8d; text-align: center; }
                    </style>
                </head>
                <body>
                    <h1>Batch File Analysis Report</h1>
                    <p>Generated on: """ + self.get_current_time() + """</p>
                    
                    <h2>Summary</h2>
                    <table>
                        <tr><th>Metric</th><th>Value</th></tr>
                        <tr><td>Total Files Processed</td><td>""" + str(len(self.batch_results)) + """</td></tr>
                        <tr><td>Files With Changed Extensions</td><td>""" + str(sum(1 for r in self.batch_results if r.get("extension_changed", False))) + """</td></tr>
                        <tr><td>Files With Errors</td><td>""" + str(sum(1 for r in self.batch_results if "error" in r)) + """</td></tr>
                    </table>
                    
                    <h2>File Results</h2>
                    <table>
                        <tr><th>Original File</th><th>Identified Type</th><th>New Filename</th><th>Status</th></tr>
                """)
                
                # Add batch results
                for result in self.batch_results:
                    # Determine row class
                    row_class = ""
                    if "error" in result:
                        row_class = "error"
                    elif result.get("extension_changed", False):
                        row_class = "success"
                        
                    # Determine status text
                    if "error" in result:
                        status = f"Error: {result['error']}"
                    elif result.get("extension_changed", False):
                        status = "Extension Changed"
                    else:
                        status = "No Change Needed"
                        
                    f.write(f"""
                        <tr class="{row_class}">
                            <td>{result.get("original_file", "")}</td>
                            <td>{result.get("identified_type", "")}</td>
                            <td>{result.get("new_filename", "")}</td>
                            <td>{status}</td>
                        </tr>
                    """)
                
                # Close tags
                f.write("""
                    </table>
                    
                    <div class="footer">
                        <p>Generated by File Signature Analyzer v""" + APP_VERSION + """</p>
                    </div>
                </body>
                </html>
                """)

    def get_current_time(self):
        """
        Get the current time formatted for reports.
        """
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def add_signature(self):
        """
        Add a new signature to the database.
        """
        dialog = SignatureEditorDialog(parent=self)
        if dialog.exec_() == QDialog.Accepted:
            # Get the new signature
            new_signature = dialog.get_signature()
            
            # Add to the signatures list
            self.signatures.append(new_signature)
            
            # Update the view
            self.update_signatures_table()
            
            # Save to disk
            self.save_signatures_to_disk()
            
            QMessageBox.information(self, "Success", "New signature added successfully.")

    def edit_signature(self):
        """
        Edit an existing signature.
        """
        # Get selected row
        selected_items = self.signatures_table.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "No Selection", "Please select a signature to edit.")
            return
            
        row = selected_items[0].row()
        
        # Get the signature at this row
        signature = self.signatures[row]
        
        # Open editor dialog
        dialog = SignatureEditorDialog(signature, parent=self)
        if dialog.exec_() == QDialog.Accepted:
            # Update the signature
            self.signatures[row] = dialog.get_signature()
            
            # Update the view
            self.update_signatures_table()
            
            # Save to disk
            self.save_signatures_to_disk()
            
            QMessageBox.information(self, "Success", "Signature updated successfully.")

    def delete_signature(self):
        """
        Delete a signature from the database.
        """
        # Get selected row
        selected_items = self.signatures_table.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "No Selection", "Please select a signature to delete.")
            return
            
        row = selected_items[0].row()
        
        # Confirm deletion
        reply = QMessageBox.question(
            self, "Confirm Deletion", 
            f"Are you sure you want to delete the signature for '{self.signatures[row].get('File description', '')}'?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            # Remove the signature
            del self.signatures[row]
            
            # Update the view
            self.update_signatures_table()
            
            # Save to disk
            self.save_signatures_to_disk()
            
            QMessageBox.information(self, "Success", "Signature deleted successfully.")

    def save_signatures_to_disk(self):
        """
        Save the signatures to the JSON file.
        """
        sig_file = resource_path(os.path.join("resources", "file_sigs.json"))
        try:
            with open(sig_file, 'w', encoding='utf-8') as f:
                json.dump({"filesigs": self.signatures}, f, indent=4)
            self.statusBar().showMessage("Signature database saved successfully.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save signatures: {str(e)}")

    def export_database(self):
        """
        Export the signature database to a file.
        """
        if not self.signatures:
            QMessageBox.warning(self, "Error", "No signatures to export.")
            return
            
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Export Signature Database", "", "JSON Files (*.json);;All Files (*)"
        )
        
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump({"filesigs": self.signatures}, f, indent=4)
                QMessageBox.information(self, "Success", "Signature database exported successfully.")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to export database: {str(e)}")

    def show_preferences(self):
        """
        Show the preferences dialog.
        """
        QMessageBox.information(
            self, "Feature Coming Soon", 
            "Preferences dialog will be added in a future version."
        )

    def show_visualization(self, viz_type):
        """
        Show a specific visualization.
        """
        # Switch to batch tab
        self.tabs.setCurrentIndex(1)
        
        # Set visualization type
        if viz_type == "type":
            self.chart_type_combo.setCurrentIndex(0)
        else:
            self.chart_type_combo.setCurrentIndex(1)
            
        # Update chart
        self.update_chart()

    def show_help(self):
        """
        Show the help documentation.
        """
        help_file = resource_path(os.path.join("resources", "help.html"))

        if os.path.exists(help_file):
            QDesktopServices.openUrl(QUrl.fromLocalFile(help_file))
        else:
            QMessageBox.information(
                self, "Help", 
                "File Signature Analyzer Help\n\n"
                "This application helps you identify file types based on their binary signatures "
                "regardless of file extension. It can analyze individual files or process entire "
                "directories of files.\n\n"
                "Key features:\n"
                "- Identify file types based on binary signatures\n"
                "- View detailed file information and metadata\n"
                "- Batch process directories of files\n"
                "- Rename files with correct extensions\n"
                "- Manage file type signatures\n\n"
                "For more information, visit our website or contact support."
            )

    def check_for_updates(self):
        """
        Check for application updates.
        """
        QMessageBox.information(
            self, "Updates", 
            f"You are running File Signature Analyzer v{APP_VERSION}.\n"
            "This is the latest version available."
        )

    def show_about(self):
        """
        Show the About dialog.
        """
        about_dialog = AboutDialog(parent=self)
        about_dialog.exec_()

    def show_contact(self):
        """
        Show the Contact dialog.
        """
        contact_dialog = ContactDialog(parent=self)
        contact_dialog.exec_()

    def new_analysis(self):
        """
        Start a new analysis.
        """
        # Switch to single file tab
        self.tabs.setCurrentIndex(0)
        
        # Clear current results
        self.clear_single_file_results()
        self.file_path_edit.clear()
        self.analyzed_file_path = None

    def new_batch(self):
        """
        Start a new batch process.
        """
        # Switch to batch tab
        self.tabs.setCurrentIndex(1)
        
        # Clear current batch results
        self.batch_results_table.setRowCount(0)
        self.input_dir_edit.clear()
        self.output_dir_edit.clear()
        self.batch_results = None
        
        # Reset progress
        self.progress_bar.setValue(0)
        self.progress_bar.setVisible(False)
        
        # Reset visualization
        self.viz_placeholder.setText("Visualization will appear here after processing files")

    def add_recent_file(self, file_path):
        """
        Add a file to the recent files list.
        """
        # Load recent files
        recent_files = self.load_recent_files()
        
        # Add new file to the beginning
        if file_path in recent_files:
            recent_files.remove(file_path)
        recent_files.insert(0, file_path)
        
        # Keep only the 10 most recent
        recent_files = recent_files[:10]
        
        # Save recent files
        self.save_recent_files(recent_files)
        
        # Update menu
        self.update_recent_files_menu()

    def load_recent_files(self):
        """
        Load the list of recent files.
        """
        try:
            recent_file = resource_path(os.path.join("resources", "recent_files.json"))
            if os.path.exists(recent_file):
                with open(recent_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            else:
                return []
        except Exception:
            return []

    def save_recent_files(self, recent_files):
        """
        Save the list of recent files.
        """
        try:
            # Ensure resources directory exists
            os.makedirs(resource_path("resources"), exist_ok=True)
            
            recent_file = resource_path(os.path.join("resources", "recent_files.json"))
            with open(recent_file, 'w', encoding='utf-8') as f:
                json.dump(recent_files, f)
        except Exception:
            pass  # Silently fail if we can't save recent files

    def update_recent_files_menu(self):
        """
        Update the recent files menu.
        """
        self.recent_menu.clear()
        
        recent_files = self.load_recent_files()
        
        if recent_files:
            for file_path in recent_files:
                # Use only the basename for display
                display_name = os.path.basename(file_path)
                action = QAction(display_name, self)
                action.setData(file_path)
                action.triggered.connect(self.open_recent_file)
                self.recent_menu.addAction(action)
                
            self.recent_menu.addSeparator()
            clear_action = QAction("Clear Recent Files", self)
            clear_action.triggered.connect(self.clear_recent_files)
            self.recent_menu.addAction(clear_action)
        else:
            no_files_action = QAction("No Recent Files", self)
            no_files_action.setEnabled(False)
            self.recent_menu.addAction(no_files_action)

    def open_recent_file(self):
        """
        Open a file from the recent files menu.
        """
        action = self.sender()
        if action:
            file_path = action.data()
            if os.path.exists(file_path):
                self.tabs.setCurrentIndex(0)
                self.file_path_edit.setText(file_path)
                self.analyzed_file_path = file_path
                self.analyze_current_file()
            else:
                QMessageBox.warning(
                    self, "File Not Found", 
                    f"The file '{file_path}' no longer exists."
                )
                
                # Remove from recent files
                recent_files = self.load_recent_files()
                if file_path in recent_files:
                    recent_files.remove(file_path)
                    self.save_recent_files(recent_files)
                    self.update_recent_files_menu()

    def clear_recent_files(self):
        """
        Clear the list of recent files.
        """
        self.save_recent_files([])
        self.update_recent_files_menu()

    def cancel_batch(self):
        """Cancel running batch processing."""
        if hasattr(self, 'worker') and self.worker.isRunning():
            self.worker.stop()
            self.cancel_button.setVisible(False)
            self.statusBar().showMessage("Batch processing cancelled")

    def update_current_file(self, filename):
        """Update the current file label during batch processing."""
        if hasattr(self, 'current_file_label'):
            self.current_file_label.setText(f"Processing: {filename}")

    def setup_ml_tab(self):
        """Set up the ML Insights tab."""
        layout = QVBoxLayout()

        # Model status
        status_group = QGroupBox("ML Model Status")
        status_layout = QVBoxLayout()
        status_group.setLayout(status_layout)

        self.ml_status_label = QLabel("Model: Not loaded")
        self.ml_status_label.setStyleSheet("font-weight: bold;")
        status_layout.addWidget(self.ml_status_label)

        if self.ml_classifier and self.ml_classifier.is_model_loaded():
            info = self.ml_classifier.get_model_info()
            active_name = ""
            if self.model_registry:
                active_info = self.model_registry.get_active_model_info()
                if active_info:
                    active_name = f" [{active_info.get('name', '')}]"
            self.ml_status_label.setText(
                f"Model: Loaded ({info.get('num_classes', info.get('n_classes', '?'))} classes){active_name}")

        layout.addWidget(status_group)

        # Confidence gauge
        gauge_group = QGroupBox("Analysis Confidence")
        gauge_layout = QVBoxLayout()
        gauge_group.setLayout(gauge_layout)

        self.ml_confidence_bar = QProgressBar()
        self.ml_confidence_bar.setRange(0, 100)
        self.ml_confidence_bar.setValue(0)
        self.ml_confidence_bar.setTextVisible(True)
        self.ml_confidence_bar.setFormat("%v%")
        self.ml_confidence_bar.setMinimumHeight(30)
        gauge_layout.addWidget(self.ml_confidence_bar)

        self.ml_entropy_label = QLabel("Entropy: --")
        self.ml_entropy_label.setStyleSheet("font-size: 14px; font-weight: bold;")
        gauge_layout.addWidget(self.ml_entropy_label)

        layout.addWidget(gauge_group)

        # ML Predictions table
        pred_group = QGroupBox("ML Predictions")
        pred_layout = QVBoxLayout()
        pred_group.setLayout(pred_layout)

        self.ml_predictions_table = QTableWidget(0, 3)
        self.ml_predictions_table.setHorizontalHeaderLabels(["File Type", "Confidence %", "Extension"])
        self.ml_predictions_table.horizontalHeader().setStretchLastSection(True)
        pred_layout.addWidget(self.ml_predictions_table)

        layout.addWidget(pred_group)

        # Action buttons - row 1
        btn_layout1 = QHBoxLayout()

        train_btn = QPushButton("Train Model")
        train_btn.setStyleSheet("background-color: #2196F3; color: white; font-weight: bold;")
        train_btn.clicked.connect(self.train_ml_model)
        btn_layout1.addWidget(train_btn)

        correct_btn = QPushButton("Record Correction")
        correct_btn.setToolTip("Record a correction if the ML prediction was wrong")
        correct_btn.clicked.connect(self.record_ml_correction)
        btn_layout1.addWidget(correct_btn)

        layout.addLayout(btn_layout1)

        # Action buttons - row 2
        btn_layout2 = QHBoxLayout()

        load_btn = QPushButton("Load Model")
        load_btn.setStyleSheet("background-color: #FF9800; color: white; font-weight: bold;")
        load_btn.setToolTip("Import a trained model (.pkl file)")
        load_btn.clicked.connect(self.load_ml_model)
        btn_layout2.addWidget(load_btn)

        export_btn = QPushButton("Export Model")
        export_btn.setStyleSheet("background-color: #4CAF50; color: white; font-weight: bold;")
        export_btn.setToolTip("Export the current model to a .pkl file")
        export_btn.clicked.connect(self.export_ml_model)
        btn_layout2.addWidget(export_btn)

        layout.addLayout(btn_layout2)

        # Action buttons - row 3 (GitHub)
        btn_layout3 = QHBoxLayout()

        update_btn = QPushButton("Check for Updates")
        update_btn.setStyleSheet("background-color: #9C27B0; color: white; font-weight: bold;")
        update_btn.setToolTip("Check GitHub for a newer model version")
        update_btn.clicked.connect(self.check_model_updates)
        btn_layout3.addWidget(update_btn)

        upload_btn = QPushButton("Upload to GitHub")
        upload_btn.setStyleSheet("background-color: #673AB7; color: white; font-weight: bold;")
        upload_btn.setToolTip("Upload the current model to GitHub Releases")
        upload_btn.clicked.connect(self.upload_model_to_github)
        btn_layout3.addWidget(upload_btn)

        layout.addLayout(btn_layout3)
        layout.addStretch()

        self.ml_tab.setLayout(layout)

    def setup_compare_tab(self):
        """Set up the File Comparison tab."""
        layout = QVBoxLayout()

        # File selection
        files_group = QGroupBox("Select Files to Compare")
        files_layout = QVBoxLayout()
        files_group.setLayout(files_layout)

        # File 1
        file1_layout = QHBoxLayout()
        file1_layout.addWidget(QLabel("File 1:"))
        self.compare_file1_edit = QLineEdit()
        self.compare_file1_edit.setReadOnly(True)
        file1_btn = QPushButton("Browse...")
        file1_btn.clicked.connect(lambda: self._browse_compare_file(1))
        file1_layout.addWidget(self.compare_file1_edit)
        file1_layout.addWidget(file1_btn)
        files_layout.addLayout(file1_layout)

        # File 2
        file2_layout = QHBoxLayout()
        file2_layout.addWidget(QLabel("File 2:"))
        self.compare_file2_edit = QLineEdit()
        self.compare_file2_edit.setReadOnly(True)
        file2_btn = QPushButton("Browse...")
        file2_btn.clicked.connect(lambda: self._browse_compare_file(2))
        file2_layout.addWidget(self.compare_file2_edit)
        file2_layout.addWidget(file2_btn)
        files_layout.addLayout(file2_layout)

        compare_btn = QPushButton("Compare Files")
        compare_btn.setStyleSheet("background-color: #4CAF50; color: white; font-weight: bold;")
        compare_btn.clicked.connect(self.run_comparison)
        files_layout.addWidget(compare_btn)

        layout.addWidget(files_group)

        # Comparison results
        results_group = QGroupBox("Comparison Results")
        results_layout = QVBoxLayout()
        results_group.setLayout(results_layout)

        self.compare_info_label = QLabel("Select two files and click Compare")
        results_layout.addWidget(self.compare_info_label)

        # Side-by-side hex display
        hex_splitter = QSplitter(Qt.Horizontal)
        self.compare_hex1 = QTextEdit()
        self.compare_hex1.setReadOnly(True)
        self.compare_hex1.setFont(QFont("Courier New", 9))
        self.compare_hex2 = QTextEdit()
        self.compare_hex2.setReadOnly(True)
        self.compare_hex2.setFont(QFont("Courier New", 9))
        hex_splitter.addWidget(self.compare_hex1)
        hex_splitter.addWidget(self.compare_hex2)
        results_layout.addWidget(hex_splitter)

        # Hash comparison
        self.compare_hash_label = QLabel("")
        self.compare_hash_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        results_layout.addWidget(self.compare_hash_label)

        layout.addWidget(results_group)

        self.compare_tab.setLayout(layout)

    def _browse_compare_file(self, file_num):
        """Browse for a file to compare."""
        file_path, _ = QFileDialog.getOpenFileName(self, f"Select File {file_num}")
        if file_path:
            if file_num == 1:
                self.compare_file1_edit.setText(file_path)
            else:
                self.compare_file2_edit.setText(file_path)

    def run_comparison(self):
        """Compare two files side by side."""
        file1 = self.compare_file1_edit.text()
        file2 = self.compare_file2_edit.text()

        if not file1 or not file2:
            QMessageBox.warning(self, "Error", "Please select both files to compare.")
            return

        if not os.path.exists(file1) or not os.path.exists(file2):
            QMessageBox.warning(self, "Error", "One or both files do not exist.")
            return

        try:
            # Read file headers (first 512 bytes)
            with open(file1, 'rb') as f:
                data1 = f.read(512)
            with open(file2, 'rb') as f:
                data2 = f.read(512)

            # Format hex dumps
            self.compare_hex1.setPlainText(self._format_hex_dump(data1, os.path.basename(file1)))
            self.compare_hex2.setPlainText(self._format_hex_dump(data2, os.path.basename(file2)))

            # Get file types
            type1, ext1, _, _ = identify_file_type(file1, self.signatures)
            type2, ext2, _, _ = identify_file_type(file2, self.signatures)

            # Calculate hashes
            hash1_md5 = hashlib.md5(open(file1, 'rb').read()).hexdigest()
            hash2_md5 = hashlib.md5(open(file2, 'rb').read()).hexdigest()
            hash1_sha = hashlib.sha256(open(file1, 'rb').read()).hexdigest()
            hash2_sha = hashlib.sha256(open(file2, 'rb').read()).hexdigest()

            files_match = hash1_sha == hash2_sha
            match_text = "IDENTICAL" if files_match else "DIFFERENT"
            match_color = "#4CAF50" if files_match else "#f44336"

            info = (
                f"<b>File 1:</b> {type1} (.{ext1}) | Size: {self.format_file_size(os.path.getsize(file1))}<br>"
                f"<b>File 2:</b> {type2} (.{ext2}) | Size: {self.format_file_size(os.path.getsize(file2))}<br>"
                f"<b>Result: <span style='color:{match_color}'>{match_text}</span></b>"
            )
            self.compare_info_label.setText(info)

            hash_info = (
                f"File 1 MD5: {hash1_md5}\nFile 1 SHA256: {hash1_sha}\n"
                f"File 2 MD5: {hash2_md5}\nFile 2 SHA256: {hash2_sha}"
            )
            self.compare_hash_label.setText(hash_info)

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Comparison failed: {str(e)}")

    def _format_hex_dump(self, data, title=""):
        """Format binary data as a hex dump string."""
        lines = [f"=== {title} ({len(data)} bytes) ===\n"]
        for i in range(0, len(data), 16):
            chunk = data[i:i+16]
            hex_part = " ".join(f"{b:02X}" for b in chunk)
            ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            lines.append(f"{i:08X}  {hex_part:<48s}  |{ascii_part}|")
        return "\n".join(lines)

    def update_ml_tab(self, file_path, file_type, entropy, confidence, ml_predictions):
        """Update the ML Insights tab with analysis results."""
        self.ml_confidence_bar.setValue(min(confidence, 100))

        color = "#4CAF50" if entropy < 4 else "#FF9800" if entropy < 7 else "#f44336"
        self.ml_entropy_label.setText(f"Entropy: {entropy:.3f}")
        self.ml_entropy_label.setStyleSheet(f"font-size: 14px; font-weight: bold; color: {color};")

        # Update predictions table
        self.ml_predictions_table.setRowCount(0)
        if ml_predictions:
            for file_type_pred, conf, ext in ml_predictions[:10]:
                row = self.ml_predictions_table.rowCount()
                self.ml_predictions_table.insertRow(row)
                self.ml_predictions_table.setItem(row, 0, QTableWidgetItem(file_type_pred))
                self.ml_predictions_table.setItem(row, 1, QTableWidgetItem(f"{conf:.1f}"))
                self.ml_predictions_table.setItem(row, 2, QTableWidgetItem(ext))

    def train_ml_model(self):
        """Train the ML model from a directory of labeled files."""
        train_dir = QFileDialog.getExistingDirectory(
            self, "Select Training Data Directory\n\n"
            "Organize as subfolders named by file type:\n"
            "  training_dir/JPEG Image/file1.jpg\n"
            "  training_dir/PNG Image/file1.png",
        )
        if not train_dir:
            return

        if not self.ml_classifier:
            self.ml_classifier = MLFileClassifier()

        # Count files to validate before training
        file_count = 0
        type_count = 0
        for label_dir in os.listdir(train_dir):
            label_path = os.path.join(train_dir, label_dir)
            if os.path.isdir(label_path):
                type_count += 1
                for fname in os.listdir(label_path):
                    if os.path.isfile(os.path.join(label_path, fname)):
                        file_count += 1

        if file_count < 10 or type_count < 2:
            QMessageBox.warning(self, "Insufficient Data",
                f"Found {file_count} files in {type_count} type folders.\n"
                "Need at least 10 files across 2+ types.\n\n"
                "Organize training data as:\n"
                "training_dir/\n  JPEG Image/\n    file1.jpg\n  PNG Image/\n    file2.png")
            return

        QApplication.setOverrideCursor(Qt.WaitCursor)
        try:
            result = self.ml_classifier.train(train_dir)
            QApplication.restoreOverrideCursor()

            if result.get("success"):
                # Register trained model in registry
                if self.model_registry:
                    self.model_registry.register_model(result["model_path"], source_type="trained")

                self.ml_status_label.setText(
                    f"Model: Trained ({result['num_classes']} classes, "
                    f"accuracy: {result.get('cv_accuracy', '?')}%)")
                QMessageBox.information(self, "Training Complete",
                    f"Model trained and registered!\n\n"
                    f"Samples: {result['num_samples']}\n"
                    f"Classes: {result['num_classes']}\n"
                    f"Cross-validation accuracy: {result.get('cv_accuracy', 'N/A')}%\n"
                    f"Skipped files: {result.get('skipped_files', 0)}\n"
                    f"Model saved to: {result['model_path']}")
            else:
                QMessageBox.critical(self, "Training Failed", result.get("error", "Unknown error"))
        except Exception as e:
            QApplication.restoreOverrideCursor()
            QMessageBox.critical(self, "Training Error", f"Failed to train model:\n{str(e)}")

    def load_ml_model(self):
        """Load a pre-trained ML model from a .pkl file."""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select ML Model File",
            "", "Model Files (*.pkl);;All Files (*)"
        )
        if not file_path:
            return

        # Validate model before loading
        QApplication.setOverrideCursor(Qt.WaitCursor)
        validation = MLFileClassifier.validate_model(file_path)
        QApplication.restoreOverrideCursor()

        if not validation["valid"]:
            QMessageBox.critical(self, "Invalid Model",
                f"This model file is not compatible:\n\n{validation['error']}\n\n"
                "The model must have:\n"
                "- 'model' and 'label_encoder' keys\n"
                "- Support for 340-feature input vectors")
            return

        if not self.ml_classifier:
            self.ml_classifier = MLFileClassifier.__new__(MLFileClassifier)
            self.ml_classifier.model = None
            self.ml_classifier.label_encoder = None
            self.ml_classifier.feature_names = []
            self.ml_classifier.model_path = MLFileClassifier.MODEL_PATH

        QApplication.setOverrideCursor(Qt.WaitCursor)
        result = self.ml_classifier.load_model(file_path)
        QApplication.restoreOverrideCursor()

        if result.get("success"):
            # Register in model registry
            if self.model_registry:
                self.model_registry.register_model(file_path, source_type="loaded")

            info = validation["info"]
            self.ml_status_label.setText(
                f"Model: Loaded ({result['num_classes']} classes)")
            details = (
                f"Model loaded and registered!\n\n"
                f"File: {os.path.basename(file_path)}\n"
                f"Classes: {result['num_classes']}\n"
            )
            if result.get('cv_accuracy'):
                details += f"Training accuracy: {result['cv_accuracy']}%\n"
            if result.get('num_samples'):
                details += f"Trained on: {result['num_samples']} samples\n"
            details += f"\nSupported types:\n"
            for cls in sorted(result.get('classes', []))[:15]:
                details += f"  - {cls}\n"
            if len(result.get('classes', [])) > 15:
                details += f"  ... and {len(result['classes']) - 15} more"
            QMessageBox.information(self, "Model Loaded", details)
        else:
            QMessageBox.critical(self, "Load Failed",
                f"Could not load model:\n{result.get('error', 'Unknown error')}")

    def export_ml_model(self):
        """Export the current ML model to a .pkl file."""
        if not self.ml_classifier or not self.ml_classifier.is_model_loaded():
            QMessageBox.warning(self, "No Model",
                "No ML model is currently loaded.\n"
                "Train or load a model first.")
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self, "Export ML Model",
            "ml_model.pkl", "Model Files (*.pkl);;All Files (*)"
        )
        if not file_path:
            return

        QApplication.setOverrideCursor(Qt.WaitCursor)
        result = self.ml_classifier.export_model(file_path)
        QApplication.restoreOverrideCursor()

        if result.get("success"):
            QMessageBox.information(self, "Model Exported",
                f"Model exported to:\n{result['model_path']}")
        else:
            QMessageBox.critical(self, "Export Failed",
                f"Could not export model:\n{result.get('error', 'Unknown error')}")

    def record_ml_correction(self):
        """Record a correction for ML learning."""
        if not self.current_results:
            QMessageBox.warning(self, "Error", "Please analyze a file first.")
            return

        if not self.ml_classifier:
            QMessageBox.warning(self, "Error", "ML classifier not available.")
            return

        correct_type, ok = QInputDialog.getText(
            self, "Record Correction",
            f"Current prediction: {self.current_results.get('file_type', 'Unknown')}\n"
            "Enter the correct file type:",
        )

        if ok and correct_type:
            self.ml_classifier.record_correction(
                self.current_results["file_path"], correct_type)
            QMessageBox.information(self, "Correction Recorded",
                f"Recorded correction: {correct_type}")

    def _start_update_check(self):
        """Start a background thread to check for model updates."""
        if not self.model_registry:
            return

        from PyQt5.QtCore import QThread, pyqtSignal

        class UpdateCheckThread(QThread):
            result_ready = pyqtSignal(dict)

            def __init__(self, registry):
                super().__init__()
                self.registry = registry

            def run(self):
                result = self.registry.check_for_update()
                self.result_ready.emit(result)

        self._update_thread = UpdateCheckThread(self.model_registry)
        self._update_thread.result_ready.connect(self._on_update_check_complete)
        self._update_thread.start()

    def _on_update_check_complete(self, result):
        """Handle background update check result."""
        if result.get("available"):
            tag = result.get("tag", "")
            self.statusBar().showMessage(
                f"New ML model available ({tag}) - use Tools > ML Model > Check for Updates", 10000)

    def check_model_updates(self):
        """Check GitHub Releases for a newer model and offer to download."""
        if not self.model_registry:
            QMessageBox.warning(self, "Error", "Model registry not available.")
            return

        QApplication.setOverrideCursor(Qt.WaitCursor)
        result = self.model_registry.check_for_update()
        QApplication.restoreOverrideCursor()

        if result.get("available"):
            tag = result["tag"]
            name = result.get("asset_name", "ml_model.pkl")
            size_mb = result.get("size", 0) / (1024 * 1024)
            release_name = result.get("release_name", tag)

            reply = QMessageBox.question(self, "Model Update Available",
                f"A newer model is available on GitHub!\n\n"
                f"Release: {release_name}\n"
                f"Tag: {tag}\n"
                f"File: {name}\n"
                f"Size: {size_mb:.1f} MB\n\n"
                f"Download and install?",
                QMessageBox.Yes | QMessageBox.No)

            if reply == QMessageBox.Yes:
                QApplication.setOverrideCursor(Qt.WaitCursor)
                dl_result = self.model_registry.download_release_model(
                    result["download_url"], result["asset_name"], result["tag"])
                QApplication.restoreOverrideCursor()

                if dl_result.get("success"):
                    # Reload the model
                    active_path = self.model_registry.get_active_model_path()
                    if active_path and self.ml_classifier:
                        self.ml_classifier.load_model(active_path)
                    elif active_path:
                        self.ml_classifier = MLFileClassifier(model_path=active_path)

                    self.ml_status_label.setText(
                        f"Model: Updated ({tag})")
                    QMessageBox.information(self, "Update Complete",
                        f"Model updated to {tag}!\n"
                        f"The new model is now active.")
                else:
                    QMessageBox.critical(self, "Download Failed",
                        f"Could not download model:\n{dl_result.get('error', 'Unknown error')}")
        else:
            reason = result.get("reason", "No updates available")
            QMessageBox.information(self, "No Updates", reason)

    def upload_model_to_github(self):
        """Upload the current model to GitHub as a release."""
        if not self.model_registry:
            QMessageBox.warning(self, "Error", "Model registry not available.")
            return

        if not self.ml_classifier or not self.ml_classifier.is_model_loaded():
            QMessageBox.warning(self, "No Model",
                "No ML model is currently loaded.\nTrain or load a model first.")
            return

        reply = QMessageBox.question(self, "Upload to GitHub",
            "Upload the current ML model to GitHub Releases?\n\n"
            "This will create a new release on the\n"
            "file-signature-analyzer repository,\n"
            "making the model available to all users.",
            QMessageBox.Yes | QMessageBox.No)

        if reply != QMessageBox.Yes:
            return

        QApplication.setOverrideCursor(Qt.WaitCursor)
        result = self.model_registry.upload_model_to_release()
        QApplication.restoreOverrideCursor()

        if result.get("success"):
            QMessageBox.information(self, "Upload Complete",
                f"Model uploaded to GitHub!\n\n"
                f"Release tag: {result.get('tag', '?')}\n"
                f"URL: {result.get('release_url', '')}")
        else:
            QMessageBox.critical(self, "Upload Failed",
                f"Could not upload model:\n{result.get('error', 'Unknown error')}")

    def format_file_size(self, size_in_bytes):
        """Format file size in human-readable format."""
        if size_in_bytes < 1024:
            return f"{size_in_bytes} bytes"
        elif size_in_bytes < 1024 * 1024:
            return f"{size_in_bytes / 1024:.2f} KB"
        elif size_in_bytes < 1024 * 1024 * 1024:
            return f"{size_in_bytes / (1024 * 1024):.2f} MB"
        else:
            return f"{size_in_bytes / (1024 * 1024 * 1024):.2f} GB"

# Entry point
if __name__ == "__main__":
    # Enable high DPI scaling - DO THIS BEFORE CREATING QApplication
    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)
    
    app = QApplication(sys.argv)
    
    # Set application style
    app.setStyle("Fusion")
    
    # Create main window
    window = FileAnalyzerApp()
    window.show()
    
    sys.exit(app.exec_())
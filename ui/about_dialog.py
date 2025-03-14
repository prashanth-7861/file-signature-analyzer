from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, 
    QTabWidget, QTextEdit, QWidget
)
from PyQt5.QtCore import Qt, QUrl
from PyQt5.QtGui import QPixmap, QFont, QDesktopServices

class AboutDialog(QDialog):
    """
    Dialog showing information about the application.
    """
    def __init__(self, parent=None):
        super().__init__(parent)
        self.app_version = parent.APP_VERSION if hasattr(parent, 'APP_VERSION') else "1.0.0"
        self.initUI()
        
    def initUI(self):
        self.setWindowTitle("About File Signature Analyzer")
        self.setFixedSize(550, 450)
        
        layout = QVBoxLayout()
        self.setLayout(layout)
        
        # Tabs
        tabs = QTabWidget()
        layout.addWidget(tabs)
        
        # About tab
        about_widget = QWidget()
        about_layout = QVBoxLayout()
        about_widget.setLayout(about_layout)
        
        # App name and version
        title_label = QLabel("File Signature Analyzer")
        title_label.setAlignment(Qt.AlignCenter)
        title_label.setFont(QFont("Arial", 18, QFont.Bold))
        
        version_label = QLabel(f"Version {self.app_version}")
        version_label.setAlignment(Qt.AlignCenter)
        version_label.setFont(QFont("Arial", 10))
        
        # Logo (placeholder)
        logo_label = QLabel()
        logo_label.setAlignment(Qt.AlignCenter)
        try:
            pixmap = QPixmap("resources/icons/app_icon.png")
            logo_label.setPixmap(pixmap.scaled(128, 128, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        except:
            logo_label.setText("[Logo Placeholder]")
            logo_label.setFont(QFont("Arial", 12))
            logo_label.setStyleSheet("background-color: #e0e0e0; padding: 40px;")
        
        # Description
        description = QLabel(
            "File Signature Analyzer is a tool for identifying file types "
            "based on their binary signatures, regardless of file extension. "
            "It can analyze individual files or process entire directories of files."
        )
        description.setAlignment(Qt.AlignCenter)
        description.setWordWrap(True)
        
        # Copyright
        copyright_label = QLabel("© 2023 All Rights Reserved")
        copyright_label.setAlignment(Qt.AlignCenter)
        
        # Add widgets to layout
        about_layout.addWidget(title_label)
        about_layout.addWidget(version_label)
        about_layout.addSpacing(20)
        about_layout.addWidget(logo_label)
        about_layout.addSpacing(20)
        about_layout.addWidget(description)
        about_layout.addStretch()
        about_layout.addWidget(copyright_label)
        
        # License tab
        license_widget = QWidget()
        license_layout = QVBoxLayout()
        license_widget.setLayout(license_layout)
        
        license_text = QTextEdit()
        license_text.setReadOnly(True)
        license_text.setHtml("""
        <h3>MIT License</h3>
        <p>Copyright (c) 2023</p>
        <p>
        Permission is hereby granted, free of charge, to any person obtaining a copy
        of this software and associated documentation files (the "Software"), to deal
        in the Software without restriction, including without limitation the rights
        to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
        copies of the Software, and to permit persons to whom the Software is
        furnished to do so, subject to the following conditions:
        </p>
        <p>
        The above copyright notice and this permission notice shall be included in all
        copies or substantial portions of the Software.
        </p>
        <p>
        THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
        IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
        FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
        AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
        LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
        OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
        SOFTWARE.
        </p>
        """)
        license_layout.addWidget(license_text)
        
        # Credits tab
        credits_widget = QWidget()
        credits_layout = QVBoxLayout()
        credits_widget.setLayout(credits_layout)
        
        credits_text = QTextEdit()
        credits_text.setReadOnly(True)
        credits_text.setHtml("""
        <h3>Credits and Acknowledgments</h3>
        <p>File Signature Analyzer uses the following open source projects:</p>
        <ul>
            <li><b>Python</b> - Programming language</li>
            <li><b>PyQt5</b> - GUI framework</li>
            <li><b>Pillow</b> - Image processing library</li>
            <li><b>Matplotlib</b> - Plotting library</li>
        </ul>
        <p>Special thanks to:</p>
        <ul>
            <li>Gary Kessler for his <a href="https://www.garykessler.net/library/file_sigs.html">File Signature Database</a></li>
            <li>The open source community for their invaluable resources</li>
        </ul>
        """)
        credits_layout.addWidget(credits_text)
        
        # Add tabs
        tabs.addTab(about_widget, "About")
        tabs.addTab(license_widget, "License")
        tabs.addTab(credits_widget, "Credits")
        
        # Buttons
        button_layout = QHBoxLayout()
        website_button = QPushButton("Visit Website")
        website_button.clicked.connect(self.open_website)
        close_button = QPushButton("Close")
        close_button.clicked.connect(self.close)
        
        button_layout.addWidget(website_button)
        button_layout.addStretch()
        button_layout.addWidget(close_button)
        
        layout.addLayout(button_layout)
        
    def open_website(self):
        """
        Open the website in the default browser.
        """
        # This would be your actual website
        QDesktopServices.openUrl(QUrl("https://example.com"))
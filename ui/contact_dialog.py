from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, 
    QLineEdit, QTextEdit, QFormLayout, QMessageBox, QComboBox
)
from PyQt5.QtCore import Qt, QUrl
from PyQt5.QtGui import QPixmap, QFont, QDesktopServices

class ContactDialog(QDialog):
    """
    Dialog for contacting the developer.
    """
    def __init__(self, parent=None):
        super().__init__(parent)
        self.initUI()
        
    def initUI(self):
        self.setWindowTitle("Contact Developer")
        self.setFixedSize(500, 400)
        
        layout = QVBoxLayout()
        self.setLayout(layout)
        
        # Title
        title_label = QLabel("Contact the Developer")
        title_label.setAlignment(Qt.AlignCenter)
        title_label.setFont(QFont("Arial", 16, QFont.Bold))
        
        # Description
        description = QLabel(
            "Have questions, suggestions, or found a bug? "
            "Use this form to get in touch with the developer."
        )
        description.setAlignment(Qt.AlignCenter)
        description.setWordWrap(True)
        
        # Contact form
        form_layout = QFormLayout()
        
        self.name_edit = QLineEdit()
        self.email_edit = QLineEdit()
        self.subject_combo = QComboBox()
        self.subject_combo.addItems([
            "General Question", 
            "Feature Request", 
            "Bug Report", 
            "Feedback", 
            "Other"
        ])
        self.message_edit = QTextEdit()
        
        form_layout.addRow("Your Name:", self.name_edit)
        form_layout.addRow("Email Address:", self.email_edit)
        form_layout.addRow("Subject:", self.subject_combo)
        form_layout.addRow("Message:", self.message_edit)
        
        # Buttons
        button_layout = QHBoxLayout()
        send_button = QPushButton("Send Message")
        send_button.clicked.connect(self.send_message)
        cancel_button = QPushButton("Cancel")
        cancel_button.clicked.connect(self.close)
        
        button_layout.addStretch()
        button_layout.addWidget(send_button)
        button_layout.addWidget(cancel_button)
        
        # Alternative contact methods
        alt_contact_label = QLabel(
            "Alternative contact methods:"
        )
        
        email_label = QLabel("Email: 63970770+prashanth-7861@users.noreply.github.com")
        email_label.setTextInteractionFlags(Qt.TextSelectableByMouse | Qt.LinksAccessibleByMouse)
        
        # Social links
        social_layout = QHBoxLayout()
        
        github_button = QPushButton("GitHub")
        github_button.clicked.connect(lambda: QDesktopServices.openUrl(QUrl("https://github.com/prashanth-7861")))
        
        twitter_button = QPushButton("Twitter")
        twitter_button.clicked.connect(lambda: QDesktopServices.openUrl(QUrl("https://twitter.com")))
        
        social_layout.addWidget(github_button)
        social_layout.addWidget(twitter_button)
        social_layout.addStretch()
        
        # Add all widgets to main layout
        layout.addWidget(title_label)
        layout.addWidget(description)
        layout.addSpacing(10)
        layout.addLayout(form_layout)
        layout.addLayout(button_layout)
        layout.addSpacing(15)
        layout.addWidget(alt_contact_label)
        layout.addWidget(email_label)
        layout.addLayout(social_layout)
        
    def send_message(self):
        """
        Send the contact message (this is a demo, so it just displays a message).
        """
        # Validate form
        if not self.name_edit.text():
            QMessageBox.warning(self, "Missing Information", "Please enter your name.")
            return
            
        if not self.email_edit.text() or '@' not in self.email_edit.text():
            QMessageBox.warning(self, "Invalid Email", "Please enter a valid email address.")
            return
            
        if not self.message_edit.toPlainText():
            QMessageBox.warning(self, "Empty Message", "Please enter a message.")
            return
            
        # In a real app, this would send the message to a server
        QMessageBox.information(
            self, "Message Sent", 
            "Thank you for your message! We will respond as soon as possible."
        )
        
        # Close the dialog
        self.accept()
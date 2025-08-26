import base64
import hashlib
import json
import os
import sys

from cryptography.fernet import Fernet, InvalidToken
from PyQt5 import QtCore
from PyQt5.QtWidgets import (
    QApplication,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from launch import launch_nonblocking

PWD_FILE = "pwd.txt"
TOKENS_FILE = "tokens.txt"


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


def derive_key(password):
    # Use SHA256 hash, then base64 encode for Fernet
    return base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())


class LoginWidget(QWidget):
    logged_in = QtCore.pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Roblox Account Manager - Login")
        layout = QVBoxLayout()
        self.label = QLabel("Enter Password:")
        self.pwd_input = QLineEdit()
        self.pwd_input.setEchoMode(QLineEdit.Password)
        self.login_btn = QPushButton("Login")
        self.login_btn.clicked.connect(self.handle_login)
        self.pwd_input.returnPressed.connect(self.handle_login)  # So when user presses Enter, it logs in
        layout.addWidget(self.label)
        layout.addWidget(self.pwd_input)
        layout.addWidget(self.login_btn)
        self.setLayout(layout)

        if self.should_set_password():
            self.label.setText("Set a new password:")
            self.login_btn.setText("Set Password")

    def should_set_password(self):
        # if files are missing, allow pwd setup
        pwd_missing = not os.path.exists(PWD_FILE) or os.path.getsize(PWD_FILE) == 0
        tokens_missing = not os.path.exists(TOKENS_FILE) or os.path.getsize(TOKENS_FILE) == 0
        if pwd_missing and not tokens_missing:
            os.remove(TOKENS_FILE)  # clear tokens if no password (so that previous tokens are not accessible)
            tokens_missing = True  # now tokens are also missing

        return pwd_missing and tokens_missing

    def handle_login(self):
        pwd = self.pwd_input.text()
        if not pwd:
            QMessageBox.warning(self, "Error", "Password cannot be empty.")
            return

        if self.should_set_password():
            # First time setup
            with open(PWD_FILE, "w") as f:
                f.write(hash_password(pwd))
            QMessageBox.information(self, "Success", "Password set. Please login again.")
            self.label.setText("Enter Password:")
            self.login_btn.setText("Login")
            self.pwd_input.clear()
            return

        with open(PWD_FILE, "r") as f:
            stored_hash = f.read().strip()

        if hash_password(pwd) == stored_hash:
            self.logged_in.emit(pwd)
        else:
            QMessageBox.warning(self, "Error", "Incorrect password.")
            self.pwd_input.clear()


class AccountManagerWidget(QWidget):
    def __init__(self, password):
        super().__init__()
        self.password = password
        self.key = derive_key(password)
        self.fernet = Fernet(self.key)
        self.setWindowTitle("Roblox Account Manager")
        self.unsaved_changes = False

        # Layout for the account manager
        layout = QVBoxLayout()
        self.table = QTableWidget(0, 3)

        self.table.setHorizontalHeaderLabels(["Account Name", "Token", "Launch"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        layout.addWidget(self.table)
        btn_layout = QHBoxLayout()

        # Add clickable help button overlay top right of screen
        # Place help button at the top right
        help_btn = QPushButton("?")
        help_btn.setFixedSize(30, 30)
        help_btn.setToolTip("Frequently Asked Questions")
        help_btn.clicked.connect(self.show_faq)

        top_layout = QHBoxLayout()
        top_layout.addStretch()
        top_layout.addWidget(help_btn)
        layout.addLayout(top_layout)

        # Buttons at the bottom of the screen
        self.add_btn = QPushButton("Add Account")
        self.add_btn.clicked.connect(self.add_account)
        self.delete_btn = QPushButton("Delete Account")
        self.delete_btn.clicked.connect(self.delete_account)
        self.save_btn = QPushButton("Save")
        self.save_btn.clicked.connect(self.save_tokens)
        self.launch_btn = QPushButton("Launch All")
        self.launch_btn.clicked.connect(self.launch_all)
        btn_layout.addWidget(self.add_btn)
        btn_layout.addWidget(self.delete_btn)
        btn_layout.addWidget(self.save_btn)
        btn_layout.addWidget(self.launch_btn)
        layout.addLayout(btn_layout)

        self.setLayout(layout)
        self.load_tokens()

        # Track changes for unsaved changes
        self.table.itemChanged.connect(self.mark_unsaved)
        self.table.model().rowsInserted.connect(self.mark_unsaved)
        self.table.model().rowsRemoved.connect(self.mark_unsaved)

        # Faq dialog tracker
        self.faq_dialog = None

    def mark_unsaved(self, *args, **kwargs):
        self.unsaved_changes = True

    def show_faq(self):
        if self.faq_dialog is not None and self.faq_dialog.isVisible():
            self.faq_dialog.raise_()
            self.faq_dialog.activateWindow()
            return

        # Loading from faqs.json (still a test rn)
        try:
            with open("faqs.json", "r", encoding="utf-8") as f:
                faqs = json.load(f)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Could not load FAQs: {e}")
            return

        self.faq_dialog = QWidget(self, QtCore.Qt.Window)
        self.faq_dialog.setWindowTitle("FAQ")
        faq_layout = QVBoxLayout()

        for entry in faqs:
            question = entry.get("question", "Question")
            answer = entry.get("answer", "Answer")
            btn = QPushButton(question)
            btn.clicked.connect(lambda _, q=question, a=answer: QMessageBox.information(self, q, a))
            faq_layout.addWidget(btn)

        close_btn = QPushButton("Close")
        close_btn.setStyleSheet("font-weight: bold;")
        close_btn.clicked.connect(self.faq_dialog.close)
        faq_layout.addWidget(close_btn)

        self.faq_dialog.setLayout(faq_layout)
        self.faq_dialog.setFixedWidth(400)
        self.faq_dialog.show()

        self.faq_dialog.destroyed.connect(lambda: setattr(self, "faq_dialog", None))

    def add_launch_button(self, row):
        def new_launch_nonblocking(row):
            if self.table.item(row, 1):
                launch_nonblocking(self.table.item(row, 1).text())
            else:
                QMessageBox.warning(self, "Error", "Token cannot be empty.")

        launch_btn = QPushButton("Launch")
        launch_btn.clicked.connect(lambda _, r=row: new_launch_nonblocking(r))
        self.table.setCellWidget(row, 2, launch_btn)

    def add_account(self):
        self.table.insertRow(self.table.rowCount())
        self.add_launch_button(self.table.rowCount() - 1)

    def delete_account(self):
        selected = self.table.currentRow()
        if selected >= 0:
            self.table.removeRow(selected)
        else:
            QMessageBox.warning(self, "Delete Account", "Please select an account to delete.")

    def save_tokens(self):
        data = []
        for row in range(self.table.rowCount()):
            name_item = self.table.item(row, 0)
            token_item = self.table.item(row, 1)
            name = name_item.text() if name_item else ""
            token = token_item.text() if token_item else ""
            if name or token:
                data.append({"name": name, "token": token})
        try:
            enc = self.fernet.encrypt(json.dumps(data).encode())
            with open(TOKENS_FILE, "wb") as f:
                f.write(enc)
            QMessageBox.information(self, "Saved", "Accounts saved successfully.")
            self.unsaved_changes = False
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save: {e}")

    def load_tokens(self):
        if not os.path.exists(TOKENS_FILE) or os.path.getsize(TOKENS_FILE) == 0:
            return

        try:
            with open(TOKENS_FILE, "rb") as f:
                enc = f.read()
            dec = self.fernet.decrypt(enc)
            data = json.loads(dec.decode())
            self.table.setRowCount(0)
            for entry in data:
                row = self.table.rowCount()
                self.table.insertRow(row)
                self.table.setItem(row, 0, QTableWidgetItem(entry.get("name", "")))
                self.table.setItem(row, 1, QTableWidgetItem(entry.get("token", "")))

                self.add_launch_button(row)
            self.unsaved_changes = False
        except InvalidToken:
            QMessageBox.critical(self, "Error", "Failed to decrypt tokens.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load tokens: {e}")

    def launch_all(self):
        # launch all accounts
        try:
            for row in range(self.table.rowCount()):
                token_item = self.table.item(row, 1)
                if token_item:
                    roblosecurity = token_item.text()
                    if roblosecurity:
                        launch_nonblocking(roblosecurity)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to launch: {e}")


class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Roblox Account Manager (v0.1)")
        self.layout = QVBoxLayout()
        self.setLayout(self.layout)
        self.login_widget = LoginWidget()
        self.layout.addWidget(self.login_widget)
        self.login_widget.logged_in.connect(self.show_manager)

    def show_manager(self, password):
        self.layout.removeWidget(self.login_widget)
        self.login_widget.deleteLater()

        self.manager_widget = AccountManagerWidget(password)
        self.layout.addWidget(self.manager_widget)

    def closeEvent(self, event):
        if hasattr(self, "manager_widget") and self.manager_widget.unsaved_changes:
            reply = QMessageBox.question(
                self,
                "Unsaved Changes",
                "You have unsaved changes. Would you like to save before exiting?",
                QMessageBox.Yes | QMessageBox.No | QMessageBox.Cancel,
                QMessageBox.Cancel,
            )
            if reply == QMessageBox.Yes:
                self.manager_widget.save_tokens()
                event.accept()
            elif reply == QMessageBox.No:
                event.accept()
            else:
                event.ignore()
        else:
            event.accept()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())

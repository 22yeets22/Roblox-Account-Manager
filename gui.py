import base64
import hashlib
import json
import os
import sys

from argon2 import PasswordHasher
from cryptography.fernet import Fernet, InvalidToken
from launch import launch_nonblocking
from PyQt5 import QtCore, QtGui, QtWidgets
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
from settings import Settings

PWD_FILE = "pwd.txt"
TOKENS_FILE = "tokens.txt"
SETTINGS_FILE = "settings.json"
FAQS_FILE = "faqs.json"


ph = PasswordHasher()


def hash_password(password):
    # returns a full Argon2 hash string including salt and other params
    return ph.hash(password)


def verify_password(stored_hash, password):
    try:
        return ph.verify(stored_hash, password)
    except Exception:
        return False


def derive_key(password, salt=b"fixed_salt"):
    # help from gpt here
    # Use a fixed salt stored securely or generated once
    key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100_000, dklen=32)  # 100k iters
    return base64.urlsafe_b64encode(key)


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

        # Lock the height to the default height, allow width to change
        self.setFixedHeight(self.sizeHint().height())

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

        if verify_password(stored_hash, pwd):
            self.logged_in.emit(pwd)
        else:
            QMessageBox.warning(self, "Error", "Incorrect password.")
            self.pwd_input.clear()


class FAQDialog(QWidget):
    def __init__(self, parent):
        super().__init__(parent, QtCore.Qt.Window)
        self.setWindowTitle("FAQ")

        self.setFixedWidth(400)
        layout = QVBoxLayout()

        try:
            with open(FAQS_FILE, "r", encoding="utf-8") as f:
                self.faqs = json.load(f)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Could not load FAQs: {e}")
            self.close()
            return

        for entry in self.faqs:
            question = entry.get("question", "Question")
            answer = entry.get("answer", "Answer")

            btn = QPushButton(question)
            btn.clicked.connect(lambda _, q=question, a=answer: QMessageBox.information(self, q, a))
            layout.addWidget(btn)

        close_btn = QPushButton("Close")
        close_btn.setStyleSheet("font-weight: bold;")
        close_btn.clicked.connect(self.close)
        layout.addWidget(close_btn)

        self.setLayout(layout)

    def closeEvent(self, event):
        event.accept()


class SettingsDialog(QWidget):
    def __init__(self, parent, settings):
        # Settings dialog, only use when settings are already loaded
        super().__init__(parent, QtCore.Qt.Window)
        self.setWindowTitle("Settings")
        self.settings = settings

        self._settings_widgets = []
        layout = QVBoxLayout()

        # Layout for label and input/checkbox
        for key, entry in self.settings.data.items():
            row_layout = QHBoxLayout()
            label = QLabel(entry.get("label", "Setting"))
            setting_type = entry.get("type", "bool")
            if setting_type == "bool":
                widget = QtWidgets.QCheckBox()
                widget.setChecked(entry.get("value", False))
            elif setting_type == "string":
                widget = QLineEdit()
                widget.setText(str(entry.get("value", "")))

            row_layout.addWidget(label)
            row_layout.addWidget(widget)
            row_layout.addStretch()
            layout.addLayout(row_layout)
            self._settings_widgets.append((key, widget, setting_type))

        save_close_btn = QPushButton("Save and Close")
        save_close_btn.setStyleSheet("font-weight: bold;")
        save_close_btn.clicked.connect(self.save_and_close)
        layout.addWidget(save_close_btn)

        cancel_btn = QPushButton("Cancel")
        cancel_btn.setStyleSheet("font-weight: bold;")
        cancel_btn.clicked.connect(self.close)
        layout.addWidget(cancel_btn)

        self.setLayout(layout)
        self.setFixedWidth(400)

    def save(self):
        for key, widget, setting_type in self._settings_widgets:
            if setting_type == "bool":
                self.settings.data[key]["value"] = widget.isChecked()
            elif setting_type == "string":
                self.settings.data[key]["value"] = widget.text()
        self.settings.save()

    def save_and_close(self):
        self.save()
        self.close()

    def closeEvent(self, event):
        event.accept()


class AccountManagerWidget(QWidget):
    def __init__(self, password):
        super().__init__()
        self.password = password
        self.fernet = Fernet(derive_key(password))
        self.setWindowTitle("Roblox Account Manager")
        self.unsaved_changes = False

        # Layout for the account manager
        layout = QVBoxLayout()
        self.table = QTableWidget(0, 3)

        self.table.setHorizontalHeaderLabels(["Account Name", "Token", "Launch"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        layout.addWidget(self.table)
        btn_layout = QHBoxLayout()

        # Add help and settings buttons
        help_btn = QPushButton("?")
        help_btn.setFixedSize(30, 30)
        help_btn.setToolTip("Frequently Asked Questions")
        help_btn.clicked.connect(self.show_faq)
        settings_btn = QPushButton("⚙")
        settings_btn.setFixedSize(30, 30)
        settings_btn.setToolTip("Settings")
        settings_btn.clicked.connect(self.show_settings)

        top_layout = QHBoxLayout()
        top_layout.addStretch()
        top_layout.addWidget(help_btn)
        top_layout.addWidget(settings_btn)
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

        # Context menu for the table (insert and delete)
        self.table.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.show_context_menu)

        # Settings and FAQ dialogs
        self.faq_dialog = None
        self.settings_dialog = None

        self.settings = Settings(SETTINGS_FILE)
        self.settings.load()

    def show_faq(self):
        if self.faq_dialog is not None and self.faq_dialog.isVisible():
            self.faq_dialog.raise_()
            self.faq_dialog.activateWindow()
            return
        self.faq_dialog = FAQDialog(self)
        self.faq_dialog.show()
        self.faq_dialog.destroyed.connect(lambda: setattr(self, "faq_dialog", None))

    def show_settings(self):
        if self.settings_dialog is not None and self.settings_dialog.isVisible():
            self.settings_dialog.raise_()
            self.settings_dialog.activateWindow()
            return
        self.settings_dialog = SettingsDialog(self, self.settings)
        self.settings_dialog.show()
        self.settings_dialog.destroyed.connect(lambda: setattr(self, "settings_dialog", None))

    def show_context_menu(self, pos):
        # lol help from chatgpt
        index = self.table.indexAt(pos)
        if not index.isValid():
            return

        menu = QtWidgets.QMenu(self)
        delete_action = menu.addAction("Delete Account")
        insert_action = menu.addAction("Insert Account")

        action = menu.exec_(self.table.viewport().mapToGlobal(pos))
        if action == delete_action:
            self.table.removeRow(index.row())
        elif action == insert_action:
            self.table.insertRow(index.row() + 1)
            self.add_launch_button(index.row() + 1)

    def mark_unsaved(self, *args, **kwargs):
        self.unsaved_changes = True

    def add_launch_button(self, row):
        def safe_launch_unblocking(row):
            if self.table.item(row, 1):
                launch_nonblocking(
                    self.table.item(row, 1).text(),
                    self.settings.data.get("launch_url", {}).get("value", "https://roblox.com/home"),
                    self.settings.data.get("launch_confirmation", {}).get("value", True),
                )
            else:
                QMessageBox.warning(self, "Error", "Please enter a valisd token.")

        launch_btn = QPushButton("Launch")
        launch_btn.clicked.connect(lambda _, r=row: safe_launch_unblocking(r))
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
        # Launch all accounts (skip over empty tokens)
        QtWidgets.QApplication.setOverrideCursor(QtCore.Qt.WaitCursor)
        try:
            for row in range(self.table.rowCount()):
                token_item = self.table.item(row, 1)
                if token_item:
                    launch_nonblocking(
                        token_item.text(),
                        self.settings.data.get("launch_url", {}).get("value", "https://roblox.com/home"),
                        self.settings.data.get("launch_confirmation", {}).get("value", True),
                    )  # Launch in non-blocking mode
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to launch: {e}")
        finally:
            QtWidgets.QApplication.restoreOverrideCursor()


class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Roblox Account Manager (v0.3)")
        self.setWindowIcon(QtGui.QIcon("icon.png"))
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

        self.setMinimumSize(400, 200)
        self.resize(600, 300)

    def closeEvent(self, event):
        # Unsaved changes check
        if (
            hasattr(self, "manager_widget")
            and self.manager_widget.unsaved_changes
            and self.manager_widget.settings.data.get("save_reminder", {}).get("value", True)
        ):
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
    # What's new:
    # - Refactored faq dialog
    # - Made settings actually work! (Oops...)
    # - Added error message in the selenium if token is invalid
    # - Fixed small bugs
    # - New setting to directly load to a page or launch a game

    app = QApplication(sys.argv)
    window = MainWindow()

    window.show()
    sys.exit(app.exec_())

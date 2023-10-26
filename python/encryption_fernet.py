import os
from cryptography.fernet import Fernet
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QLabel, QFileDialog, QLineEdit, QStackedWidget, QComboBox, QMessageBox

class EncryptionApp:
    def __init__(self):
        self.app = QApplication([])
        self.logged_in = False
        self.user_key = None
        self.key_storage_folder = None
        self.selected_key = None
        self.entered_password = None

        self.stacked_widget = QStackedWidget()
        self.login_widget = QWidget()
        self.main_widget = QWidget()
        self.stacked_widget.addWidget(self.login_widget)
        self.stacked_widget.addWidget(self.main_widget)
        self.window_layout = QVBoxLayout()

        self.initialize_login_ui()
        self.initialize_main_ui()
        self.initialize_event_handlers()

        self.window = QWidget()
        self.window.setWindowTitle("File Encryption and Decryption")
        self.window_layout.addWidget(self.stacked_widget)
        self.window.setLayout(self.window_layout)

    def initialize_login_ui(self):
        self.id_label = QLabel("User ID:")
        self.id_input = QLineEdit()
        self.password_label = QLabel("Password:")
        self.password_input = QLineEdit()
        self.login_button = QPushButton("Login")
        self.select_key_folder_button = QPushButton("Select Key Storage Folder")
        self.login_layout = QVBoxLayout(self.login_widget)
        self.login_layout.addWidget(self.id_label)
        self.login_layout.addWidget(self.id_input)
        self.login_layout.addWidget(self.password_label)
        self.login_layout.addWidget(self.password_input)
        self.login_layout.addWidget(self.select_key_folder_button)
        self.login_layout.addWidget(self.login_button)

    def initialize_main_ui(self):
        self.key_management_layout = QVBoxLayout(self.main_widget)

        self.key_storage_folder_label = QLabel("Key Storage Folder: Not selected")
        self.selected_key_label = QLabel("Selected Key: Not selected")

        self.select_file_button_encryption = QPushButton("Select File for Encryption")
        self.encrypt_button = QPushButton("Encrypt")

        self.select_file_button_decryption = QPushButton("Select File for Decryption")
        self.decrypt_button = QPushButton("Decrypt")

        self.key_management_layout.addWidget(self.key_storage_folder_label)
        self.key_management_layout.addWidget(self.selected_key_label)
        self.key_management_layout.addWidget(self.select_file_button_encryption)
        self.key_management_layout.addWidget(self.encrypt_button)
        self.key_management_layout.addWidget(self.select_file_button_decryption)
        self.key_management_layout.addWidget(self.decrypt_button)

    def initialize_event_handlers(self):
        self.login_button.clicked.connect(self.authenticate_user)
        self.select_key_folder_button.clicked.connect(self.select_key_storage_folder)
        self.select_file_button_encryption.clicked.connect(self.select_file_for_encryption)
        self.encrypt_button.clicked.connect(self.encrypt)
        self.select_file_button_decryption.clicked.connect(self.select_file_for_decryption)
        self.decrypt_button.clicked.connect(self.decrypt)

    def authenticate_user(self):
        valid_id = "123"
        valid_password = "123"
        entered_id = self.id_input.text()
        entered_password = self.password_input.text()

        if entered_id == valid_id and entered_password == valid_password:
            self.logged_in = True

            if self.key_storage_folder and self.selected_key:
                self.load_user_key()
            elif self.key_storage_folder:
                self.user_key = self.generate_user_key(entered_id, entered_password)
                self.encrypt_user_key(self.user_key)

            self.selected_key_label.setText(f"Selected Key: {self.selected_key}")

            self.stacked_widget.setCurrentIndex(1)
        else:
            self.show_error("Invalid login credentials")

    def select_key_storage_folder(self):
        folder = QFileDialog.getExistingDirectory(self.window, "Select Key Storage Folder")
        if folder:
            self.key_storage_folder = folder
            self.key_storage_folder_label.setText(f"Key Storage Folder: {self.key_storage_folder}")

    def load_user_key(self):
        if self.selected_key:
            with open(self.selected_key, "rb") as key_file:
                self.user_key = Fernet(key_file.read())

    def generate_user_key(self, user_id, password):
        # Generate a user-specific key
        key = Fernet.generate_key()
        user_key = Fernet(key)

        # Encrypt and save the user key in the selected key storage folder
        if self.key_storage_folder:
            user_key_path = os.path.join(self.key_storage_folder, f"{user_id}_key.key")
            with open(user_key_path, "wb") as key_file:
                key_file.write(key)

        return user_key

    def encrypt_user_key(self, user_key):
        if self.key_storage_folder:
            for key_file in os.listdir(self.key_storage_folder):
                if key_file.endswith("_key.key"):
                    key_path = os.path.join(self.key_storage_folder, key_file)
                    with open(key_path, "rb") as key_file:
                        key = key_file.read()
                    encrypted_key = user_key.encrypt(key)
                    with open(key_path, "wb") as key_file:
                        key_file.write(encrypted_key)

    def encrypt(self):
        if not self.user_key:
            self.show_error("No user key selected")
            return

        file, _ = QFileDialog.getOpenFileName(self.window, "Select File for Encryption", filter="All Files (*.*)")
        if file:
            try:
                f = self.user_key
                with open(file, "rb") as f:
                    file_data = f.read()
                encrypted_data = f.encrypt(file_data)
                encrypted_filename = file + ".encrypted"
                with open(encrypted_filename, "wb") as f:
                    f.write(encrypted_data)
                self.selected_key_label.setText(f"File '{file}' encrypted and saved as '{encrypted_filename}'")
            except Exception as e:
                self.show_error(f"Error during encryption: {str(e)}")

    def decrypt(self):
        if not self.user_key:
            self.show_error("No user key selected")
            return

        file, _ = QFileDialog.getOpenFileName(self.window, "Select File for Decryption", filter="Encrypted Files (*.encrypted)")
        if file:
            try:
                f = self.user_key
                with open(file, "rb") as f:
                    encrypted_data = f.read()
                decrypted_data = f.decrypt(encrypted_data)
                decrypted_filename = file.rsplit('.', 1)[0]
                with open(decrypted_filename, "wb") as f:
                    f.write(decrypted_data)
                self.selected_key_label.setText(f"File '{file}' decrypted and saved as '{decrypted_filename}'")
            except Exception as e:
                self.show_error(f"Error during decryption: {str(e)}")

    def select_file_for_encryption(self):
        self.selected_key_label.setText("")
        self.stacked_widget.setCurrentIndex(1)
        self.select_file_button_encryption.setText("Select File for Encryption")
        self.encrypt_button.setText("Encrypt")
        self.select_file_button_decryption.setText("Select File for Decryption")
        self.decrypt_button.setText("Decrypt")

    def select_file_for_decryption(self):
        self.selected_key_label.setText("")
        self.stacked_widget.setCurrentIndex(1)
        self.select_file_button_encryption.setText("Select File for Encryption")
        self.encrypt_button.setText("Encrypt")
        self.select_file_button_decryption.setText("Select File for Decryption")
        self.decrypt_button.setText("Decrypt")

    def show_error(self, message):
        msg_box = QMessageBox()
        msg_box.setIcon(QMessageBox.Critical)
        msg_box.setWindowTitle("Error")
        msg_box.setText(message)
        msg_box.exec_()

    def run(self):
        self.window.show()
        self.app.exec_()

if __name__ == "__main__":
    app = EncryptionApp()
    app.run()

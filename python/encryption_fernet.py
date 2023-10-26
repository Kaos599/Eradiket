import sys
import os
from PyQt5.QtWidgets import QApplication, QMainWindow, QPushButton, QLabel, QFileDialog
from cryptography.fernet import Fernet

class FileEncryptionApp(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("File Encryption and Decryption")
        self.setGeometry(100, 100, 400, 150)

        self.encrypt_button = QPushButton("Encrypt", self)
        self.encrypt_button.clicked.connect(self.encrypt_button_clicked)
        self.encrypt_button.setGeometry(50, 50, 100, 30)

        self.decrypt_button = QPushButton("Decrypt", self)
        self.decrypt_button.clicked.connect(self.decrypt_button_clicked)
        self.decrypt_button.setGeometry(250, 50, 100, 30)

        self.result_label = QLabel("", self)
        self.result_label.setGeometry(50, 100, 300, 30)

        if not os.path.exists("key.key"):
            self.generate_key()

    def generate_key(self):
        key = Fernet.generate_key()
        with open("key.key", "wb") as key_file:
            key_file.write(key)

    def load_key(self):
        return open("key.key", "rb").read()

    def encrypt_file(self, filename, key):
        f = Fernet(key)
        with open(filename, "rb") as file:
            file_data = file.read()
        encrypted_data = f.encrypt(file_data)

        encrypted_filename = filename + ".encrypted"
        with open(encrypted_filename, "wb") as file:
            file.write(encrypted_data)

    def decrypt_file(self, filename, key):
        f = Fernet(key)
        with open(filename, "rb") as file:
            encrypted_data = file.read()
        decrypted_data = f.decrypt(encrypted_data)

        decrypted_filename = filename.rsplit('.', 1)[0]
        with open(decrypted_filename, "wb") as file:
            file.write(decrypted_data)

    def encrypt_button_clicked(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select a file to encrypt")
        if file_path:
            key = self.load_key()
            self.encrypt_file(file_path, key)
            self.result_label.setText(f"File '{os.path.basename(file_path)}' encrypted.")

    def decrypt_button_clicked(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select a file to decrypt")
        if file_path:
            key = self.load_key()
            self.decrypt_file(file_path, key)
            self.result_label.setText(f"File '{os.path.basename(file_path)}' decrypted.")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = FileEncryptionApp()
    window.show()
    sys.exit(app.exec_())

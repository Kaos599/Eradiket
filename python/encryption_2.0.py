import os
import secrets
from Crypto.Cipher import AES, ChaCha20
from PyQt5.QtWidgets import (
    QApplication,
    QWidget,
    QFileDialog,
    QPushButton,
    QLabel,
    QVBoxLayout,
    QComboBox,
    QMessageBox,
    QDialog,
    QLineEdit,
    QStackedWidget,
)


key_size = {
    "128 Bits": 16,  
    "192 Bits": 24,  
    "256 Bits": 32,  
}


app = QApplication([])


logged_in = False
key_storage_folder = None
selected_key = None
user_key = None  


stacked_widget = QStackedWidget()


def authenticate_user():
    global logged_in, key_storage_folder, selected_key, user_key
    
    if (key_storage_folder is None and selected_key is None) or (not key_storage_folder and not selected_key):
        show_error("Please select a key storage folder or a previous key.")
        return

    
    valid_id = "123"
    valid_password = "123"
    entered_id = id_input.text()
    entered_password = password_input.text()

    if entered_id == valid_id and entered_password == valid_password:
        logged_in = True
        
        stacked_widget.setCurrentIndex(1)

        
        if selected_key:
            with open(selected_key, "rb") as key_file:
                user_key = key_file.read()
        else:
            user_key_path = os.path.join(key_storage_folder, "user_key.bin")
            if os.path.exists(user_key_path):
                with open(user_key_path, "rb") as key_file:
                    user_key = key_file.read()
            else:
                
                user_key = secrets.token_bytes(key_size["128 Bits"])
                with open(user_key_path, "wb") as key_file:
                    key_file.write(user_key)
    else:
        show_error("Invalid login credentials")


def select_key_storage_folder():
    global key_storage_folder, selected_key
    folder = QFileDialog.getExistingDirectory(window, "Select Key Storage Folder")
    if folder:
        key_storage_folder = folder
        key_storage_folder_label.setText(f"Key Storage Folder: {key_storage_folder}")

        
        user_key_path = os.path.join(key_storage_folder, "user_key.bin")
        if os.path.exists(user_key_path):
            selected_key = user_key_path
            selected_key_label.setText(f"Selected Key: {selected_key}")
        else:
            selected_key = None
            selected_key_label.setText("Selected Key: Not Selected")


def select_key():
    global selected_key
    file, _ = QFileDialog.getOpenFileName(window, "Select Key")
    if file:
        selected_key = file
        selected_key_label.setText(f"Selected Key: {selected_key}")


login_dialog = QDialog()
login_dialog.setWindowTitle("Login")
login_dialog.setModal(True)

id_label = QLabel("ID:")
id_input = QLineEdit()
password_label = QLabel("Password:")
password_input = QLineEdit()
password_input.setEchoMode(QLineEdit.Password)
login_button = QPushButton("Login")
login_button.clicked.connect(authenticate_user)

login_layout = QVBoxLayout()
login_layout.addWidget(id_label)
login_layout.addWidget(id_input)
login_layout.addWidget(password_label)
login_layout.addWidget(password_input)


select_folder_button = QPushButton("Select Key Storage Folder")
select_folder_button.clicked.connect(select_key_storage_folder)
login_layout.addWidget(select_folder_button)


key_storage_folder_label = QLabel("Key Storage Folder: Not Selected")
login_layout.addWidget(key_storage_folder_label)


select_key_button = QPushButton("Select Key")
select_key_button.clicked.connect(select_key)
login_layout.addWidget(select_key_button)


selected_key_label = QLabel("Selected Key: Not Selected")
login_layout.addWidget(selected_key_label)

login_layout.addWidget(login_button)
login_dialog.setLayout(login_layout)


main_container = QWidget()


window = QWidget()
window.setWindowTitle("File Encryption Tool")

label = QLabel("No file selected")

algorithm_label = QLabel("Select algorithm")
algorithm_combo = QComboBox()
algorithm_combo.addItems(["AES", "ChaCha20"])

key_strength_label = QLabel("Encryption Strength")
key_strength_combo = QComboBox()
key_strength_combo.addItems(["128 Bits", "192 Bits", "256 Bits"])


def encrypt_file(file, key, algorithm_name):
    try:
        
        if algorithm_name == "AES":
            nonce = secrets.token_bytes(16)  
        elif algorithm_name == "ChaCha20":
            nonce = secrets.token_bytes(12)  
        else:
            raise ValueError("Invalid algorithm selected")

        
        if algorithm_name == "AES":
            cipher = AES.new(key=key, mode=AES.MODE_GCM, nonce=nonce)
        else:
            cipher = ChaCha20.new(key=key, nonce=nonce)

        
        with open(file, "rb") as f:
            data = f.read()

        
        ciphertext = cipher.encrypt(data)

        
        return nonce + ciphertext

    except Exception as e:
        show_error(f"Error during encryption: {str(e)}")


def decrypt_file(ciphertext, key, algorithm_name):
    try:
        
        nonce = ciphertext[:12] if algorithm_name == "ChaCha20" else ciphertext[:16]

        
        if algorithm_name == "AES":
            cipher = AES.new(key=key, mode=AES.MODE_GCM, nonce=nonce)
        else:
            cipher = ChaCha20.new(key=key, nonce=nonce)

        
        data = cipher.decrypt(ciphertext[len(nonce):])

        
        return data

    except Exception as e:
        show_error(f"Error during decryption: {str(e)}")


def encrypt():
    file = label.text()
    algorithm_name = algorithm_combo.currentText()
    key_strength = key_strength_combo.currentText()

    if not file:
        show_error("No file selected")
        return

    try:
        
        key = user_key

        
        ciphertext = encrypt_file(file, key, algorithm_name)
        new_file = f"{file}_{algorithm_name}_{key_strength}.enc"
        with open(new_file, "wb") as f:
            f.write(ciphertext)
        label.setText(f"File {file} encrypted with {algorithm_name} ({key_strength}) and saved as {new_file}")
    except Exception as e:
        show_error(f"Error during encryption: {str(e)}")


def decrypt():
    file = label.text()
    algorithm_name = algorithm_combo.currentText()

    if not file:
        show_error("No file selected")
        return

    try:
        
        key = user_key

        
        with open(file, "rb") as f:
            ciphertext = f.read()

        data = decrypt_file(ciphertext, key, algorithm_name)
        parts = os.path.basename(file).rsplit('_', 2)
        if len(parts) != 3:
            show_error("Invalid file name format for decryption")
            return
        original_file = parts[0]
        key_strength = parts[2].split('.')[0]  
        new_file = f"{original_file}_{algorithm_name}_{key_strength}.dec"
        with open(new_file, "wb") as f:
            f.write(data)
        label.setText(f"File {file} decrypted with {algorithm_name} ({key_strength}) and saved as {new_file}")
    except Exception as e:
        show_error(f"Error during decryption: {str(e)}")


def select_file_for_encryption():
    file, _ = QFileDialog.getOpenFileName(window, "Select File for Encryption")
    if file:
        
        label.setText(file)


def select_file_for_decryption():
    file, _ = QFileDialog.getOpenFileName(window, "Select File for Decryption")
    if file:
        
        label.setText(file)


select_file_button_encryption = QPushButton("Select File for Encryption")
select_file_button_encryption.clicked.connect(select_file_for_encryption)

select_file_button_decryption = QPushButton("Select File for Decryption")
select_file_button_decryption.clicked.connect(select_file_for_decryption)


encryption_decryption_layout = QVBoxLayout()
encryption_decryption_layout.addWidget(label)
encryption_decryption_layout.addWidget(algorithm_label)
encryption_decryption_layout.addWidget(algorithm_combo)
encryption_decryption_layout.addWidget(key_strength_label)
encryption_decryption_layout.addWidget(key_strength_combo)


encrypt_button = QPushButton("Encrypt")
encrypt_button.clicked.connect(encrypt)

decrypt_button = QPushButton("Decrypt")
decrypt_button.clicked.connect(decrypt)

encryption_decryption_layout.addWidget(encrypt_button)
encryption_decryption_layout.addWidget(decrypt_button)
encryption_decryption_layout.addWidget(select_file_button_encryption)  
encryption_decryption_layout.addWidget(select_file_button_decryption)  
main_container.setLayout(encryption_decryption_layout)  

stacked_widget.addWidget(login_dialog)
stacked_widget.addWidget(main_container)


window_layout = QVBoxLayout()
window_layout.addWidget(stacked_widget)
window.setLayout(window_layout)


def show_error(message):
    msg_box = QMessageBox()
    msg_box.setIcon(QMessageBox.Critical)
    msg_box.setWindowTitle("Error")
    msg_box.setText(message)
    msg_box.exec_()

window.show()

app.exec_()

#Chacha20 and AES working well
import os
import secrets
from Crypto.Cipher import AES, ChaCha20
from PyQt5.QtWidgets import QApplication, QWidget, QFileDialog, QPushButton, QLabel, QVBoxLayout, QComboBox, QMessageBox

# Define the key size for AES and ChaCha20
key_size = {
    "128 Bits": 16,
    "192 Bits": 24,
    "256 Bits": 32,
}

# Define a dictionary to map algorithm names to their encryption functions
encryption_algorithms = {
    "AES": AES,
    "ChaCha20": ChaCha20,
}

# Define a function to encrypt a file using a selected algorithm and a given key
def encrypt_file(file, key, algorithm_name):
    # Generate a random nonce (IV) of the appropriate size for the algorithm
    if algorithm_name == "AES":
        nonce = secrets.token_bytes(16)  # 16 bytes for AES
    elif algorithm_name == "ChaCha20":
        nonce = secrets.token_bytes(12)  # 12 bytes for ChaCha20
    else:
        raise ValueError("Invalid algorithm selected")
    
    # Create a cipher object using the selected algorithm, key, mode, and nonce
    if algorithm_name == "AES":
        cipher = AES.new(key=key, mode=AES.MODE_GCM, nonce=nonce)
    else:
        cipher = encryption_algorithms[algorithm_name].new(key=key, nonce=nonce)
    
    # Open the file in binary mode and read its contents
    with open(file, "rb") as f:
        data = f.read()
    # Encrypt the data using the cipher
    ciphertext = cipher.encrypt(data)
    # Return the ciphertext
    return nonce + ciphertext

# Define a function to decrypt a file using a selected algorithm and a given key
def decrypt_file(ciphertext, key, algorithm_name):
    # Extract the nonce (IV) from the first 12 bytes of the ciphertext for ChaCha20
    nonce = ciphertext[:12] if algorithm_name == "ChaCha20" else ciphertext[:16]
    
    # Create a cipher object using the selected algorithm, key, mode, and nonce
    if algorithm_name == "AES":
        cipher = AES.new(key=key, mode=AES.MODE_GCM, nonce=nonce)
    else:
        cipher = encryption_algorithms[algorithm_name].new(key=key, nonce=nonce)
    
    # Decrypt the ciphertext using the cipher
    data = cipher.decrypt(ciphertext[len(nonce):])
    # Return the decrypted data
    return data


def encrypt():
    file = label.text()
    algorithm_name = algorithm_combo.currentText()
    key_strength = key_strength_combo.currentText()
    
    if not file:
        show_error("No file selected")
        return
    
    try:
        key = secrets.token_bytes(key_size[key_strength])
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
        parts = file.split('_')
        if len(parts) != 3:
            show_error("Invalid file name format for decryption")
            return
        
        original_file = parts[0]
        key_strength = parts[2].split('.')[0]  # Extract the key strength from the filename
        with open(file, "rb") as f:
            ciphertext = f.read()
        
        key = secrets.token_bytes(key_size[key_strength])
        data = decrypt_file(ciphertext, key, algorithm_name)
        
        new_file = f"{original_file}_{algorithm_name}_{key_strength}.dec"
        with open(new_file, "wb") as f:
            f.write(data)
        label.setText(f"File {file} decrypted with {algorithm_name} ({key_strength}) and saved as {new_file}")
    except Exception as e:
        show_error(f"Error during decryption: {str(e)}")

def select_file():
    file, _ = QFileDialog.getOpenFileName(window, "Select File")
    label.setText(file)

def show_error(message):
    msg_box = QMessageBox()
    msg_box.setIcon(QMessageBox.Critical)
    msg_box.setWindowTitle("Error")
    msg_box.setText(message)
    msg_box.exec_()

app = QApplication([])

window = QWidget()

label = QLabel("No file selected")

algorithm_label = QLabel("Select algorithm")
algorithm_combo = QComboBox()
algorithm_combo.addItems(encryption_algorithms.keys())

key_strength_label = QLabel("Encryption Strength")
key_strength_combo = QComboBox()
key_strength_combo.addItems(key_size.keys())

encrypt_button = QPushButton("Encrypt")
encrypt_button.clicked.connect(encrypt)

decrypt_button = QPushButton("Decrypt")
decrypt_button.clicked.connect(decrypt)

select_button = QPushButton("Select File")
select_button.clicked.connect(select_file)

layout = QVBoxLayout()
layout.addWidget(label)
layout.addWidget(algorithm_label)
layout.addWidget(algorithm_combo)
layout.addWidget(key_strength_label)
layout.addWidget(key_strength_combo)
layout.addWidget(encrypt_button)
layout.addWidget(decrypt_button)
layout.addWidget(select_button)

window.setLayout(layout)

window.show()

app.exec_()

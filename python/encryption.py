import sys
import os
import time
from PyQt5.QtWidgets import QApplication, QMainWindow, QPushButton, QFileDialog, QLabel, QComboBox

class SecureFileDeletionApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Secure File Deletion")
        self.setGeometry(100, 100, 400, 400)
        self.initUI()
        self.wiping_method = None
        self.file_path = None
        
    def initUI(self):
        self.method_label = QLabel("Select Wiping Method:", self)
        self.method_label.setGeometry(20, 20, 200, 30)

        self.method_combo = QComboBox(self)
        self.method_combo.setGeometry(230, 20, 150, 30)
        self.method_combo.addItem("Select Algorithm")  # Initial placeholder option
        self.method_combo.addItem("Random Data Overwrite (1 Pass)")
        self.method_combo.addItem("NCSC-TG (3 Passes)")
        self.method_combo.addItem("RCMP TSSIT OPS-II (7 Passes)")
        self.method_combo.addItem("DoD 5220.22-M (3 Passes)")
        self.method_combo.currentIndexChanged.connect(self.method_changed)

        self.select_button = QPushButton("Select File", self)
        self.select_button.setGeometry(20, 60, 200, 30)
        self.select_button.clicked.connect(self.showFileDialog)

        self.delete_button = QPushButton("Delete File Permanently", self)
        self.delete_button.setGeometry(20, 100, 200, 30)
        self.delete_button.clicked.connect(self.deleteFile)
        self.delete_button.setEnabled(False)

        self.result_label = QLabel(self)
        self.result_label.setGeometry(20, 140, 360, 30)

        self.file_info_label = QLabel(self)
        self.file_info_label.setGeometry(20, 180, 360, 30)

        self.runtime_label = QLabel("Runtime (seconds):", self)
        self.runtime_label.setGeometry(20, 220, 150, 30)
        self.runtime_value_label = QLabel(self)
        self.runtime_value_label.setGeometry(170, 220, 100, 30)

    def method_changed(self, index):
        # Map combo box items to wiping methods
        wiping_methods = {
            "Random Data Overwrite (1 Pass)": "1_pass",
            "NCSC-TG (3 Passes)": "ncsc_tg",
            "RCMP TSSIT OPS-II (7 Passes)": "rcmp_tssit",
            "DoD 5220.22-M (3 Passes)": "dod"
        }
        self.wiping_method = wiping_methods.get(self.method_combo.currentText(), None)

    def showFileDialog(self):
        options = QFileDialog.Options()
        options |= QFileDialog.ReadOnly

        file_dialog = QFileDialog()
        file_path, _ = file_dialog.getOpenFileName(self, "Select File for Deletion", "", "All Files (*)", options=options)

        if file_path:
            self.file_path = file_path
            self.file_info_label.setText(f"Selected File: {file_path}")
            self.delete_button.setEnabled(True)

    def deleteFile(self):
        if self.wiping_method is None:
            self.result_label.setText("Error: Please select a wiping method.")
            return

        if self.file_path is None:
            self.result_label.setText("Error: Please select a file to delete.")
            return

        try:
            start_time = time.time()
            if self.wiping_method == "1_pass":
                self.onePassDelete(self.file_path)
            elif self.wiping_method == "ncsc_tg":
                self.ncscTGDelete(self.file_path)
            elif self.wiping_method == "rcmp_tssit":
                self.rcmpTSSITDelete(self.file_path)
            elif self.wiping_method == "dod":
                self.dodDelete(self.file_path)
            elapsed_time = time.time() - start_time

            self.result_label.setText("File deleted securely.")
            self.file_info_label.setText(f"Selected File: {self.file_path}")
            self.runtime_value_label.setText(f"{elapsed_time:.10f}")
        except Exception as e:
            self.result_label.setText(f"An error occurred: {str(e)}")

    def onePassDelete(self, file_path):
        # Overwrite the file with random data (1 pass)
        with open(file_path, 'ab') as file:
            file.write(os.urandom(os.path.getsize(file_path)))

        # Remove the file
        os.remove(file_path)

    def ncscTGDelete(self, file_path):
        # Overwrite the file with zeros (5 passes)
        with open(file_path, 'wb') as file:
            file.write(b'\x00' * os.path.getsize(file_path))
            file.write(b'\xff' * os.path.getsize(file_path))
            file.write(b'\x00' * os.path.getsize(file_path))
            file.write(b'\xff' * os.path.getsize(file_path))
            file.write(b'\x00' * os.path.getsize(file_path))

        # Remove the file
        os.remove(file_path)

    def rcmpTSSITDelete(self, file_path):
        # Overwrite the file with random data (7 passes)
        with open(file_path, 'ab') as file:
            for _ in range(7):
                file.write(os.urandom(os.path.getsize(file_path)))

        # Remove the file
        os.remove(file_path)

    def dodDelete(self, file_path):
        # Overwrite the file with zeros and ones (3 passes)
        with open(file_path, 'wb') as file:
            file.write(b'\x00' * os.path.getsize(file_path))
            file.write(b'\xff' * os.path.getsize(file_path))
            file.write(b'\x00' * os.path.getsize(file_path))

        # Remove the file
        os.remove(file_path)

def main():
    app = QApplication(sys.argv)
    window = SecureFileDeletionApp()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()

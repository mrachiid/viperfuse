import sys
import os
import time
import hashlib
import qdarktheme
from PyQt5.QtWidgets import QApplication, QMainWindow, QVBoxLayout, QWidget, QLabel, QLineEdit, QTextEdit, QPushButton, QRadioButton, QHBoxLayout, QStyle, QFileDialog

def calculate_file_hash(filepath):
    with open(filepath, "rb") as f:
        file_data = f.read()
        return hashlib.sha512(file_data).hexdigest()

def erase_baseline_if_already_exists():
    if os.path.exists("./baseline.txt"):
        os.remove("./baseline.txt")

def get_file_info(filepath):
    file_stat = os.stat(filepath)
    file_size = file_stat.st_size
    file_mod_time = file_stat.st_mtime
    return file_size, file_mod_time

class FileIntegrityMonitor(QMainWindow):
    def __init__(self):
        super().__init__()
        # qdarktheme.setup_theme()  #dark theme

        self.init_ui()
        self.changed_files = []

    def init_ui(self):
        self.setWindowTitle('File Integrity Monitor')

        widget = QWidget()
        layout = QVBoxLayout()

        self.option_a = QRadioButton('Collect new Baseline')
        layout.addWidget(self.option_a)

        self.option_b = QRadioButton('Begin monitoring files with saved Baseline')
        layout.addWidget(self.option_b)

        self.dir_label = QLabel('Directory path to monitor:')
        layout.addWidget(self.dir_label)

        self.dir_entry = QLineEdit()
        #layout.addWidget(self.dir_entry)
        
        #dir button
        btn = QPushButton()
        pixmapi = getattr(QStyle, "SP_DirIcon")
        icon = self.style().standardIcon(pixmapi)
        btn.setIcon(icon)
        btn.clicked.connect(self.open_dir)

        #horizontal layout
        hlayout = QHBoxLayout()
        hlayout.addWidget(self.dir_entry)
        hlayout.addWidget(btn)
        layout.addLayout(hlayout)
        #

        self.start_button = QPushButton('Start')
        self.start_button.clicked.connect(self.monitor_files)
        layout.addWidget(self.start_button)

        self.result_text = QTextEdit()
        self.result_text.setReadOnly(True)
        layout.addWidget(self.result_text)

        widget.setLayout(layout)
        self.setCentralWidget(widget)

    def open_dir(self):
        dialog = QFileDialog()
        dirc = dialog.getExistingDirectory(self, 'Select a directory')
        self.dir_entry.setText(dirc)


    def monitor_files(self):
        response = None
        if self.option_a.isChecked():
            response = "A"
        elif self.option_b.isChecked():
            response = "B"

        dir_path = self.dir_entry.text()

        if response == "A":
            erase_baseline_if_already_exists()

            files = os.listdir(dir_path)
            with open("./baseline.txt", "w") as baseline_file:
                for f in files:
                    file_path = os.path.join(dir_path, f)
                    file_hash = calculate_file_hash(file_path)
                    file_size, file_mod_time = get_file_info(file_path)
                    baseline_file.write(f"{file_path}|{file_hash}|{file_size}|{file_mod_time}\n")
            self.result_text.append("Baseline collected!")

        elif response == "B":
            file_info_dict = {}
            deleted_files = []
            modified_files = []
            new_files = []

            #statusbar
            self.statusBar().showMessage(f'Monitoring...')
                
            with open("./baseline.txt", "r") as baseline_file:
                for line in baseline_file:
                    file_path, file_hash, file_size, file_mod_time = line.strip().split("|")
                    file_info_dict[file_path] = (file_hash, int(file_size), float(file_mod_time))

            while True:
                QApplication.processEvents()
                time.sleep(1)

                files = os.listdir(dir_path)

                # Check for deleted files
                for file_path in list(file_info_dict.keys()):
                    if not os.path.exists(file_path):
                        file_size, file_mod_time = file_info_dict[file_path][1], file_info_dict[file_path][2]
                        self.result_text.append(f"{file_path} has been deleted! (size: {file_size} bytes, modified: {time.ctime(file_mod_time)})")
                        del file_info_dict[file_path]
                        deleted_files.append(file_path)

                # Check for modified and new files
                for f in files:
                    file_path = os.path.join(dir_path, f)
                    if file_path in file_info_dict:
                        file_hash = calculate_file_hash(file_path)
                        if file_info_dict[file_path][0] != file_hash:
                            old_size, old_mod_time = file_info_dict[file_path][1], file_info_dict[file_path][2]
                            new_size, new_mod_time = get_file_info(file_path)
                            if file_path not in modified_files:
                                self.result_text.append(f"{file_path} has changed! (old size: {old_size} bytes, new size: {new_size} bytes, old modified: {time.ctime(old_mod_time)}, new modified: {time.ctime(new_mod_time)})")
                                modified_files.append(file_path)
                            file_info_dict[file_path] = (file_hash, new_size, new_mod_time)
                    else:
                        file_hash = calculate_file_hash(file_path)
                        file_size, file_mod_time = get_file_info(file_path)
                        self.result_text.append(f"{file_path} is a new file! (size: {file_size} bytes, modified: {time.ctime(file_mod_time)})")
                        file_info_dict[file_path] = (file_hash, file_size, file_mod_time)
                        new_files.append(file_path)

                # Rename modified files
                for file_path in modified_files:
                    new_path = file_path + "_modified"
                    os.rename(file_path, new_path)
                    self.result_text.append(f"{file_path} has been renamed to {new_path}")
                
                deleted_files.clear()
                modified_files.clear()
                new_files.clear()
        else:
            self.result_text.append("Invalid option selected!")


def main():
    app = QApplication(sys.argv)
    window = FileIntegrityMonitor()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()

from PyQt5.QtWidgets import QMainWindow, QPushButton, QLineEdit, QTextEdit, QVBoxLayout, QWidget
from PyQt5.QtGui import QRegExpValidator
from PyQt5.QtCore import QRegExp
import nmap
import subprocess

class NmapScanner(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle('Nmap Scanner')
        self.setGeometry(100, 100, 600, 400)

        layout = QVBoxLayout()
        centralWidget = QWidget()
        centralWidget.setLayout(layout)
        self.setCentralWidget(centralWidget)

        self.ipInput = QLineEdit(self)
        self.ipInput.setPlaceholderText('Enter IP or IP range')

        # IP Address Validation
        ipRegex = QRegExp("^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
        ipValidator = QRegExpValidator(ipRegex, self.ipInput)
        self.ipInput.setValidator(ipValidator)

        layout.addWidget(self.ipInput)

        self.scanButton = QPushButton('Scan', self)
        self.scanButton.clicked.connect(self.performScan)
        layout.addWidget(self.scanButton)

        # Add "Scan All In Network" button
        self.scanAllButton = QPushButton('Scan All In Network', self)
        self.scanAllButton.clicked.connect(self.scanAllInNetwork)
        layout.addWidget(self.scanAllButton)

        self.resultArea = QTextEdit(self)
        self.resultArea.setReadOnly(True)
        layout.addWidget(self.resultArea)

    def performScan(self):
        ip = self.ipInput.text()
        if ip:  # Proceed with the scan only if the IP input is not empty
            self.scan(ip, '-sV')
        else:
            self.resultArea.setText("Please enter a valid IP address.")

    def scanAllInNetwork(self):
        ip = self.ipInput.text()
        if ip:  # Use the provided IP to determine the network range
            network = '.'.join(ip.split('.')[:3]) + '.0/24'  # Assumes a class C network
            self.scan(network, '-sS')
        else:
            self.resultArea.setText("Please enter a valid IP address to determine the network.")

    def scan(self, ip, arguments):
        self.resultArea.clear()
        command = f"pkexec nmap {arguments} {ip}"
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()

        if process.returncode == 0:
            output = stdout.decode('utf-8')
            self.resultArea.append(output)
        else:
            self.resultArea.append(f"Error: {stderr.decode('utf-8')}")
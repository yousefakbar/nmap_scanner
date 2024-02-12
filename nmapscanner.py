from PyQt5.QtWidgets import QMainWindow, QPushButton, QLineEdit, QTextEdit, QGridLayout, QWidget
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

        layout = QGridLayout()
        centralWidget = QWidget()
        centralWidget.setLayout(layout)
        self.setCentralWidget(centralWidget)

        self.ipInput = QLineEdit(self)
        self.ipInput.setPlaceholderText('Enter IP or IP range')

        # IP Address Validation
        ipRegex = QRegExp("^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
        ipValidator = QRegExpValidator(ipRegex, self.ipInput)
        self.ipInput.setValidator(ipValidator)

        layout.addWidget(self.ipInput, 0, 0, 1, 2)

        self.scanButton = QPushButton('Scan', self)
        self.scanButton.clicked.connect(self.performScan)
        layout.addWidget(self.scanButton, 1, 0)

        # Add "Scan All In Network" button
        self.scanAllButton = QPushButton('Scan All In Network', self)
        self.scanAllButton.clicked.connect(self.scanAllInNetwork)
        layout.addWidget(self.scanAllButton, 1, 1)

        # "Clear" button
        self.clearButton = QPushButton('Clear', self)
        self.clearButton.clicked.connect(self.clearResults)
        layout.addWidget(self.clearButton, 2, 0, 1, 2)

        self.resultArea = QTextEdit(self)
        self.resultArea.setReadOnly(True)
        layout.addWidget(self.resultArea, 3, 0, 1, 2)

    def performScan(self):
        ip = self.ipInput.text()
        scanner = nmap.PortScanner()
        scanner.scan(ip, arguments='sC sV')
        for host in scanner.all_hosts():
            self.resultArea.append(f'Host: {host} ({scanner[host].hostname()})')
            self.resultArea.append(f'State: {scanner[host].state()}')
            for proto in scanner[host].all_protocols():
                self.resultArea.append(f'----------\nProtocol: {proto}')
                lport = scanner[host][proto].keys()
                for port in lport:
                    self.resultArea.append(f'port: {port}\tstate: {scanner[host][proto][port]["state"]}\tservice: {scanner[host][proto][port]["name"]}')
            self.resultArea.append('---------------------')

    def scanAllInNetwork(self):
        ip = self.ipInput.text()
        if ip:  # Use the provided IP to determine the network range
            network = '.'.join(ip.split('.')[:3]) + '.0/24'  # Assumes a class C network
            self.scan(network, arguments='-sS')
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

    def clearResults(self):
        self.resultArea.clear()

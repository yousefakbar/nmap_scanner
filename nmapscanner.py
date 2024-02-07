from PyQt5.QtWidgets import QMainWindow, QPushButton, QLineEdit, QTextEdit, QVBoxLayout, QWidget
from PyQt5.QtGui import QRegExpValidator
from PyQt5.QtCore import QRegExp
import nmap

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

        self.resultArea = QTextEdit(self)
        self.resultArea.setReadOnly(True)
        layout.addWidget(self.resultArea)

    def performScan(self):
        ip = self.ipInput.text()
        if ip:  # Proceed with the scan only if the IP input is not empty
            scanner = nmap.PortScanner()
            scanner.scan(ip, arguments='-sV')
            for host in scanner.all_hosts():
                self.resultArea.append(f'Host: {host} ({scanner[host].hostname()})')
                self.resultArea.append(f'State: {scanner[host].state()}')
                for proto in scanner[host].all_protocols():
                    self.resultArea.append(f'----------\nProtocol: {proto}')
                    lport = scanner[host][proto].keys()
                    for port in lport:
                        self.resultArea.append(f'port: {port}\tstate: {scanner[host][proto][port]["state"]}\tservice: {scanner[host][proto][port]["name"]}')
                self.resultArea.append('---------------------')
        else:
            self.resultArea.setText("Please enter a valid IP address.")

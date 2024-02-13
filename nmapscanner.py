from PyQt5.QtWidgets import QMainWindow, QPushButton, QLineEdit, QTextEdit, QGridLayout, QWidget, QLabel
from PyQt5.QtGui import QRegExpValidator
from PyQt5.QtCore import QRegExp
import nmap
import subprocess

class NmapScanner(QMainWindow):
    def __init__(self):
        super().__init__()
        self.layout = None
        self.hostWidgets = []  # List to keep track of dynamically added widgets (labels and buttons)
        self.initUI()

    def initUI(self):
        self.setWindowTitle('Nmap Scanner')
        self.setGeometry(100, 100, 600, 400)

        self.layout = QGridLayout()
        centralWidget = QWidget()
        centralWidget.setLayout(self.layout)
        self.setCentralWidget(centralWidget)

        self.ipInput = QLineEdit(self)
        self.ipInput.setPlaceholderText('Enter IP or IP range')

        # IP Address Validation
        ipRegex = QRegExp("^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
        ipValidator = QRegExpValidator(ipRegex, self.ipInput)
        self.ipInput.setValidator(ipValidator)

        self.layout.addWidget(self.ipInput, 0, 0, 1, 2)

        self.scanButton = QPushButton('Scan', self)
        self.scanButton.clicked.connect(self.performScan)
        self.layout.addWidget(self.scanButton, 1, 0)

        # Add "Scan All In Network" button
        self.scanAllButton = QPushButton('Scan All In Network', self)
        self.scanAllButton.clicked.connect(self.scanAllInNetwork)
        self.layout.addWidget(self.scanAllButton, 1, 1)

        # "Clear" button
        self.clearButton = QPushButton('Clear', self)
        self.clearButton.clicked.connect(self.clearResults)
        self.layout.addWidget(self.clearButton, 2, 0, 1, 2)

        self.resultArea = QTextEdit(self)
        self.resultArea.setReadOnly(True)
        self.layout.addWidget(self.resultArea, 3, 0, 1, 2)

    def performScan(self, ip=None):
        self.clearDynamicWidgets()
        if not ip:
            ip = self.ipInput.text()

        scanner = nmap.PortScanner()
        scanner.scan(ip, arguments='-sC -sV')
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
            self.scan(network)
        else:
            self.resultArea.setText("Please enter a valid IP address to determine the network.")

    def scan(self, ip):
        self.clearDynamicWidgets()
        self.resultArea.clear()
        i =3 # Adjust if more fields are added above the results field
        scanner = nmap.PortScanner()
        scanner.scan(ip, arguments='-sn')
        uphosts = scanner.scanstats()['uphosts']
        totalhosts = scanner.scanstats()['totalhosts']
        self.resultArea.append('List of hosts UP (%s/%s) in network (%s)\n' % (uphosts, totalhosts, ip))
        for host in scanner.all_hosts():  # for each host found, create a qLabel and "more" button
            i+=i
            self.hostLabel = QLabel(self)
            self.hostLabel.setText(f'Host: {host} ({scanner[host].hostname()})')

            self.moreButton = QPushButton(self)
            self.moreButton.setText('Scan')  # TODO: add functionality to button
            self.moreButton.clicked.connect(lambda checked, ip=host: self.performScan(ip))

            self.layout.addWidget(self.hostLabel, i, 0, 1, 2)
            self.layout.addWidget(self.moreButton, i, 1, 1, 1)
            self.hostWidgets.append((self.hostLabel, self.moreButton))

    def clearResults(self):
        self.resultArea.clear()

    def clearDynamicWidgets(self):
        # Remove and delete each dynamically added widget
        for label, button in self.hostWidgets:
            self.layout.removeWidget(label)
            self.layout.removeWidget(button)
            label.deleteLater()
            button.deleteLater()
        self.hostWidgets.clear()  # Clear the list after removing the widgets

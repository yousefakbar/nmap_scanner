from PyQt5.QtWidgets import QMainWindow, QPushButton, QLineEdit, QGridLayout, QWidget, QLabel, QTextBrowser, QScrollArea
from PyQt5.QtGui import QRegExpValidator, QDesktopServices
from PyQt5.QtCore import QRegExp, QUrl
import nmap
import subprocess
import nvdlib
import re

class NmapScanner(QMainWindow):
    def __init__(self):
        super().__init__()
        self.layout = None

        self.hosts_list = []
        self.hostWidgets = []  # List to keep track of dynamically added widgets (labels and buttons)
        self.initUI()

    def initUI(self):
        self.setWindowTitle('Nmap Scanner')
        self.setGeometry(100, 100, 600, 400)

        self.layout = QGridLayout()
        self.scrollArea = QScrollArea()
        self.scrollArea.setWidgetResizable(True)  # Allow the scroll area to resize the widget

        # Create a container widget to hold the layout
        container = QWidget()
        container.setLayout(self.layout)

        # Set the container widget as the widget for the scroll area
        self.scrollArea.setWidget(container)

        self.setCentralWidget(self.scrollArea)
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
        self.layout.addWidget(self.clearButton, 2, 0, 1, 1)

        self.resultArea = QTextBrowser(self)
        self.resultArea.setReadOnly(True)
        self.resultArea.setOpenExternalLinks(True)
        self.resultArea.anchorClicked.connect(self.openLink)
        self.layout.addWidget(self.resultArea, 3, 0, 1, 2)

        # "Reset" button
        self.resetButton = QPushButton('Reset', self)
        self.resetButton.clicked.connect(self.resetView)
        self.layout.addWidget(self.resetButton, 2, 1, 1, 1)

    def performScan(self, ip=None):
        i = 3

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
                    i += 1
                    self.portLabel = QLabel(self)
                    self.portLabel.setText(f'port: {port}\nstate:{scanner[host][proto][port]["state"]}\nservice: {scanner[host][proto][port]["name"]}')

                    self.performVersionScanButton = QPushButton(self)
                    self.performVersionScanButton.setText('Perform Version Scan')
                    self.performVersionScanButton.clicked.connect(lambda checked, ip=host, inport=port: self.performVersionScan(ip, inport))

                    self.layout.addWidget(self.portLabel, i, 0, 1, 2)
                    self.layout.addWidget(self.performVersionScanButton, i, 1, 1, 1)
                    self.hostWidgets.append((self.portLabel, self.performVersionScanButton))

                    
            self.resultArea.append('---------------------')

    def performVersionScan(self, ip, port):

        #First the program finds the qlabel with the correct port:
        sender = self.sender()  # Get the object that triggered the signal (in this case, the button)
        gridLayout = sender.parentWidget().layout()  # Get the grid layout

        row_position, column_position, _, _ = gridLayout.getItemPosition(gridLayout.indexOf(sender))

        self.layout.removeWidget(sender)
        self.portVulnTB = QTextBrowser(self)
        self.portVulnTB.setOpenExternalLinks(True)
        self.layout.addWidget(self.portVulnTB, row_position, column_position)

        args = '-sV -p ' + str(port)
        scanner = nmap.PortScanner()
        scanner.scan(ip, arguments=args)

        self.portVulnTB.append('Port: ' + str(port))
        self.portVulnTB.append('Service: ' + scanner[ip]['tcp'][port]['name'])
        self.portVulnTB.append('Name: ' + scanner[ip]['tcp'][port]['product'])
        self.portVulnTB.append('Version: ' + scanner[ip]['tcp'][port]['version'] + '\n')
        version = scanner[ip]['tcp'][port]['version']

        self.portVulnTB.append('Vulnerabilities:')
        self.portVulnTB.append('---------------\n')

        if scanner[ip]['tcp'][port]['product'] == 'OpenSSH':
            version = self.getSSHVersion(scanner[ip]['tcp'][port]['version'])

        self.getCVEs(scanner[ip]['tcp'][port]['product'], version)

    def getSSHVersion(self, version):
        ssh_version = version[:version.index(' ')]
        match = re.search('[a-zA-Z]', ssh_version)
        match_idx = match.start()
        return ssh_version[:match_idx] + ' ' + ssh_version[match_idx:]


    def getCVEs(self, service, version):
        q = service + ' ' + version
        cpe_list = nvdlib.searchCPE(keywordSearch=q)
        for cpe in cpe_list:
            cve_res = nvdlib.searchCVE(cpe.cpeName)
            for cve in cve_res:
                self.portVulnTB.append('Severity: ' + cve.score[2])
                self.portVulnTB.append('<a href="https://nvd.nist.gov/vuln/detail/' + cve.id + '">' + cve.id + '</a>')
                self.portVulnTB.append('Last Updated: ' + cve.lastModified)
                self.portVulnTB.append('')
                self.appendToFile(cve.id)

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
            self.hosts_list.append(scanner[host])

            self.hostLabel = QLabel(self)
            self.hostLabel.setText(f'IP: {host}\nHostname: {scanner[host].hostname()}\n')

            self.performScanButton = QPushButton(self)
            self.performScanButton.setText('Scan')  # TODO: add functionality to button
            self.performScanButton.clicked.connect(lambda checked, ip=host: self.performScan(ip))

            self.layout.addWidget(self.hostLabel, i, 0, 1, 2)
            self.layout.addWidget(self.performScanButton, i, 1, 1, 1)
            self.hostWidgets.append((self.hostLabel, self.performScanButton))
        print(len(self.hosts_list))
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

    def resetView(self):
        self.clearDynamicWidgets()
        self.clearResults()
        self.ipInput.setText('')

    def appendToFile(self, cveID):
        # TODO: allow this to take an input from the created file screen (also to be added)
        with open('temp.txt', 'a') as file:
            file.write('Copy and paste the following link: https://nvd.nist.gov/vuln/detail/')
            file.write(cveID + '\n')

    def openLink(self, url):
        QDesktopServices.openUrl(url)
        return

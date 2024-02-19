from PyQt5.QtWidgets import QMainWindow, QPushButton, QLineEdit, QGridLayout, QWidget, QLabel, QTextBrowser, \
    QScrollArea, QFrame
from PyQt5.QtGui import QRegExpValidator, QDesktopServices
from PyQt5.QtCore import QRegExp, QThread, pyqtSignal
import nmap
import nvdlib
import re
import asyncio


class NmapScanner(QMainWindow):
    def __init__(self):
        super().__init__()
        self.layout = None

        self.hosts_list = []
        self.hostWidgets = []  # List to keep track of dynamically added widgets (labels and buttons)
        self.layouts = {}  # Dictionary to keep track of QFrames and their layouts
        self.activeThreads = []  # List to keep track of active threads
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
        self.scanButton.clicked.connect(lambda: self.onScanButtonClick(self.scanButton))
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

    async def performScan(self, ip=None):
        self.clearDynamicWidgets()
        loop = asyncio.get_event_loop()
        if not ip:
            self.clearDynamicWidgets()
            ip = self.ipInput.text()

        scanner = nmap.PortScanner()
        return await loop.run_in_executor(None, self.blocking_nmap_scan, scanner, ip, '-T4 -sC -sV')

    def displayResultsPerformScan(self, scanner):
        print(scanner.all_hosts())
        i = 3
        numports = 0

        frame = QFrame(self)
        port_layout = QGridLayout(frame)

        #sender = self.sender()  # Get the object that triggered the signal (in this case, the button)
        sender = self.pressedButton  # Get the object that triggered the signal (in this case, the button)
        gridLayout = sender.parentWidget().layout()  # Get the grid layout

        row_position, column_position, _, _ = gridLayout.getItemPosition(gridLayout.indexOf(sender))

        self.layout.removeWidget(sender)
        sender.deleteLater()  # Remove and delete the scan button

        self.layout.addWidget(frame, row_position, 3, 1, 2)
        self.layouts[frame] = port_layout  # Store the QFrame and its layout in the dictionary
        for host in scanner.all_hosts():
            self.resultArea.append(f'Host: {host} ({scanner[host].hostname()})')
            self.resultArea.append(f'State: {scanner[host].state()}')

            for proto in scanner[host].all_protocols():
                lport = scanner[host][proto].keys()

                for port in lport:
                    numports = numports + 1

                    portLabel = QLabel(self)
                    portLabel.setText(
                        f'port: {port}\nstate:{scanner[host][proto][port]["state"]}\nservice: {scanner[host][proto][port]["name"]}')

                    performVersionScanButton = QPushButton(self)
                    performVersionScanButton.setText('Check for CVE')
                    performVersionScanButton.clicked.connect(
                        lambda checked, ip=host, inport=port: self.performVersionScan(ip, inport))

                    port_layout.addWidget(portLabel, numports, 0, 1, 1)
                    port_layout.addWidget(performVersionScanButton, numports, 1, 1, 1)

            self.resultArea.append('---------------------')

    def performVersionScan(self, ip, port):

        sender = self.sender()  # Get the object that triggered the signal (in this case, the button)
        gridLayout = sender.parentWidget().layout()  # Get the grid layout

        row_position, _, _, _ = gridLayout.getItemPosition(gridLayout.indexOf(sender))

        self.layout.removeWidget(sender)
        frame = next((key for key, value in self.layouts.items() if value == gridLayout), None)

        if frame:
            # Instantiate QTextBrowser with the correct parent (frame)
            self.portVulnTB = QTextBrowser(frame)
            self.portVulnTB.setOpenExternalLinks(True)

            # Use the retrieved layout to add the QTextBrowser to the QFrame
            self.layouts[frame].addWidget(self.portVulnTB, row_position, 1, 1, 2)

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
        i = 3  # Adjust if more fields are added above the results field
        scanner = nmap.PortScanner()
        scanner.scan(ip, arguments='-sn')
        uphosts = scanner.scanstats()['uphosts']
        totalhosts = scanner.scanstats()['totalhosts']
        self.resultArea.append('List of hosts UP (%s/%s) in network (%s)\n' % (uphosts, totalhosts, ip))
        for host in scanner.all_hosts():  # for each host found, create a qLabel and "more" button
            i += i
            self.hosts_list.append(scanner[host])

            self.hostLabel = QLabel(self)
            self.hostLabel.setText(f'IP: {host}\nHostname: {scanner[host].hostname()}\n')

            self.performScanButton = QPushButton(self)
            self.performScanButton.setText('Scan Ports')
            self.performScanButton.clicked.connect(lambda checked, ip=host: self.performScan(ip))


            self.layout.addWidget(self.hostLabel, i, 0, 1, 2)
            self.layout.addWidget(self.performScanButton, i, 1, 1, 1)
            self.hostWidgets.append((self.hostLabel, self.performScanButton))
        print(len(self.hosts_list))

    def blocking_nmap_scan(self, nm, ip, args):
        nm.scan(ip, arguments=args)
        return nm

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

    def onScanButtonClick(self, button):
        self.pressedButton = button
        self.startAsyncTask(self.performScan())

    def onVersionScanButtonClick(self, ip, port):
        self.startAsyncTask(self.performVersionScan(ip, port))

    def startAsyncTask(self, coroutine):
        task = Worker(coroutine)
        task.scanComplete.connect(self.displayResultsPerformScan)
        task.finished.connect(lambda: self.activeThreads.remove(task))  # Connect to a slot to remove the thread from the list
        self.activeThreads.append(task)  # Add the thread to the list of active threa
        task.start()

class Worker(QThread):
    scanComplete = pyqtSignal(object)

    def __init__(self, coro):
        super().__init__()
        self.coro = coro

    def run(self):
        print("AsyncTask started")
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        result = loop.run_until_complete(self.coro)
        self.scanComplete.emit(result)  # Emit the scan results
        loop.close()


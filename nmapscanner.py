from PyQt5.QtWidgets import QMainWindow, QPushButton, QLineEdit, QGridLayout, QWidget, QLabel, QTextBrowser, \
        QScrollArea, QFrame, QMessageBox
from PyQt5.QtGui import QRegExpValidator, QDesktopServices
from PyQt5.QtCore import QRegExp, QThread, pyqtSignal, Qt
import nmap
import nvdlib
import re
import asyncio
import subprocess


class NmapScanner(QMainWindow):
    def __init__(self):
        super().__init__()
        self.layout = None

        self.api_key = '1f8da398-dc1d-4a00-be62-139a13cacda2'
        self.hosts_list = []
        self.hostWidgets = []  # List to keep track of dynamically added widgets (labels and buttons)
        self.layouts = {}  # Dictionary to keep track of QFrames and their layouts
        self.activeThreads = []  # List to keep track of active threads
        self.allButtons = [] #List to keep track of buttons
        self.nvdlib_error = False
        self.nm_scan_error = False
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

        self.layout.addWidget(self.ipInput, 0, 0, 1, 4)

        self.scanButton = QPushButton('Scan', self)
        self.scanButton.clicked.connect(lambda: self.onScanButtonClick(self.scanButton))
        self.layout.addWidget(self.scanButton, 1, 0, 1, 2)
        self.allButtons.append(self.scanButton)

        # Add "Scan All In Network" button
        self.scanAllButton = QPushButton('Scan All In Network', self)
        self.scanAllButton.clicked.connect(lambda: self.onNetworkScanButtonClick(self.scanAllButton))
        self.layout.addWidget(self.scanAllButton, 1, 2, 1, 2)
        self.allButtons.append(self.scanAllButton)

        # "Clear" button
        self.clearButton = QPushButton('Clear', self)
        self.clearButton.clicked.connect(self.clearResults)
        self.layout.addWidget(self.clearButton, 2, 0, 1, 2)
        self.allButtons.append(self.clearButton)

        self.resultArea = QTextBrowser(self)
        self.resultArea.setReadOnly(True)
        self.resultArea.setOpenExternalLinks(True)
        self.resultArea.anchorClicked.connect(self.openLink)
        self.layout.addWidget(self.resultArea, 3, 0, 1, 4)

        # "Reset" button
        self.resetButton = QPushButton('Reset', self)
        self.resetButton.clicked.connect(self.resetView)
        self.layout.addWidget(self.resetButton, 2, 2, 1, 2)
        self.allButtons.append(self.resetButton)

        # Check if nmap is installed. If not, ask user to install it first.
        if self.is_nmap_installed() == False:
            reply = QMessageBox.question(container, 'Install nmap?', 'Nmap is required to run the program. Would you like to install nmap?', QMessageBox.Yes | QMessageBox.No, QMessageBox.No)

            if reply == QMessageBox.No:
                QMessageBox.warning(container, 'nmap Required', 'nmap is required to run this command. Please install then run again.')
                sys.exit(1)
            else:
                self.install_nmap(container)

    async def performScan(self, ip=None):
        loop = asyncio.get_event_loop()
        if not ip:
            self.clearDynamicWidgets()
            ip = self.ipInput.text()

        scanner = nmap.PortScanner()
        return await loop.run_in_executor(None, self.blocking_nmap_scan, scanner, ip, '-sC -sV')

    def displayResultsPerformScan(self, scanner):

        self.enableAllButtons()
        print(scanner.all_hosts())
        if self.nm_scan_error == True:
            return

        numports = 0

        frame = QFrame(self)
        frame.setFrameShape(QFrame.StyledPanel)
        frame.setStyleSheet("background-color:gray")

        sshFile = "NMapScannerCSS.qss"
        with open(sshFile, "r") as fh:
            frame.setStyleSheet(fh.read())

        port_layout = QGridLayout(frame)

        sender = self.scanPressedButton  # Get the object that triggered the signal (in this case, the button)
        gridLayout = sender.parentWidget().layout()  # Get the grid layout

        row_position, column_position, _, _ = gridLayout.getItemPosition(gridLayout.indexOf(sender))

        if row_position == 1:
            row_position = 4
            column_position = 0
            self.scanPressedButton.setEnabled(True)
        else:
            self.layout.removeWidget(sender)
            self.allButtons.remove(sender)


            sender.deleteLater()  # Remove and delete the scan button


        self.layout.addWidget(frame, row_position, column_position, 1, 2)
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

                    port_layout.addWidget(portLabel, numports, 0, 1, 1)
                    port_layout.addWidget(performVersionScanButton, numports, 1, 1, 1)

                    self.allButtons.append(performVersionScanButton)

                    performVersionScanButton.clicked.connect(
                        lambda checked, ip=host, inport=port: self.onVersionScanButtonClick(ip, inport, performVersionScanButton))

            self.resultArea.append('---------------------')


    async def performVersionScan(self, ip, port):
        loop = asyncio.get_event_loop()
        args = '-sV -p ' + str(port)
        scanner = nmap.PortScanner()
        return await loop.run_in_executor(None, self.blocking_version_scan, scanner, ip, port, args)

    def displayResultsVersionScan(self, scanner):

        self.enableAllButtons()

        if self.nvdlib_error == True:
            print('There was an error in the nvdlib call')
            return

        if self.nm_scan_error == True:
            return

        ip = self.test_ip
        port = self.test_port
        sender = self.versionScanPressedButton  # Get the object that triggered the signal (in this case, the button)
        gridLayout = sender.parentWidget().layout()  # Get the grid layout

        row_position, _, _, _ = gridLayout.getItemPosition(gridLayout.indexOf(sender))

        self.layout.removeWidget(sender)

        frame = next((key for key, value in self.layouts.items() if value == gridLayout), None)



        if frame:
            # Instantiate QTextBrowser with the correct parent (frame)
            self.portVulnTB = QTextBrowser(frame)
            self.portVulnTB.setStyleSheet("background-color: white; color: black")
            self.portVulnTB.setOpenExternalLinks(True)

            # Use the retrieved layout to add the QTextBrowser to the QFrame
            self.layouts[frame].addWidget(self.portVulnTB, row_position, 1, 1, 2)
            # self.layouts[frame].addWidget(self.portVulnTB, 1, 1, 1, 2)

        self.portVulnTB.append('Port: ' + str(port))
        self.portVulnTB.append('Service: ' + scanner[ip]['tcp'][port]['name'])
        self.portVulnTB.append('Name: ' + scanner[ip]['tcp'][port]['product'])
        self.portVulnTB.append('Version: ' + scanner[ip]['tcp'][port]['version'] + '\n')
        version = scanner[ip]['tcp'][port]['version']

        self.portVulnTB.append('Vulnerabilities:')
        self.portVulnTB.append('---------------\n')

        for line in self.version_res:
            self.portVulnTB.append(line)

    def getSSHVersion(self, version):
        if len(version) <= 3:
            return version
        ssh_version = version[:version.index(' ')]
        match = re.search('[a-zA-Z]', ssh_version)
        match_idx = match.start()
        return ssh_version[:match_idx] + ' ' + ssh_version[match_idx:]

    async def scanAllInNetwork(self):
        self.clearDynamicWidgets()
        loop = asyncio.get_event_loop()
        ip = self.ipInput.text()
        if ip:  # Use the provided IP to determine the network range
            network = '.'.join(ip.split('.')[:3]) + '.0/24'  # Assumes a class C network
            scanner = nmap.PortScanner()
            return await loop.run_in_executor(None, self.blocking_nmap_scan, scanner, network, '-sn')
        else:
            self.resultArea.setText("Please enter a valid IP address to determine the network.")

    def displayResultsScanAll(self, scanner):
        self.enableAllButtons()
        self.resultArea.clear()
        self.scanAllPressedButton.setEnabled(True)
        i = 3  # Adjust if more fields are added above the results field
        uphosts = scanner.scanstats()['uphosts']
        totalhosts = scanner.scanstats()['totalhosts']
        self.resultArea.append('List of hosts UP (%s/%s) in network \n' % (uphosts, totalhosts))
        for host in scanner.all_hosts():  # for each host found, create a qLabel and "more" button
            i += i
            self.hosts_list.append(scanner[host])

            self.hostLabel = QLabel(self)
            self.hostLabel.setText(f'IP: {host}\nHostname: {scanner[host].hostname()}\n')
            print(scanner[host])
            self.hostLabel.setAlignment(Qt.AlignTop)

            self.performScanButton = QPushButton(self)
            self.performScanButton.setText('Scan Ports')

            self.allButtons.append(self.performScanButton)

            self.layout.addWidget(self.hostLabel, i, 0, 1, 2)
            self.layout.addWidget(self.performScanButton, i, 2, 1, 1)
            self.hostWidgets.append((self.hostLabel, self.performScanButton))


            self.performScanButton.clicked.connect(lambda checked, ip=host: self.onScanButtonClick(self.performScanButton, ip))





    def blocking_nmap_scan(self, nm, ip, args):
        try:
            nm.scan(ip, arguments=args)
        except:
            print('There was an error in the nmap scan. Try again.')
            self.nm_scan_error = True
        return nm

    def blocking_version_scan(self, scanner, ip, port, args):
        try:
            scanner.scan(ip, arguments=args)
        except:
            print('There was an error in the nmap version scan. Try again.')
            self.nm_scan_error = True
            return

        self.version_res = []

        service = scanner[ip]['tcp'][port]['product']
        if scanner[ip]['tcp'][port]['product'] == 'OpenSSH':
            version = self.getSSHVersion(scanner[ip]['tcp'][port]['version'])
        else:
            version = scanner[ip]['tcp'][port]['version']

        q = service + ' ' + version

        try:
            cpe_list = nvdlib.searchCPE(keywordSearch=q, key=self.api_key, delay=1)
        except:
            self.nvdlib_error = True
            return scanner

        for cpe in cpe_list:
            try:
                cve_res = nvdlib.searchCVE(cpe.cpeName, key=self.api_key, delay=1)
            except:
                self.nvdlib_error = True
                return scanner

            for cve in cve_res:
                self.version_res.append('Severity: ' + cve.score[2])
                self.version_res.append('<a href="https://nvd.nist.gov/vuln/detail/' + cve.id + '">' + cve.id + '</a>')
                self.version_res.append('Last Updated: ' + cve.lastModified)
                self.version_res.append('')
                self.appendToFile(cve.id)

        self.test_ip = ip
        self.test_port = port
        return scanner

    def clearResults(self):
        self.resultArea.clear()

    def clearDynamicWidgets(self):
        # Remove and delete each dynamically added widget
        for label, button in self.hostWidgets:
            self.layout.removeWidget(label)
            self.layout.removeWidget(button)

            label.deleteLater()
            button.deleteLater()
            self.allButtons.remove(button)
        self.hostWidgets.clear()  # Clear the list after removing the widgets

        # Remove and Delete each frame and it's layout
        for frame, layout in self.layouts.items():
            self.layout.removeWidget(frame)
            frame.deleteLater()

            # Remove and delete widgets from the layout
            for i in reversed(range(layout.count())):
                layout_item = layout.itemAt(i)
                if layout_item is not None:
                    widget = layout_item.widget()
                    if widget is not None:
                        layout.removeWidget(widget)
                        widget.deleteLater()

        self.layouts.clear()  # Clear the dictionary after removing the frames and layouts

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

    def onScanButtonClick(self, button, ip=None):

        self.disableAllButtons()

        self.scanPressedButton = self.sender()

        if ip:
            self.startAsyncTask(self.performScan(ip), self.displayResultsPerformScan)
        else:
            self.startAsyncTask(self.performScan(), self.displayResultsPerformScan)

    def onNetworkScanButtonClick(self, button):
        self.disableAllButtons()

        if self.ipInput.text() != '':
            self.scanAllPressedButton = self.sender()
            self.scanAllPressedButton.setEnabled(False)
            self.startAsyncTask(self.scanAllInNetwork(), self.displayResultsScanAll)
        else:
            self.resultArea.append('Enter IP or IP range.')

    def onVersionScanButtonClick(self, ip, port, button):

        for b in self.allButtons:
            if b != self.sender() and isinstance(b, QPushButton) and b.text() == 'Check for CVE':
                pass
            else:
                b.setEnabled(False)

        self.versionScanPressedButton = self.sender()
        self.versionScanPressedButton.setEnabled(False)
        self.startAsyncTask(self.performVersionScan(ip, port), self.displayResultsVersionScan) # TODO

    def startAsyncTask(self, coroutine, callback):
        task = Worker(coroutine)
        task.scanComplete.connect(callback)
        task.finished.connect(lambda: self.activeThreads.remove(task))  # Connect to a slot to remove the thread from the list
        self.activeThreads.append(task)  # Add the thread to the list of active threa
        task.start()

    def is_nmap_installed(self):
        return subprocess.run(['which', 'nmap'], stdout=subprocess.PIPE).returncode == 0

    def install_nmap(self, container):
        QMessageBox.information(container, 'Installing', 'Please wait while we download and install nmap')
        try:
            subprocess.run(['pkexec', 'sudo', 'apt', 'install', '-y', 'nmap'], check=True)
            QMessageBox.information(container, 'nmap Installed', 'nmap has been successfully installed. You may now use the program')
        except:
            QMessageBox.critical(container, 'Installation failed', 'Installation failed.')

    # functions to disable and enable buttons
    def disableAllButtons(self):
        for button in self.allButtons:
            button.setEnabled(False)

    def enableAllButtons(self):
        for button in self.allButtons:
            button.setEnabled(True)


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


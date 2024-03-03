import sys
from PyQt5.QtWidgets import QApplication
from nmapscanner import NmapScanner


def main():
    app = QApplication(sys.argv)
    sshFile = "NMapScannerCSS.qss"
    with open(sshFile, "r") as fh:
        app.setStyleSheet(fh.read())
    ex = NmapScanner()
    ex.show()
    sys.exit(app.exec_())


if __name__ == '__main__':
    main()

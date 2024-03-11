from PyQt5.QtWidgets import QApplication
from models.scanner import NmapScanner
import os
import sys


def main():
    app = QApplication(sys.argv)
    if getattr(sys, 'frozen', False):
        application_path = sys._MEIPASS
    else:
        application_path = os.path.dirname(os.path.abspath(__file__))
    sshFile = os.path.join(application_path, 'NMapScannerCSS.qss')
    with open(sshFile, "r") as fh:
        app.setStyleSheet(fh.read())
    ex = NmapScanner()
    ex.show()
    sys.exit(app.exec_())


if __name__ == '__main__':
    main()

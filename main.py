import sys
from PyQt5.QtWidgets import QApplication
from nmapscanner import NmapScanner


def main():
    app = QApplication(sys.argv)
    ex = NmapScanner()
    ex.show()
    sys.exit(app.exec_())


if __name__ == '__main__':
    main()

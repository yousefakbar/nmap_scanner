from PyQt5.QtCore import QThread, pyqtSignal
import asyncio

class Worker(QThread):
    scan_complete = pyqtSignal(object)

    def __init__(self, coro):
        super().__init__()
        self.coro = coro

    def run(self):
        print("AsyncTask started")
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        result = loop.run_until_complete(self.coro)
        self.scan_complete.emit(result)  # Emit the scan results
        loop.close()
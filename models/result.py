# do we want to select what we want to push into the db or push everything?
class ScanResult():
    def __init__(self, ip, stats, result):
        print(ip, stats, result)
        self.ip = ip
        self.stats = stats
        self.result = result
        # should we add CVE?
        # should we push to db at the end or as soon as we scan?
        # should we also save results for when we can all in network?

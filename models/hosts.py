# Host defines and organizes IP's, ports, and CVE's in a data structure that can
# be instantiated, populated, modified, and retrieved from the NmapScanner for
# debugging, logging, and creating the report in an efficient way

class Host():
    # Structure of the Host dictionary:
    # hosts_list = {
    # [192.168.1.1]
    #   [22]
    #       [CVE-2023-3422]
    #       [CVE-2024-2123]
    #
    #   [80]
    #
    # [172.10.4.32]
    #
    # [10.103.24.2]
    # }
    hosts_list = {}


    def append_host(self, ip):
        # If the ip is already in the dict, move on
        # Otherwise, add it as a nested dict for space to add ports and cve's
        if ip in self.hosts_list:
            return False

        self.hosts_list[ip] = {}


    def append_port_to_host(self, ip, port):
        if port in self.hosts_list[ip]:
            return False

        self.hosts_list[ip][port] = {}


    def append_cve_to_port(self, ip, port, cve):
        if cve in self.hosts_list[ip][port]:
            return False

        self.hosts_list[ip][port][cve] = {}


    def print_dict(self):
        print('Printing the hosts dictionary')
        print(self.hosts_list)

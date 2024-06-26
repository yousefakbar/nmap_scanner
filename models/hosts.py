# Host defines and organizes IP's, ports, and CVE's in a data structure that can
# be instantiated, populated, modified, and retrieved from the NmapScanner for
# debugging, logging, and creating the report in an efficient way

import datetime
from models.ip import IP
from models.port import Port
from models.cve import CVE


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

    def __init__(self):
        # date = datetime.now()
        # TODO: Add user tracking logic
        user_id = 0

    def append_host(self, ip, host_name):
        # If the ip is already in the dict, move on
        # Otherwise, add it as a nested dict for space to add ports and cve's
        if ip in self.hosts_list:
            return False

        self.hosts_list[ip] = IP(ip, host_name, {})

    def append_port_to_host(self, ip, port, info):
        if port in self.hosts_list[ip].ports:
            return False

        self.hosts_list[ip].ports[port] = Port(port, info['product'], info['service'], info['version'], {})

    def append_cve_to_port(self, ip, port, cve, info):
        if cve in self.hosts_list[ip].ports[port].cves:
            return False

        self.hosts_list[ip].ports[port].cves[cve] = CVE(cve, info['last_modified'], info['url'], info['severity'])

    def print_dict(self):
        print('Printing the hosts dictionary')
        # print(self.hosts_list)
        for ip in self.hosts_list.values():
            self.print_ip(ip)

    def print_ip(self, ip):
        print("IP:", ip.ip)
        print("\tHost Name:", ip.hostname)
        if ip.ports:
            print("\tPorts:")
            for port in ip.ports.values():
                self.print_port(port)

    def print_port(self, port):
        print("\t\tPort:", port.port_number)
        print("\t\t\tProduct:", port.product)
        print("\t\t\tService Name:", port.service_name)
        print("\t\t\tService Version:", port.service_version)
        if port.cves:
            print("\t\t\tCVES:")
            for cve in port.cves.values():
                self.print_cve(cve)

    def print_cve(self, cve):
        print("\t\t\t\tCVE:", cve.name)
        print("\t\t\t\t\tLast Modified:", cve.last_modified)
        print("\t\t\t\t\tURL:", cve.url)
        print("\t\t\t\t\tSeverity:", cve.severity)


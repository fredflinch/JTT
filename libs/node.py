
class ipnode:
    def __init__(self, ip):
        self.ip = ip
        self.pulse_count = ""
        self.pulse_info = []
        self.malware_count = ""
        self.dns_entries = []
        self.ports = []
        self.asn = ""
        self.geo = ""
    

    def print_node(self):
        print(f"\nnode: {self.ip}\n# of pulses:{self.pulse_count}\nasn: {self.asn}\nCountry: {self.geo}\n")

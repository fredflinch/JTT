from libs.otx import otx
from libs.node import ipnode
from tqdm import tqdm

class otxscanner:
    def __init__(self, ips):
        self.nodes = []
        store = otxscan(ips)
        for data in store:
            n = ipnode(data['indicator'])
            process_general(data, n)
            self.nodes.append(n)
        
def otxscan(ips):
    o = otx()
    for ip in tqdm(ips):
        o.get_by_field(ip, "general")
    o.fin()
    return o.storeage

def process_general(general_data, node):
    pdata = []
    node.pulse_count = str(general_data['pulse_info']['count'])
    for p in general_data['pulse_info']['pulses']:
        pdata.append((p['name'], p['created']))
    node.pulse_info = pdata
    node.asn = general_data['asn']
    node.geo = general_data['country_code']

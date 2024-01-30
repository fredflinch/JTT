import re, ipaddress
import pandas as pd

def is_cidr(ipStr):
    if re.match(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\/[0-9]{1,2}', ipStr):
        return  [str(ip) for ip in ipaddress.IPv4Network(ipStr)]
    else:
        return [ipStr]
    
def load_csv(file):
    df = pd.read_csv(file)
    return df.iloc[:, 0].to_list()
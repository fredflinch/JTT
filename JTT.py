#!/usr/bin/python3
from libs.utils import is_cidr, load_csv
from modules.otxscanner import otxscanner
import pandas as pd
import argparse

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("-i", "--infile", help="Path to ipfile\nSupported modes: csv")
    p.add_argument("-o", "--outfile", help="Write the output to the file\nSupported modes: csv")
    args = p.parse_args()

    ips = load_csv(args.infile)
    a = otxscanner(ips)
    for x in a.nodes:
        x.print_node()
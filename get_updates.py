#!/usr/bin/env python3

import argparse
import ipaddress
import os
import re
from datetime import datetime

import requests
import supernets

IP_LIST_DIR = "./lists/"
TMP_OUTPUT_FILE = "./output.txt"


def is_valid_ipv4(ip):
    # check single address
    try:
        address = ipaddress.ip_address(ip)
        return isinstance(address, ipaddress.IPv4Address)
    except:
        pass

    # check CIDR range
    try:
        range = ipaddress.ip_network(ip)
        return isinstance(range, ipaddress.IPv4Network)
    except:
        pass

    # didn't match anything good
    return False


def absolute_file_paths(directory):
    path = os.path.abspath(directory)
    return [entry.path for entry in os.scandir(path) if entry.is_file()]


def concat_supernets(directory, output_file):

    # files with full path
    list_files = absolute_file_paths(directory)
    list_files.insert(0, "first_empty_arg")

    supernets.process_input(list_files)
    supernets.process_prefixes()
    with open(output_file, "a") as out:
        for network in sorted(supernets.networks, key=lambda ip: ip.network_address.packed):
            out.write(str(network)+'\n')


def concat_ip_lists(directory, output_file):
    with open(output_file, "a") as out:
        for file in os.listdir(directory):
            with open(directory+file, 'r') as f:
                for line in f.readlines():
                    line = line.rstrip('\n')
                    if is_valid_ipv4(line):
                        out.write(line+'\n')
                    else:
                        print("Bad line in " + file + ": " + line)
                        exit(1)


def get_aws_ips(output_file):
    ip_ranges = requests.get(
        "https://ip-ranges.amazonaws.com/ip-ranges.json").json()['prefixes']
    with open(output_file, "a") as out:
        for range in ip_ranges:
            if "ip_prefix" in range.keys():  # filter out IPv6
                if is_valid_ipv4(range['ip_prefix']):
                    out.write(range['ip_prefix'] + '\n')
                else:
                    print("Bad AWS IP range: " + range['ip_prefix'])
                    exit(1)
    return


def get_azure_ips(output_file):
    AZURE_RANGES = [
        "https://www.microsoft.com/en-us/download/confirmation.aspx?id=56519",  # public
        "https://www.microsoft.com/en-us/download/confirmation.aspx?id=57062",  # China
        "https://www.microsoft.com/en-us/download/confirmation.aspx?id=57063"   # Gov
    ]

    for range in AZURE_RANGES:
        # TODO filter out overlaps (for example 13.70.185.130/32 is within 13.70.128.0/18)
        download_page_data = requests.get(range).text
        download_link = re.findall(
            '"(https://download.*?)"', download_page_data)[0]
        if not download_link:
            print("Azure IP download link not found")
            exit(1)

        services = requests.get(download_link).json()['values']
        with open(output_file, "a") as out:
            for service in services:
                ip_ranges = service['properties']['addressPrefixes']
                for ip_range in ip_ranges:
                    if ":" not in ip_range:  # filter out IPv6 the hacky way
                        if is_valid_ipv4(ip_range):
                            out.write(ip_range + '\n')
                        else:
                            print("Bad Azure IP range: " + ip_range)
                            exit(1)
    return


def get_gcp_ips(output_file):
    ip_ranges = requests.get(
        "https://www.gstatic.com/ipranges/cloud.json").json()['prefixes']
    with open(output_file, "a") as out:
        for range in ip_ranges:
            if "ipv4Prefix" in range.keys():  # filter out IPv6
                if is_valid_ipv4(range['ipv4Prefix']):
                    out.write(range['ipv4Prefix'] + '\n')
                else:
                    print("Bad GCP IP range: " + range['ipv4Prefix'])
                    exit(1)
    return


def main(args):

    if not os.path.exists(IP_LIST_DIR):
        os.makedirs(IP_LIST_DIR)

    open(TMP_OUTPUT_FILE, 'w').close()  # clear the file

    # get all of the IPs
    # downloads AWS IP ranges and adds to file
    get_aws_ips(IP_LIST_DIR + "_aws")
    # downloads Azure IP ranges and adds to file
    get_azure_ips(IP_LIST_DIR + "_azure")
    # downloads Google Cloud IP ranges and adds to file
    get_gcp_ips(IP_LIST_DIR + "_gcp")
    # concat the ip files in this repo
    concat_supernets(IP_LIST_DIR, TMP_OUTPUT_FILE)

    print("See file at " + TMP_OUTPUT_FILE)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument("--print", action="store_true", default=False,
                        help="Print out the results from the tmp file")
    args = parser.parse_args()
    main(args)

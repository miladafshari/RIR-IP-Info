import subprocess
import ipaddress
import math
import requests
import json
import shutil
import argparse
import urllib.request as request
import re

from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from tqdm import tqdm
from contextlib import closing
from urllib.error import URLError
from iso3166 import countries_by_alpha2
from itertools import product


rir_list = ["ripe", "afrinic", "apnic", "lacnic", "arin"]
rir_stat_urls = {
    "ripe": "ftp://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest",
    "afrinic": "ftp://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-extended-latest",
    "apnic": "ftp://ftp.apnic.net/pub/stats/apnic/delegated-apnic-extended-latest",
    "lacnic": "ftp://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-extended-latest",
    "arin": "ftp://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest"
}

def init_argparse() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        usage="%(prog)s [OPTION]",
        description="Fetch and display IP Prefixes (IPv4, IPv6) and, organization information associated with RIR IP ranges."
    )

    parser.add_argument('-r', '--rir', choices=rir_list, nargs=1, required=True)
    parser.add_argument('-c', '--country_code', choices=countries_by_alpha2.keys(), nargs=1, required=True)
    parser.add_argument('-v', '--ip_version', choices=['ipv4','ipv6'], nargs=1, required=True)
    # parser.add_argument('-v', '--ip_version', type=int, choices=[4,6], nargs=1, required=True)
    parser.add_argument('-t', '--prefix_type', choices=["allocated", "assigned"], nargs=1, required=True)
    parser.add_argument('-o', '--org_info', action='store_true', required=False)
    return parser

def ip_to_prefix(ip, num_addresses, ip_version):
    if ip_version == 'ipv4':
        bits_needed = math.ceil(math.log2(num_addresses))
        prefix_length = 32 - bits_needed
        network = ipaddress.IPv4Network((ip, prefix_length), strict=False)
    else:
        network = ipaddress.IPv6Network((ip, num_addresses), strict=False)
    return str(network)

def fetch_organization_info(ip_prefix):
    try:
        url = f"https://stat.ripe.net/data/whois/data.json?resource={ip_prefix}"
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()
        records = data.get('data', {}).get('records', [])
        for record in records:
            for entry in record:
                if entry.get('key') == 'netname':
                    return entry.get('value', 'Unknown organization')
    except requests.exceptions.RequestException as e:
        print(f"RequestException occurred: {e}")
    except json.JSONDecodeError as e:
        print(f"JSONDecodeError occurred while parsing response for {ip_prefix}: {e}")
    except Exception as e:
        print(f"Exception occurred while fetching organization info for {ip_prefix}: {e}")
    return "Unknown organization"

def process_ip_range(net_addr, len, ip_version, fetch_org_info):
    try:
        if ip_version == 'ipv4':
            num_addresses = int(len)
            prefix_notation = ip_to_prefix(net_addr, num_addresses, ip_version)
        else:
            prefix_length = int(len)
            prefix_notation = ip_to_prefix(net_addr, prefix_length, ip_version)
        
        if fetch_org_info:
            org_info = fetch_organization_info(prefix_notation)
            return (prefix_notation, org_info, num_addresses if ip_version == 'ipv4' else prefix_length)
        else:
            return (prefix_notation, None, num_addresses if ip_version == 'ipv4' else prefix_length)
    except ValueError as e:
        print(f"ValueError: {e}")
        return None

def main():
    parser = init_argparse()
    args = parser.parse_args()

    records = []
    try:
        for rir in args.rir:
            with closing(request.urlopen(rir_stat_urls[rir])) as r:
                for record in product(args.country_code, args.ip_version, args.prefix_type):
                    records.extend(re.findall(f"(.*?)\|{record[0]}\|{record[1]}\|(.*?)\|(.*?)\|(.*?)\|{record[2]}\|(.*?)", str(r.read())))
    except URLError as e:
        if e.reason.find('No such file or directory') >= 0:
            raise Exception('FileNotFound')
        else:
            raise Exception(f'Something else happened. "{e.reason}"')

    total_ip_addresses = 0
    results = []

    print(records)
    # Use ThreadPoolExecutor to fetch data concurrently
    with ThreadPoolExecutor(max_workers=40) as executor:
        futures = [executor.submit(process_ip_range, record[1], record[2], args.ip_version, args.org_info) for record in records]
        progress_desc = f"Processing data from retrieved Database..."
        for future in tqdm(as_completed(futures), total=len(futures), desc=progress_desc):
            result = future.result()
            if result:
                prefix_notation, org_info, num_addresses_or_prefix_length = result
                if args.org_info:
                    results.append(f"{prefix_notation} | {org_info}")
                else:
                    results.append(f"{prefix_notation}")
                
                if args.ip_version == 'ipv4':
                    total_ip_addresses += num_addresses_or_prefix_length
                else:
                    total_ip_addresses += 2**(128 - num_addresses_or_prefix_length)

        # Print the total number of IP addresses
        results.append(f"Total IP addresses: {total_ip_addresses}")

        # Write results to a file with a timestamp, country code, prefix type, IP version, and RIR name
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"results_{timestamp}.txt"
        # filename = f"results_{rir.replace(' ', '_').upper()}_{args.country_code}_{args.prefix_type.replace(' ', '_')}_{args.ip_version}_{timestamp}.txt"
        with open(filename, 'w') as file:
            file.write("\n".join(results))
        
        print(f"Results have been written to {filename}")

if __name__ == "__main__":
    main()

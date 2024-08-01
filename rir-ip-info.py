#!/usr/bin/env python3
from concurrent.futures import ThreadPoolExecutor, as_completed
from iso3166 import countries_by_alpha2
from sys import stderr as STREAM
from datetime import datetime
from io import BytesIO
from tqdm import tqdm
import ipaddress
import requests
import argparse
import pycurl
import math
import re

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

    parser.add_argument('-r', '--rir', type=str.lower, choices=rir_stat_urls.keys(), nargs='+', required=True)
    parser.add_argument('-c', '--country_code', type=str.upper, choices=countries_by_alpha2.keys(), nargs='+', required=True)
    parser.add_argument('-v', '--ip_version', type=int, choices=[4,6], nargs='*', default=[4,6])
    parser.add_argument('-t', '--prefix_type', type=str.lower, choices=["allocated", "assigned"], nargs='+', required=True)
    parser.add_argument('-o', '--org_info', action='store_true', required=False)
    parser.add_argument('-p', '--progress', action='store_true', required=False, default=False)
    return parser

def prefix_len_by_num_of_ip(num_of_ip: int) -> int:
    bits_needed = math.ceil(math.log2(num_of_ip))
    prefix_length = 32 - bits_needed
    return prefix_length

def fetch_organization_info(prefix_notation: str) -> str:
    url = f"https://stat.ripe.net/data/whois/data.json?resource={prefix_notation}"
    response = requests.get(url, timeout=10)
    response.raise_for_status()
    response_json = response.json()
    if data := response_json.get('data'):
        for record in data['records']:
            for entry in record:
                if entry.get('key') == 'NetName':
                    return entry.get('value', 'Unknown organization')
    return 'Unknown organization'


def process_ip_range(ip_address: str, length: int, fetch_org_info: bool) -> dict:
    ip_version = ipaddress.ip_address(ip_address).version

    if ip_version == 4:
        length = prefix_len_by_num_of_ip(length)

    prefix_notation = ipaddress.ip_network((ip_address, length))

    org_info = None
    if fetch_org_info:
        org_info = fetch_organization_info(prefix_notation)

    return {"prefix_notation": prefix_notation,
            "length": length,
            "version": ip_version,
            "org_info": org_info}

def prefix_info_list_to_file(ip_info_list: list, filename: str) -> None:
    total_ip_addresses = 0
    with open(filename, 'w') as file:
        for ip_info in ip_info_list:
            line = ip_info["prefix_notation"]
            if ip_info['org_info']:
                line += f" | {ip_info['org_info']}"
            
            if ip_info['version'] == 4:
                total_ip_addresses += 2**(32 - ip_info['length'])
            else:
                total_ip_addresses += 2**(128 - ip_info['length'])

            file.write(f"{line}\n")
            # Print the total number of IP addresses
        file.write(f"Total IP addresses: {total_ip_addresses}")

# callback function for c.XFERINFOFUNCTION
def status(download_t, download_d, upload_t, upload_d) -> None:
    # use kiB's
    kb = 1024

    STREAM.write('Downloading: {}/{} kiB ({}%)\r'.format(
        str(int(download_d/kb)),
        str(int(download_t/kb)),
        str(int(download_d/download_t*100) if download_t > 0 else 0)
    ))
    STREAM.flush()

def fetch(url: str, progress: bool = None) -> bytes:
    b_obj = BytesIO() 
    crl = pycurl.Curl() 

    # Set URL value
    crl.setopt(crl.URL, url)

    # Write bytes that are utf-8 encoded
    crl.setopt(crl.WRITEDATA, b_obj)

    if progress:
        # display progress
        crl.setopt(crl.NOPROGRESS, False)
        crl.setopt(crl.XFERINFOFUNCTION, status)

    # Perform a file transfer 
    crl.perform() 

    # End curl session
    crl.close()

    # Get the content stored in the BytesIO object (in byte characters) 
    return b_obj.getvalue()


def main() -> None:
    # cli arguments
    parser = init_argparse()
    args = parser.parse_args()

    # Convert list to piped string for regex
    country_code = ""
    if len(args.country_code) != 1:
        for cc in args.country_code[:-1]:
            country_code += f"{cc}|"
    country_code += args.country_code[-1]

    ip_version = ""
    if len(args.ip_version) != 1:
        for version in args.ip_version[:-1]:
            ip_version += f"{version}|"
    ip_version += str(args.ip_version[-1])

    prefix_type = ""
    if len(args.prefix_type) != 1:
        for type in args.prefix_type[:-1]:
            prefix_type += f"{type}|"
    prefix_type += args.prefix_type[-1]
    
    regex = f"(.*?)\|({country_code})\|(ipv{ip_version})\|(.*?)\|(.*?)\|(.*?)\|({prefix_type})\|(.*?)"

    records = []
    for rir in args.rir:
        data = fetch(rir_stat_urls[rir], progress=args.progress).decode('utf8')
        regex_match = re.findall(regex, data)
        records.extend(regex_match)
    # Free memory
    del data, regex_match

    results = []
    # Use ThreadPoolExecutor to fetch data concurrently
    with ThreadPoolExecutor(max_workers=40) as executor:
        futures = [executor.submit(process_ip_range, record[3], int(record[4]), args.org_info) for record in records]
        progress_desc = f"Processing data from retrieved Database..."
        for future in tqdm(as_completed(futures), total=len(futures), desc=progress_desc):
            results.append(future.result())

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"results_{timestamp}.txt"
        prefix_info_list_to_file(results, filename)
        print(f"Results have been written to {filename}")

if __name__ == "__main__":
    main()

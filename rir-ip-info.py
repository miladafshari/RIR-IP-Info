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
        description="Fetch and display IP Prefixes (IPv4, IPv6) and, organization information (netname, status) associated with RIR IP ranges."
    )

    parser.add_argument('-r', '--rir', type=str.lower, choices=rir_stat_urls.keys(), nargs='+', required=True)
    parser.add_argument('-c', '--country_code', type=str.upper, choices=countries_by_alpha2.keys(), nargs='+', required=True)
    parser.add_argument('-v', '--ip_version', type=int, choices=[4,6], nargs='*', default=[4,6])
    parser.add_argument('-t', '--prefix_type', type=str.lower, choices=["allocated", "assigned"], nargs='+', required=True)
    parser.add_argument('-o', '--org_info', type=str.lower, choices=["netname", "status"], nargs='+', required=False, default=[])
    parser.add_argument('-p', '--progress', action='store_true', required=False, default=False)
    return parser

def prefix_len_by_num_of_ip(num_of_ip: int) -> list:
    prefixes = []
    log2 = math.log2(num_of_ip)
    bits_needed = math.floor(log2)
    prefixes.append(32 - bits_needed)
    if log2 != bits_needed:
        remainder_num_of_ip = num_of_ip - (2 ** bits_needed)
        prefixes.extend(prefix_len_by_num_of_ip(remainder_num_of_ip))
    return prefixes

def fetch_ripe_whois(prefix_notation: str) -> dict:
    url = f"https://stat.ripe.net/data/whois/data.json?resource={prefix_notation}"
    try:
        response = requests.get(url, timeout=10)
    except:
        return None

    # Free unused
    del url
    response.raise_for_status()
    response_json = response.json()

    # Free unused
    del response

    if response_json.get('status') == "ok" and response_json.get('status_code') == 200:
        return response_json['data']
    return None

def fetch_organization_info(prefix_notation: str, org_info: dict) -> dict:
    info_fields = list(org_info.keys())
    if whois := fetch_ripe_whois(prefix_notation):
        for record in whois['records']:
            for entry in record:
                for field in info_fields:
                    if entry.get('key') == field:
                        org_info[field] = entry.get('value', 'Unknown')
                        info_fields.remove(field)
                        break
    return org_info


def process_ip_range(ip_address: str, length: int, org_info_fields: list) -> list:
    ip_version = ipaddress.ip_address(ip_address).version

    if ip_version == 4:
        length_list = prefix_len_by_num_of_ip(length)
    else:
        length_list = [length]

    json_list = []
    next_ip = curr_ip = ipaddress.ip_address(ip_address)
    for len in length_list:

        if ip_version == 4:
            num_of_ip = 2 ** (32 - len)
            curr_ip = next_ip
            next_ip = ipaddress.ip_address(next_ip) + num_of_ip

        prefix_notation = ipaddress.ip_network((curr_ip, len), strict=False)

        org_info = dict()
        for key in org_info_fields:
            org_info[key] = None

        if org_info_fields:
            org_info = fetch_organization_info(str(prefix_notation), org_info)

        json = {
            "prefix_notation": prefix_notation,
            "length": len,
            "version": ip_version
        }
        json.update(org_info)
        json_list.append(json)
    
    return json_list

def prefix_info_list_to_file(ip_info_list: list, org_info_fields: list, filename: str) -> None:
    total_ip_addresses = 0
    with open(filename, 'w') as file:
        for ip_info in ip_info_list:
            line = str(ip_info["prefix_notation"])
            for field in org_info_fields:
                line += f" | {ip_info[field]}"
            
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
            results.extend(future.result())

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"results_{timestamp}.txt"
        prefix_info_list_to_file(results, args.org_info, filename)
        print(f"Results have been written to {filename}")

if __name__ == "__main__":
    main()

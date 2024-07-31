import subprocess
import ipaddress
import math
import requests
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from tqdm import tqdm

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

def process_ip_range(line, ip_version, fetch_org_info):
    try:
        ip, value = line.strip().split('|')
        if ip_version == 'ipv4':
            num_addresses = int(value)
            prefix_notation = ip_to_prefix(ip, num_addresses, ip_version)
        else:
            prefix_length = int(value)
            prefix_notation = ip_to_prefix(ip, prefix_length, ip_version)
        
        if fetch_org_info:
            org_info = fetch_organization_info(prefix_notation)
            return (prefix_notation, org_info, num_addresses if ip_version == 'ipv4' else prefix_length)
        else:
            return (prefix_notation, None, num_addresses if ip_version == 'ipv4' else prefix_length)
    except ValueError as e:
        print(f"ValueError: {e}")
        return None

def main():
    rirs = {
        "ripe ncc": "ftp://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest",
        "afrinic": "ftp://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-extended-latest",
        "apnic": "ftp://ftp.apnic.net/pub/stats/apnic/delegated-apnic-extended-latest",
        "lacnic": "ftp://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-extended-latest",
        "arin": "ftp://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest"
    }

    # Prompt for RIR
    rir = input("Enter the RIR (e.g., RIPE NCC, AFRINIC, APNIC, LACNIC, ARIN): ").strip().lower()
    if rir == 'ripe':
        rir = 'ripe ncc'
    if rir not in rirs:
        print("Invalid RIR.")
        return
    
    # Prompt for country code
    country_code = input("Enter the country code (e.g., IR for Iran): ").strip().upper()
    if not country_code:
        print("Invalid country code.")
        return

    # Prompt for IP prefix type
    prefix_type = input("Enter the prefix type (Allocated/Assigned PI): ").strip().lower()
    if prefix_type not in ["allocated", "assigned pi", "assigned"]:
        print("Invalid prefix type.")
        return
    if prefix_type == "assigned pi":
        prefix_type = "assigned"

    # Prompt for IP version
    ip_version = input("Enter the IP version (IPv4/IPv6): ").strip().lower()
    if ip_version not in ["ipv4", "ipv6"]:
        print("Invalid IP version.")
        return

    # Prompt for fetching organization info
    fetch_org_info = input("Do you want to fetch organization info? (yes/no): ").strip().lower()
    if fetch_org_info not in ["yes", "no"]:
        print("Invalid input.")
        return
    fetch_org_info = fetch_org_info == "yes"

    # Create the curl command with the specified RIR, country code, prefix type, and IP version
    curl_command = f"curl {rirs[rir]} | grep -i '{prefix_type}' | grep -i {country_code} | grep -i {ip_version} | cut -f4,5 -d'|'"
    
    try:
        # Execute the curl command and capture the output
        process = subprocess.Popen(curl_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()

        if process.returncode != 0:
            print(f"Error executing command: {stderr.decode().strip()}")
            return

        # Process the output
        lines = stdout.decode().strip().split('\n')

        total_ip_addresses = 0
        results = []

        # Use ThreadPoolExecutor to fetch data concurrently
        with ThreadPoolExecutor(max_workers=40) as executor:
            futures = [executor.submit(process_ip_range, line, ip_version, fetch_org_info) for line in lines]
            progress_desc = f"Retrieving data from {rir.upper()} Database..."
            for future in tqdm(as_completed(futures), total=len(futures), desc=progress_desc):
                result = future.result()
                if result:
                    prefix_notation, org_info, num_addresses_or_prefix_length = result
                    if fetch_org_info:
                        results.append(f"{prefix_notation} | {org_info}")
                    else:
                        results.append(f"{prefix_notation}")
                    
                    if ip_version == 'ipv4':
                        total_ip_addresses += num_addresses_or_prefix_length
                    else:
                        total_ip_addresses += 2**(128 - num_addresses_or_prefix_length)

        # Print the total number of IP addresses
        results.append(f"Total IP addresses: {total_ip_addresses}")

        # Write results to a file with a timestamp, country code, prefix type, IP version, and RIR name
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"results_{rir.replace(' ', '_').upper()}_{country_code}_{prefix_type.replace(' ', '_')}_{ip_version}_{timestamp}.txt"
        with open(filename, 'w') as file:
            file.write("\n".join(results))
        
        print(f"Results have been written to {filename}")

    except Exception as e:
        print(f"Exception occurred: {e}")

if __name__ == "__main__":
    main()

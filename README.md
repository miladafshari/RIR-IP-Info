# RIR IP Info

![Python Version](https://img.shields.io/badge/Python-3.8-blue.svg)
[![GitHub issues](https://img.shields.io/github/issues/miladafshari/RIR-IP-Info.svg)](https://github.com/miladafshari/RIR-IP-Info/issues)
[![GitHub forks](https://img.shields.io/github/forks/miladafshari/RIR-IP-Info.svg)](https://github.com/miladafshari/RIR-IP-Info/network)
[![GitHub stars](https://img.shields.io/github/stars/miladafshari/RIR-IP-Info.svg)](https://github.com/miladafshari/RIR-IP-Info/stargazers)

## A network information extractor from RIR

This project provides a Python script to process IP ranges from various Regional Internet Registries (RIRs). It allows you to fetch and display IP Prefixes (IPv4, IPv6) and, optionally, organization information associated with these IP ranges. The script supports multiple RIRs, including RIPE NCC, AFRINIC, APNIC, LACNIC, and ARIN.
This project is useful for network administrators, researchers, and IT professionals who need to analyze and manage IP address allocations across different regions.

## Installation

### GitHub

To get started with the project, follow these steps:

```sh
git clone https://github.com/miladafshari/RIR-IP-Info.git
cd RIR-IP-Info
sudo make depends
make install
```

## Usage

1. Run the Script: Execute the Python script from the command line:

```sh
rir-ip-info -h
```

### Help

The script will accept the following arguments:

   `-r`/`--rir`: Enter the Regional Internet Registry (e.g., RIPE, AFRINIC, APNIC, LACNIC, ARIN).

   `-c`/`--country_code` Enter the country code (e.g., IR for Iran).

   `-t`/`--prefix_type` Enter the type of prefix (Allocated/Assigned).

   `-v`/`--ip_version` Enter the IP version (4/6).

   `-o`/`--org_info` Choose whether to fetch organization information.

   `-p`/`--progress` Choose whether to fetch organization information.

   Note: You can pass mutiple values to `-r`, `-c`, `-t`, and `-v`.

## Output Files

The results will be saved to a file named according to the format:

``results_{timestamp}.txt``















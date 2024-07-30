# RIR-IP-Info
This project provides a Python script to process IP ranges from various Regional Internet Registries (RIRs). It allows you to fetch and display IP Prefixes (IPv4, IPv6) and, optionally, organization information associated with these IP ranges. The script supports multiple RIRs, including RIPE NCC, AFRINIC, APNIC, LACNIC, and ARIN.

This project is useful for network administrators, researchers, and IT professionals who need to analyze and manage IP address allocations across different regions. By providing an automated way to fetch and process IP range data and associated organization information, the script simplifies the task of managing IP resources and understanding their distribution. It helps in network planning, IP address management, and provides insights into the organizations that own specific IP ranges.

# How Users Can Get Started with the Project?
To get started with the project, follow these steps:
1. Clone the Repository:
 ``git clone https://github.com/miladafshari/RIR-IP-Info.git``
2. Navigate to the Project Directory:
 ``cd RIR-IP-Info``
3. Install Required Python Packages:
   Ensure you have Python 3.6 or later installed, then install the dependencies using pip:
``pip install -r requirements.txt``

# Usage
1. Run the Script:
Execute the Python script from the command line:
``python3 RIR-IP-Info.py``
2. Follow the Prompts:<br/>
   The script will prompt you for the following information:<br/>
RIR: Enter the Regional Internet Registry (e.g., RIPE NCC, AFRINIC, APNIC, LACNIC, ARIN).<br/>
Country Code: Enter the country code (e.g., IR for Iran).<br/>
Prefix Type: Enter the type of prefix (Allocated/Assigned PI).<br/>
IP Version: Enter the IP version (IPv4/IPv6).<br/>
Fetch Organization Info: Choose whether to fetch organization information (yes/no).<br/>

# Output Files
The results will be saved to a file named according to the format:<br/>
``results_{RIR}_{country_code}_{prefix_type}_{ip_version}_{timestamp}.txt``















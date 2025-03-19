import requests
import json

# API Keys (Replace with your own)
VIRUSTOTAL_API_KEY = "15a150134e14b00a811c106da03ebfbf3866998d58647c3ad7cde538b3611c34"
ABUSEIPDB_API_KEY = "78d18a8dd77b9db8fd243cb65546befe40f238f2298b5dac7bd838b30ef93f2e2ab3a4f6d6e13711"
GREYNOISE_API_KEY = "BXLX9dc3pufQ6kNLpG1xy4qxFOYBh3oQLbpu3ERxLB1DKtr0btAkZhTuEGKddMMW"

# Function to check IP reputation using AbuseIPDB
def check_ip_abuseipdb(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Accept": "application/json",
        "Key": ABUSEIPDB_API_KEY
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }
    response = requests.get(url, headers=headers, params=params)
    return response.json()

# Function to check IP reputation using GreyNoise
def check_ip_greynoise(ip):
    url = f"https://api.greynoise.io/v3/community/{ip}"
    headers = {
        "Accept": "application/json",
        "key": GREYNOISE_API_KEY
    }
    response = requests.get(url, headers=headers)
    return response.json()

# Function to check IP, Domain, or Hash in VirusTotal
def check_virustotal(indicator, indicator_type):
    url = f"https://www.virustotal.com/api/v3/{indicator_type}/{indicator}"
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }
    response = requests.get(url, headers=headers)
    return response.json()

# Function to analyze an IP
def analyze_ip(ip):
    print(f"\n[+] Checking IP Reputation: {ip}")

    # AbuseIPDB Check
    abuseipdb_result = check_ip_abuseipdb(ip)
    print("\n--- AbuseIPDB Result ---")
    print(json.dumps(abuseipdb_result, indent=2))

    # GreyNoise Check
    greynoise_result = check_ip_greynoise(ip)
    print("\n--- GreyNoise Result ---")
    print(json.dumps(greynoise_result, indent=2))

    # VirusTotal Check
    vt_result = check_virustotal(ip, "ip_addresses")
    print("\n--- VirusTotal Result ---")
    print(json.dumps(vt_result, indent=2))

# Function to analyze a domain
def analyze_domain(domain):
    print(f"\n[+] Checking Domain Reputation: {domain}")

    # VirusTotal Check
    vt_result = check_virustotal(domain, "domains")
    print("\n--- VirusTotal Result ---")
    print(json.dumps(vt_result, indent=2))

# Function to analyze a hash
def analyze_hash(file_hash):
    print(f"\n[+] Checking Hash Reputation: {file_hash}")

    # VirusTotal Check
    vt_result = check_virustotal(file_hash, "files")
    print("\n--- VirusTotal Result ---")
    print(json.dumps(vt_result, indent=2))

# Function to get user input and run analysis
def main():
    print("\nThreat Intelligence Tracker")
    print("1. Track Suspicious IP Address")
    print("2. Track Suspicious Domain Name")
    print("3. Track Suspicious File Hash")
    
    choice = input("\nEnter your choice (1/2/3): ")

    if choice == "1":
        ip = input("Enter the suspicious IP address: ")
        analyze_ip(ip)

    elif choice == "2":
        domain = input("Enter the suspicious domain name: ")
        analyze_domain(domain)

    elif choice == "3":
        file_hash = input("Enter the file hash (MD5, SHA1, SHA256): ")
        analyze_hash(file_hash)

    else:
        print("\nInvalid choice! Please enter 1, 2, or 3.")

if __name__ == "__main__":
    main()


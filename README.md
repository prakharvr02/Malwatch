# Malwatch

# ThreatScope

ThreatScope is a **Threat Intelligence Tool** that helps track and analyze **suspicious IPs, domains, and file hashes** using public threat intelligence APIs.

## Features
- Track **IP addresses** using AbuseIPDB, GreyNoise, and VirusTotal  
- Analyze **domain names** for malicious activity  
- Investigate **file hashes** (MD5, SHA1, SHA256) via VirusTotal  
- Simple **command-line interface (CLI)**  
- Uses **environment variables** for API key security  

## Installation
1. **Clone the Repository**  


2. **Set Up API Keys**  
Rename `.env.example` to `.env` and add your API keys:
VIRUSTOTAL_API_KEY=your_virustotal_api_key ABUSEIPDB_API_KEY=your_abuseipdb_api_key GREYNOISE_API_KEY=your_greynoise_api_key

3. **Install Dependencies**  
pip install -r requirements.txt


## Usage
Run the tool and choose an option:
Options:  
1️⃣ Track Suspicious **IP Address**  
2️⃣ Track Suspicious **Domain Name**  
3️⃣ Track Suspicious **File Hash**  

## API Integration
- **AbuseIPDB** – Check IP reputation  
- **GreyNoise** – Classify IPs as benign or malicious  
- **VirusTotal** – Scan domains, hashes, and IPs  

## Contributing
1. Fork the repository  
2. Create a new branch (`git checkout -b feature-name`)  
3. Commit changes (`git commit -m "Added feature XYZ"`)  
4. Push to GitHub (`git push origin feature-name`)  
5. Create a Pull Request  

## License
This project is licensed under the **MIT License**.

---
**Stay Secure! 🚀**

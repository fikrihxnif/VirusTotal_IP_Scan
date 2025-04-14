import csv
import json
import requests
import time
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Get API key from environment variable
apikey = os.getenv('VIRUSTOTAL_API_KEY')

if not apikey:
    raise ValueError("API key not found. Please set VIRUSTOTAL_API_KEY in your .env file.")

# Function to check if an IP address is malicious
def check_ip(ip_address):
    url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip_address}'
    headers = {'x-apikey': apikey}
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        response_json = response.json()
        
        if 'data' not in response_json:
            raise ValueError("Invalid response structure")

        attributes = response_json['data']['attributes']
        as_owner = attributes.get('as_owner')
        country = attributes.get('country')
        reputation = attributes.get('reputation', 'N/A')
        tags = attributes.get('tags', [])
        stat_analysis = attributes.get('last_analysis_stats')

        malicious = stat_analysis.get('malicious', 0)
        suspicious = stat_analysis.get('suspicious', 0)
        undetected = stat_analysis.get('undetected', 0)
        harmless = stat_analysis.get('harmless', 0)

        total = int(malicious) + int(suspicious) + int(undetected) + int(harmless)

        return {
            'IP Address': ip_address,
            'Country': country,
            'Owner': as_owner,
            'Reputation': reputation,
            'Tags': ', '.join(tags),
            'Malicious': malicious,
            'Suspicious': suspicious,
            'Undetected': undetected,
            'Harmless': harmless
        }
    except requests.exceptions.RequestException as e:
        print(f"Request failed for IP {ip_address}: {e}")
        return None
    except ValueError as e:
        print(f"Error processing data for IP {ip_address}: {e}")
        return None

def process_ip_list(input_file, output_file, malicious_output_file):
    try:
        with open(input_file, 'r', encoding='utf-8-sig') as infile:
            reader = csv.DictReader(infile)
            ip_list = list(reader)

        if len(ip_list) > 500:
            print("IP count exceeding VirusTotal rate limit. Checking first 500 IPs.")
            ip_list = ip_list[:500]

        with open(output_file, 'w', newline='', encoding='utf-8') as outfile, \
             open(malicious_output_file, 'w', newline='', encoding='utf-8') as malicious_outfile:
            fieldnames = ['IP Address', 'Country', 'Owner', 'Reputation', 'Tags', 'Malicious', 'Suspicious', 'Undetected', 'Harmless']
            writer = csv.DictWriter(outfile, fieldnames=fieldnames)
            malicious_writer = csv.DictWriter(malicious_outfile, fieldnames=fieldnames)

            writer.writeheader()
            malicious_writer.writeheader()

            total_ips = len(ip_list)
            for index, col in enumerate(ip_list, start=1):
                ip_address = col['IP Address']
                progress = (index / total_ips) * 100
                print(f"Scanning IP {ip_address}... ({progress:.2f}% complete)")

                data = check_ip(ip_address)
                if data:
                    writer.writerow(data)

                    if int(data['Malicious']) > 0 or int(data['Suspicious']) > 0:
                        malicious_writer.writerow(data)

                time.sleep(15)  # Sleep to prevent hitting rate limit

    except FileNotFoundError:
        print("The specified file was not found.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

if __name__ == '__main__':
    # Define file paths
    input_file = r'C:\YourWorkingPath\IP_list.csv'  # Input CSV file path
    output_file = r'C:\YourWorkingPath\IP_score.csv'  # Output CSV file path
    malicious_output_file = r'C:\YourWorkingPath\Malicious_IP_score.csv'  # Output CSV file for malicious and suspicious IPs

    process_ip_list(input_file, output_file, malicious_output_file)
    print("IP scan completed!")

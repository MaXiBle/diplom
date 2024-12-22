import json
import pandas as pd
import requests
from io import BytesIO
import urllib3

# Отключаем предупреждения об SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TECHNIQUES_ENTERPRISE_FILE_URL = "https://attack.mitre.org/docs/enterprise-attack-v16.1/enterprise-attack-v16.1-techniques.xlsx"
ENTERPRISE_XSLX_CASE = 9
TECHNIQUES_MOBILE_FILE_URL = "https://attack.mitre.org/docs/mobile-attack-v16.1/mobile-attack-v16.1-techniques.xlsx"
MOBILE_XSLX_CASE = 10
TECHNIQUES_ICS_FILE_URL = "https://attack.mitre.org/docs/ics-attack-v16.1/ics-attack-v16.1-techniques.xlsx"
ICS_XSLX_CASE = 9
TECHNIQUES_FILE = "C:\\PycharmProjects\\diplom\\CVE2CAPEC\\resources\\techniques_db.json"


# Download the techniques data
def download_techniques(base_url, case):
    try:
        # Make a GET request with SSL verification disabled
        response = requests.get(base_url, verify=False)
        response.raise_for_status()  # Raise an exception for bad responses
        # Load the file into pandas using BytesIO to simulate a file object
        data = pd.read_excel(BytesIO(response.content))

        result = {}
        for i in range(len(data)):
            result[data.iloc[i, 0]] = data.iloc[i, case].split(", ")
        return result
    except Exception as e:
        print(f"Error downloading the data from {base_url}: {str(e)}")
        return {}


# Save the techniques data to a JSON file
def save_json(data):
    with open(TECHNIQUES_FILE, 'w') as f:
        json.dump(data, f, indent=4)


def main():
    print("[!] Загрузка данных для техник MITRE...")
    techniques_data = download_techniques(TECHNIQUES_ENTERPRISE_FILE_URL, ENTERPRISE_XSLX_CASE)
    techniques_data.update(download_techniques(TECHNIQUES_MOBILE_FILE_URL, MOBILE_XSLX_CASE))
    techniques_data.update(download_techniques(TECHNIQUES_ICS_FILE_URL, ICS_XSLX_CASE))

    if techniques_data:
        print("[!] Обновление данных для техник MITRE...")
        save_json(techniques_data)

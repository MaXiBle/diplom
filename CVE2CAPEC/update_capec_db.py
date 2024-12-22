import os
import requests
from zipfile import ZipFile
import csv
import json

CAPEC_FILE_URL = "https://capec.mitre.org/data/csv/1000.csv.zip"
CAPEC_FILE = "C:\\PycharmProjects\\diplom\\CVE2CAPEC\\resources\\capec_db.json"

# Download and extract CAPEC data
def download_capec():
    response = requests.get(CAPEC_FILE_URL)
    with open("1000.csv.zip", 'wb') as f:
        f.write(response.content)
    with ZipFile("1000.csv.zip", 'r') as zip_ref:
        zip_ref.extractall()
    os.remove("1000.csv.zip")
    # Указываем явную кодировку utf-8 при открытии CSV
    with open("1000.csv", 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        capec_list = [row for row in reader]
    os.remove("1000.csv")
    return capec_list


# Format CAPEC data and save to JSON file
def format_capec(capec_list):
    capec_data = {}
    for capec in capec_list:
        capec_data[capec["'ID"]] = {"name": capec["Name"], "techniques": capec["Taxonomy Mappings"]}

    with open(CAPEC_FILE, 'w', encoding='utf-8') as f:  # Сохраняем JSON с utf-8
        json.dump(capec_data, f, indent=4)


def main():
    print("[!] Загрузка данных CAPEC...")
    capec_list = download_capec()
    print("[!] Обновление данных CAPEC...")
    format_capec(capec_list)

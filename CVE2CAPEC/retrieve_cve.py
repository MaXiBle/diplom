import requests
import json
from datetime import datetime
from tqdm import tqdm
from re import match
import os

# Base URL for NVD CVE API
API_CVES = "https://services.nvd.nist.gov/rest/json/cves/2.0/"
UPDATE_FILE = "C:\\PycharmProjects\\diplom\\CVE2CAPEC\\lastUpdate.txt"
CVE_FILE = "C:\\PycharmProjects\\diplom\\CVE2CAPEC\\results\\new_cves.jsonl"

# Parse CVE data from the API
def parse_cves(url: str):
    cve_data = {}
    session = requests.Session()
    response = session.get(url)

    if response.status_code != 200:
        raise Exception("Не удалось загрузить данные CVE")

    # Get the total number of results and the number of results per page
    cves = response.json()
    results_per_page = cves.get("resultsPerPage", 0)
    total_results = cves.get("totalResults", 0)

    if results_per_page == 0 or total_results == 0:
        print("[-] Не найдено новых уязвимостей")
        return cve_data

    # Calculate total number of pages needed based on the results per page
    nb_pages = (total_results + results_per_page - 1) // results_per_page

    # Process each page of the API response
    for page in tqdm(range(nb_pages), desc="Загрузка страниц", unit="Страница"):
        url = f"{url}&resultsPerPage=2000&startIndex={page * 2000}"
        response = session.get(url)
        if response.status_code != 200:
            raise Exception("Не удалось загрузить данные CVE")
        cves = response.json()

        # Process each CVE in the current page
        for cve in tqdm(cves.get("vulnerabilities", []), desc="Обработка CVE", unit="CVE"):
            has_primary_cwe = False
            cve_id = cve.get("cve", {}).get("id", "")
            cwe_list = []
            infos = cve.get("cve", {}).get("weaknesses", [])

            if infos:
                # Process Primary CWE
                for cwe in infos:
                    if cwe.get("type", "") == "Primary":  # Get only primary CWE
                        cwe_code = cwe.get("description", [])[0].get("value", "")
                        if match(r"CWE-\d{1,4}", cwe_code):
                            cwe_list.append(cwe_code.split("-")[1])
                            has_primary_cwe = True

                # If no primary CWE, process Secondary CWE
                if not has_primary_cwe:
                    for cwe in infos:
                        if cwe.get("type", "") == "Secondary":  # Get only secondary CWE
                            cwe_code = cwe.get("description", [])[0].get("value", "")
                            if match(r"CWE-\d{1,4}", cwe_code):
                                cwe_list.append(cwe_code.split("-")[1])

                cve_data[cve_id] = {"CWE": cwe_list}
            else:
                cve_data[cve_id] = {"CWE": []}

    return cve_data


# Load existing CVE data from the JSONL file
def load_existing_cves():
    cve_data = {}
    if os.path.exists(CVE_FILE):
        with open(CVE_FILE, 'r') as f:
            for line in f:
                cve_entry = json.loads(line.strip())
                cve_data.update(cve_entry)
    return cve_data


# Save CVE data to JSONL file (append mode)
def save_jsonl(cve_data, today):
    # Ensure the directory exists
    os.makedirs(os.path.dirname(CVE_FILE), exist_ok=True)

    with open(CVE_FILE, 'a') as f:
        for cve, data in cve_data.items():
            f.write(json.dumps({cve: data}) + "\n")

    # Update the last update date
    with open(UPDATE_FILE, 'w') as f:
        f.write(today)


def main():
    # Get the last update date
    today = datetime.now().isoformat()
    last_update = ""

    # Check if the last update file exists and read the date
    if os.path.exists(UPDATE_FILE):
        with open(UPDATE_FILE, 'r') as f:
            last_update = f.read()
    else:
        # If no last update file, default to a distant past
        last_update = "2000-01-01T00:00:00.000Z"

    # Prepare the API URL with the date range for modified CVEs
    url = f"{API_CVES}?pubStartDate={last_update}&pubEndDate={today}"

    # Parse CVEs from the API
    new_cves_data = parse_cves(url)

    # Load existing CVEs from the JSONL file
    existing_cves_data = load_existing_cves()

    # Filter out the new CVEs that are already in the file
    new_cves_data = {k: v for k, v in new_cves_data.items() if k not in existing_cves_data}

    if new_cves_data:
        # Print message for each new CVE detected
        print(f"[+] Найдено {len(new_cves_data)} новых CVE. Добавляю их в файл.")

        # Save only the new CVEs to the JSONL file
        save_jsonl(new_cves_data, today)

        # Inform the user that the new CVEs have been added
        print(f"[+] Добавлено {len(new_cves_data)} новых CVE.")
    else:
        print("[-] Нет новых CVE для добавления.")
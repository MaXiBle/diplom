import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm

CWE_FILE = "C:\\PycharmProjects\\diplom\\CVE2CAPEC\\resources\\cwe_db.json"
CVE_FILE = "C:\\PycharmProjects\\diplom\\CVE2CAPEC\\results\\new_cves.jsonl"


# Retrieve the CAPEC entries related to a CWE
def fetch_capec_for_cwe(cwe: str, cwe_db: dict):
    try:
        result = cwe_db.get(cwe, {})
        capec_list = result.get("RelatedAttackPatterns", [])
        return capec_list if capec_list else []
    except Exception as e:
        print(f"Exception for CWE-{cwe}: {str(e)}")
        return []


# Process each CWE to extract the related CAPEC entries
def process_cwe_to_capec(cwe_list, cwe_db):
    list_capec = set()
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(fetch_capec_for_cwe, cwe, cwe_db): cwe for cwe in cwe_list}
        for future in as_completed(futures):
            cwe = futures[future]
            try:
                data = future.result()
                list_capec.update(data)
            except Exception as e:
                print(f"Error processing CWE-{cwe}: {str(e)}")
    return list(list_capec)


# Save the results to a JSONL file
def save_jsonl(cve_capec_data):
    with open(CVE_FILE, 'w') as f:
        for cve, data in cve_capec_data.items():
            f.write(json.dumps({cve: data}) + "\n")


# Load the CWE database
def load_db():
    with open(CWE_FILE, 'r') as f:
        cwe_db = json.load(f)
    return cwe_db


def main():
    # Load the JSONL file
    cve_cwe_data = {}
    with open(CVE_FILE, 'r') as f:
        for line in f:
            cve = json.loads(line.strip())
            cve_cwe_data.update(cve)

    if cve_cwe_data:
        cwe_db = load_db()

        # Process each CVE to extract the related CAPEC entries
        cve_capec_data = {}
        for cve in tqdm(cve_cwe_data, desc="Processing CWE to CAPEC for all CVEs", unit="CVE"):
            cwe_list = cve_cwe_data[cve]["CWE"]
            cve_capec_data[cve] = {"CWE": cwe_list}
            cve_capec_data[cve]["CAPEC"] = process_cwe_to_capec(cwe_list, cwe_db)

        save_jsonl(cve_capec_data)
    else:
        print("[-] No CVEs found in the input file")


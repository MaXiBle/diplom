import sys
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm

# Файлы для CAPEC и CVE
CAPEC_FILE = "C:\\PycharmProjects\\diplom\\CVE2CAPEC\\resources\\capec_db.json"
CVE_FILE = "C:\\PycharmProjects\\diplom\\CVE2CAPEC\\results\\new_cves.jsonl"


# Обновляем базу данных CVE и сохраняем результаты в JSONL файл
def save_jsonl(cve_capec_data):
    # Записываем результаты в новый JSONL файл
    with open(CVE_FILE, 'w') as f:
        for cve, data in cve_capec_data.items():
            f.write(json.dumps({cve: data}) + "\n")


# Загружаем базу данных CVE из new_cves.jsonl
def load_db_jsonl():
    cve_db = {}
    try:
        with open(CVE_FILE, 'r') as f:
            for line in f:
                cve_entry = json.loads(line.strip())
                cve_db.update(cve_entry)
    except FileNotFoundError:
        print(f"[-] Файл {CVE_FILE} не найден.")
    return cve_db


# Обрабатываем CVE, чтобы извлечь связанные CAPEC записи
def process_single_cve(cve, capec_list, cve_capec_data):
    technics = set()
    for capec in cve_capec_data[cve]["CAPEC"]:
        lines = capec_list.get(capec, {}).get("techniques", "")
        if lines:
            entries = lines.split("NAME:ATTACK:ENTRY ")[1:]
            for entry in entries:
                infos = entry.split(":")
                id = infos[1]
                technics.add(id)
    return list(sorted(technics))


# Многозадачная обработка CVE и CAPEC
def process_capec(cve_capec_data, capec_list):
    with ThreadPoolExecutor() as executor:
        futures = {executor.submit(process_single_cve, cve, capec_list, cve_capec_data): cve for cve in tqdm(cve_capec_data, desc="Processing CAPEC to TECHNIQUES", unit="CVE")}
        for future in as_completed(futures):
            cve_result = future.result()
            cve_capec_data[futures[future]]["TECHNIQUES"] = cve_result


def main():
    if len(sys.argv) == 2:
        file = sys.argv[1]
    else:
        file = CVE_FILE

    # Загружаем CVE данные из файла
    cve_capec_data = load_db_jsonl()

    if cve_capec_data:
        # Загружаем базу данных CAPEC
        with open(CAPEC_FILE, 'r') as f:
            capec_list = json.load(f)

        # Обрабатываем CAPEC для каждого CVE
        process_capec(cve_capec_data, capec_list)

        # Сохраняем обновленные данные CVE в новый файл
        save_jsonl(cve_capec_data)
    else:
        print("[-] No new vulnerabilities found")
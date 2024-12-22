# 1.5. Получение описаний CVE, CWE, CAPEC и техник Mitre

import os
import re
import csv
import json
import requests
import concurrent
from xml.dom import minidom
from zipfile import ZipFile
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor

def find_and_append_missing_cve_with_descriptions(jsonl_file, csv_file):
    def fetch_cve_description_v2(cve_id):
        API_CVES = "https://services.nvd.nist.gov/rest/json/cves/2.0/"
        """
        Получение описания уязвимости и её CVSS-балла через API NVD версии 2.0.
        :param cve_id: Идентификатор CVE.
        :return: Кортеж (описание, балл CVSS) или сообщение, если данные отсутствуют.
        """
        params = {"cveId": cve_id}
        try:
            response = requests.get(API_CVES, params=params, timeout=10)
            if response.status_code == 200:
                data = response.json()
                if "vulnerabilities" in data and len(data["vulnerabilities"]) > 0:
                    vuln = data["vulnerabilities"][0]
                    descriptions = vuln["cve"]["descriptions"]
                    for desc in descriptions:
                        if desc["lang"] == "en":  # Только описание на английском
                            description = desc["value"]
                            return description
        except Exception as e:
            print(f"Ошибка при запросе {cve_id}: {e}")
        return "Description not available.", 0

    """
    Функция для поиска отсутствующих CVE, получения их описаний через API NVD 2.0 и добавления в CSV.
    :param jsonl_file: Путь к файлу с новыми CVE в формате JSONL.
    :param csv_file: Путь к CSV-файлу с существующими CVE.
    """
    print("[+] Загрузка данных из CSV...")
    existing_cves = set()
    if os.path.exists(csv_file):
        with open(csv_file, "r", encoding="utf-8") as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                existing_cves.add(row["id"])

    print("[+] Загрузка данных из JSONL...")
    new_cves = []
    with open(jsonl_file, "r", encoding="utf-8") as file:
        for line in file:
            cve_entry = json.loads(line.strip())
            new_cves.extend(cve_entry.keys())

    print("[+] Поиск отсутствующих CVE...")
    missing_cves = [cve for cve in new_cves if cve not in existing_cves]
    print(f"[+] Найдено {len(missing_cves)} отсутствующих CVE.")

    if missing_cves:
        print("[+] Получение описаний для отсутствующих CVE...")
        with open(csv_file, "a", encoding="utf-8", newline="") as csvfile:
            fieldnames = ["id", "description"]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            # Если файл пустой, добавляем заголовки
            if os.stat(csv_file).st_size == 0:
                writer.writeheader()

            for cve in tqdm(missing_cves, desc="Обработка CVE"):
                description = fetch_cve_description_v2(cve)
                writer.writerow({"id": cve, "description": description})
                csvfile.flush()  # Сохраняем изменения после каждой записи
    else:
        print("[-] Отсутствующих CVE не найдено.")

def process_capec_data(file_url="https://capec.mitre.org/data/csv/1000.csv.zip", output_file="C:\\PycharmProjects\\diplom\\описание_capec.csv"):
    # 1. Загрузка и извлечение данных CAPEC
    response = requests.get(file_url)
    with open("1000.csv.zip", 'wb') as f:
        f.write(response.content)
    with ZipFile("1000.csv.zip", 'r') as zip_ref:
        zip_ref.extractall()
    os.remove("1000.csv.zip")

    # Считываем извлечённый CSV
    with open("1000.csv", 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        capec_list = [row for row in reader]
    os.remove("1000.csv")

    # 2. Загрузка уже существующих данных из файла
    existing_capec = set()
    if os.path.exists(output_file):
        with open(output_file, 'r', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                existing_capec.add(row["id"])  # Собираем существующие CAPEC ID

    # 3. Добавление новых CAPEC в файл
    with open(output_file, "a", encoding="utf-8", newline="") as csvfile:
        fieldnames = ["id", "description"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        # Если файл пустой, добавляем заголовки
        if os.stat(output_file).st_size == 0:
            writer.writeheader()

        # Обрабатываем и записываем новые CAPEC
        for capec in tqdm(capec_list, desc="Обработка CAPEC"):
            capec_id = capec["'ID"]
            description = capec['Description']
            if capec_id not in existing_capec:
                writer.writerow({"id": capec_id, "description": description})

def fetch_and_save_cwe_descriptions(api_url="http://cwe.mitre.org/data/xml/cwec_latest.xml.zip", output_csv="C:\\PycharmProjects\\diplom\\описание_CWE.csv"):
    print("[!] Загрузка данных CWE...")

    # 1. Загрузка CWE XML файла
    response = requests.get(api_url)
    if response.status_code != 200:
        raise Exception("Не удалось загрузить файл CWE")

    # 2. Сохранение и извлечение XML файла
    zip_file_name = "cwec_latest.xml.zip"
    with open(zip_file_name, 'wb') as f:
        f.write(response.content)

    with ZipFile(zip_file_name, 'r') as zip_ref:
        zip_ref.extractall()
    os.remove(zip_file_name)

    # 3. Поиск извлечённого XML файла
    xml_file_name = re.search(r"cwec_v\d+\.\d+\.xml", " ".join(os.listdir())).group()
    cwe_list = minidom.parse(xml_file_name)
    os.remove(xml_file_name)  # Удаляем XML после обработки

    # 4. Получение существующих CWE из CSV
    existing_cwe_ids = set()
    if os.path.exists(output_csv):
        with open(output_csv, 'r', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                existing_cwe_ids.add(row['id'])

    # 5. Извлечение описаний CWE
    descriptions = []
    weaknesses = cwe_list.getElementsByTagName("Weakness")

    for weakness in weaknesses:
        cwe_id = weakness.getAttribute("ID")
        description = weakness.getElementsByTagName("Description")[
            0].firstChild.nodeValue if weakness.getElementsByTagName("Description") else "Нет описания"

        # Проверка на существование CWE в файле
        if cwe_id not in existing_cwe_ids:
            descriptions.append((cwe_id, description))

    # 6. Сохранение новых описаний в CSV
    new_cwe_count = 0
    if descriptions:
        with open(output_csv, 'a', encoding='utf-8',
                  newline='') as csvfile:  # Используем 'a' для добавления новых строк
            fieldnames = ['id', 'description']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

            for cwe_id, description in descriptions:
                writer.writerow({'id': cwe_id, 'description': description})
                new_cwe_count += 1

    # 7. Вывод общего результата
    print(f"[!] Всего новых CWE добавлено: {new_cwe_count}")

def fetch_and_save_mitre_techniques(json_files, output_csv="C:\\PycharmProjects\\diplom\\описание_technique.csv", max_workers=4):
    def get_technique_description(obj, external_id):
        """Извлекает описание техники по объекту JSON."""
        for ref in obj.get("external_references", []):
            if ref.get("external_id") == external_id:
                return obj.get('description', 'Нет данных')
        return None

    def process_object(obj, external_ids):
        """Обрабатывает объект JSON и возвращает ID и описание, если ID отсутствует в CSV."""
        if obj.get("type") != "attack-pattern":
            return None
        for ref in obj.get("external_references", []):
            external_id = ref.get("external_id")
            if external_id and external_id not in external_ids:
                description = get_technique_description(obj, external_id)
                if description:
                    return external_id, description
        return None

    """Основная функция для сохранения отсутствующих техник."""
    print("[!] Загрузка данных MITRE...")

    # 1. Проверка существования файлов JSON
    for json_file in json_files:
        if not os.path.exists(json_file):
            raise FileNotFoundError(f"Файл {json_file} не найден!")

    # 2. Получение существующих техник из CSV
    existing_technique_ids = set()
    if os.path.exists(output_csv):
        with open(output_csv, 'r', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                existing_technique_ids.add(row['id'])

    # 3. Загрузка всех объектов из всех JSON-файлов
    all_objects = []
    for json_file in json_files:
        with open(json_file, 'r', encoding='utf-8') as file:
            data = json.load(file)
            all_objects.extend(data.get("objects", []))

    # 4. Обработка объектов с использованием многопоточности
    techniques_to_add = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(process_object, obj, existing_technique_ids): obj for obj in all_objects}
        for future in tqdm(concurrent.futures.as_completed(futures), total=len(all_objects), desc="Обработка техник"):
            result = future.result()
            if result:
                techniques_to_add.append(result)

    # 5. Сохранение новых техник в CSV
    new_technique_count = 0
    if techniques_to_add:
        with open(output_csv, 'a', encoding='utf-8', newline='') as csvfile:
            fieldnames = ['id', 'description']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

            # Добавляем заголовок, если файл только что создан
            if os.stat(output_csv).st_size == 0:
                writer.writeheader()

            for technique_id, description in tqdm(techniques_to_add, desc="Сохранение техник"):
                writer.writerow({
                    'id': technique_id,
                    'description': description
                })
                new_technique_count += 1

    # 6. Вывод общего результата
    print(f"[!] Всего новых техник добавлено: {new_technique_count}")

def main():
    find_and_append_missing_cve_with_descriptions(
        "C:\\PycharmProjects\\diplom\\CVE2CAPEC\\results\\new_cves.jsonl",
        "C:\\PycharmProjects\\diplom\\описание_cve.csv"
    )

    process_capec_data()

    fetch_and_save_cwe_descriptions()

    # Выполнение функции
    fetch_and_save_mitre_techniques([
        "C:\PycharmProjects\diplom\CVE2CAPEC\\resources\capec_db.json",
        "C:\PycharmProjects\diplom\CVE2CAPEC\\resources\cwe_db.json",
        "C:\PycharmProjects\diplom\CVE2CAPEC\\resources\\techniques_association.json",
        "C:\PycharmProjects\diplom\CVE2CAPEC\\resources\\techniques_db.json"
    ])


main()
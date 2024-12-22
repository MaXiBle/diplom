import xml.etree.ElementTree as ET
import csv

def load_cve_descriptions(csv_file_path):
    """
    Загружает описания CVE из CSV-файла.

    :param csv_file_path: Путь к CSV-файлу.
    :return: Словарь, где ключ - CVE, значение - описание.
    """
    cve_descriptions = {}
    try:
        with open(csv_file_path, mode='r', encoding='utf-8') as csv_file:
            reader = csv.DictReader(csv_file)
            for row in reader:
                cve_id = row.get("id")
                description = row.get("description")
                if cve_id and description:
                    cve_descriptions[cve_id] = description
    except Exception as e:
        print(f"Ошибка при загрузке CSV: {e}")
    return cve_descriptions

def get_cves_with_descriptions(cwe_list, xml_file_path, csv_file_path):
    """
    Извлекает уникальные CVE для указанных CWE из XML-файла с учетом пространства имен
    и добавляет описание из CSV-файла.

    :param cwe_list: Список идентификаторов CWE.
    :param xml_file_path: Путь к файлу cwe.xml.
    :param csv_file_path: Путь к файлу описание.csv.
    :return: Список уникальных кортежей (CVE, описание).
    """
    # Пространство имен
    namespace = {'cwe': 'http://cwe.mitre.org/cwe-7'}
    unique_cves = set()
    result = []

    # Загрузка описаний CVE
    cve_descriptions = load_cve_descriptions(csv_file_path)

    try:
        # Парсим XML файл
        tree = ET.parse(xml_file_path)
        root = tree.getroot()

        # Проходим по всем элементам Weakness
        for weakness in root.findall(".//cwe:Weakness", namespace):
            cwe_id = weakness.get("ID")
            if cwe_id in cwe_list:
                # Найти примеры Observed_Examples и извлечь ссылки на CVE
                observed_examples = weakness.find("cwe:Observed_Examples", namespace)
                if observed_examples:
                    for example in observed_examples.findall("cwe:Observed_Example", namespace):
                        reference = example.find("cwe:Reference", namespace)
                        if reference is not None and reference.text.startswith("CVE-"):
                            cve_id = reference.text
                            if cve_id not in unique_cves:  # Проверка на уникальность
                                unique_cves.add(cve_id)
                                description = cve_descriptions.get(cve_id, "Описание не найдено")
                                result.append((cve_id, description))
    except Exception as e:
        print(f"Ошибка при обработке файла: {e}")

    return result


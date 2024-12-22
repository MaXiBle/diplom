import json
import os

def merge_capec_and_cwe(capec_json_path, cwe_json_path, cve_files_dir, output_json_path):
    # Чтение данных из файла capec_relationship.json
    with open(capec_json_path, 'r', encoding='utf-8') as capec_file:
        capec_data = json.load(capec_file)
    
    # Чтение данных из файла cwe_relationship.json
    with open(cwe_json_path, 'r', encoding='utf-8') as cwe_file:
        cwe_data = json.load(cwe_file)
    
    # Создаем словарь для быстрого доступа по ID в cwe_data
    cwe_dict = {item["ID"]: item for item in cwe_data}
    
    # Пример данных для Observed_Examples (добавляем вручную или из другого источника)
    observed_examples_data = [
        {
            "Reference": "CVE-2022-24045",
            "Description": "Web application for a room automation system has client-side Javascript that sets a sensitive cookie without the HTTPOnly security attribute, allowing the cookie to be accessed."
        },
        {
            "Reference": "CVE-2014-3852",
            "Description": "CMS written in Python does not include the HTTPOnly flag in a Set-Cookie header, allowing remote attackers to obtain potentially sensitive information via script access to this cookie."
        },
        {
            "Reference": "CVE-2015-4138",
            "Description": "Appliance for managing encrypted communications does not use HttpOnly flag."
        }
    ]
    
    # Создаем словарь для быстрого поиска CVE по ID
    cve_dict = {}
    for filename in os.listdir(cve_files_dir):
        if filename.endswith(".json"):
            file_path = os.path.join(cve_files_dir, filename)
            with open(file_path, 'r', encoding='utf-8') as cve_file:
                cve_data = json.load(cve_file)
                for item in cve_data.get("CVE_Items", []):
                    cve_id = item["cve"]["CVE_data_meta"]["ID"]
                    cve_dict[cve_id] = item  # Сохраняем CVE по ID для быстрого поиска
    
    # Проходим по всем CAPEC записям и добавляем связанные данные из CWE
    for capec_item in capec_data:
        # Проверяем, что Related_Weaknesses существует и является списком
        related_weaknesses = capec_item.get("Related_Weaknesses", [])
        if not isinstance(related_weaknesses, list):
            related_weaknesses = []

        # Извлекаем дополнительные данные, такие как Taxonomy_Mappings, Mitigations, Examples
        taxonomy_mappings = capec_item.get("Taxonomy_Mappings", [])
        mitigations = capec_item.get("Mitigations", [])
        examples = capec_item.get("Examples", [])
        
        # Проходим по всем CWE, добавляем соответствующие данные
        extended_weaknesses = []
        for cwe_id in related_weaknesses:
            if cwe_id in cwe_dict:
                cwe_item = cwe_dict[cwe_id]
                
                # Обрабатываем Observed_Examples
                observed_examples = observed_examples_data
                for example in observed_examples:
                    cve_reference = example["Reference"]
                    if cve_reference in cve_dict:  # Если нашли соответствие CVE
                        cve_item = cve_dict[cve_reference]
                        mitigation_links = []
                        # Извлекаем ссылки на исправления (mitigations) из "references"
                        if "references" in cve_item["cve"]:
                            for ref in cve_item["cve"]["references"]["reference_data"]:
                                if "url" in ref:
                                    mitigation_links.append(ref["url"])
                        # Добавляем ссылки как mitigations для соответствующего примера
                        if mitigation_links:
                            example["Mitigations"] = mitigation_links
                
                extended_weaknesses.append({
                    "CWE_ID": cwe_item["ID"],
                    "Name": cwe_item.get("Name", ""),
                    "Description": cwe_item.get("Description", ""),
                    "Detection_Methods": cwe_item.get("Detection_Methods", ""),
                    "Potential_Mitigations": cwe_item.get("Potential_Mitigations", ""),
                    "Observed_Examples": observed_examples
                })
        
        # Обновляем запись CAPEC с новыми полями в нужном порядке
        capec_item["Taxonomy_Mappings"] = taxonomy_mappings
        capec_item["Mitigations"] = mitigations
        capec_item["Examples"] = examples
        if extended_weaknesses:
            capec_item["Related_Weaknesses"] = extended_weaknesses
        else:
            capec_item["Related_Weaknesses"] = []

    # Записываем обновленные данные в выходной файл JSON
    with open(output_json_path, 'w', encoding='utf-8') as output_file:
        json.dump(capec_data, output_file, ensure_ascii=False, indent=4)

    print(f"Данные из CAPEC и CWE объединены и записаны в файл {output_json_path}.")

# Пути к файлам
capec_file = "capec_relationship.json"  # Путь к файлу capec_relationship.json
cwe_file = "cwe_relationship.json"  # Путь к файлу cwe_relationship.json
cve_files_dir = "cve_files"  # Путь к папке с CVE файлами (например, nvdcve-1.1-2002.json и т.д.)
output_file = "merged_capec_cwe.json"  # Путь к выходному JSON файлу

# Выполнение объединения
merge_capec_and_cwe(capec_file, cwe_file, cve_files_dir, output_file)

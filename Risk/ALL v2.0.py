import json
import os
from collections import defaultdict

def merge_capec_and_cwe_with_cve(capec_json_path, cwe_json_path, cve_folder_path, output_json_path):
    # Чтение данных из файла capec_relationship.json
    with open(capec_json_path, 'r', encoding='utf-8') as capec_file:
        capec_data = json.load(capec_file)
    
    # Чтение данных из файла cwe_relationship.json
    with open(cwe_json_path, 'r', encoding='utf-8') as cwe_file:
        cwe_data = json.load(cwe_file)
    
    # Создаем словарь для быстрого доступа по ID в cwe_data
    cwe_dict = {item["ID"]: item for item in cwe_data}
    
    # Читаем все файлы CVE из папки
    cve_references = {}
    for file_name in os.listdir(cve_folder_path):
        file_path = os.path.join(cve_folder_path, file_name)
        if os.path.isfile(file_path) and file_name.endswith('.json'):
            with open(file_path, 'r', encoding='utf-8') as cve_file:
                cve_data = json.load(cve_file)
                # Извлекаем ID и URL из CVE файлов
                for cve_item in cve_data.get("CVE_Items", []):
                    cve_id = cve_item.get("cve", {}).get("CVE_data_meta", {}).get("ID")
                    references = cve_item.get("cve", {}).get("references", {}).get("reference_data", [])
                    for ref in references:
                        if cve_id:
                            cve_references[cve_id] = ref.get("url")

    # Создаем список для хранения итоговых данных
    result_data = []
    
    # Группируем CAPEC по Entry_ID
    taxonomy_grouped = defaultdict(list)
    
    # Проходим по всем CAPEC записям
    for capec_item in capec_data:
        # Получаем CAPEC_ID
        capec_id = capec_item.get("ID") or capec_item.get("CAPEC_ID")
        
        if capec_id is None:
            print(f"Warning: 'ID' or 'CAPEC_ID' is missing or None in CAPEC item: {capec_item}")
        
        # Извлекаем Taxonomy_Mappings, если оно существует
        taxonomy_mappings = capec_item.get("Taxonomy_Mappings", [])
        if taxonomy_mappings is None:
            taxonomy_mappings = []  # Если None, то заменяем на пустой список
        
        # Инициализация информации для записи
        info = {
            "CAPEC_ID": capec_id,
            "Name": capec_item.get("Name", ""),
            "Description": (capec_item.get("Description", "") or "").strip(),  # Проверка на None
            "Mitigations": capec_item.get("Mitigations", []),
            "Examples": capec_item.get("Examples", []),
            "Related_Weaknesses": []
        }
        
        # Процесс добавления связей с CWE
        related_weaknesses = capec_item.get("Related_Weaknesses", [])
        for cwe_item in related_weaknesses:
            if isinstance(cwe_item, dict):  # Если это словарь, то данные уже есть
                info["Related_Weaknesses"].append(cwe_item)
            elif isinstance(cwe_item, str):  # Если это строка (CWE_ID), ищем в словаре cwe_dict
                if cwe_item in cwe_dict:
                    cwe_item_data = cwe_dict[cwe_item]
                    info["Related_Weaknesses"].append({
                        "CWE_ID": cwe_item_data["ID"],
                        "Name": cwe_item_data.get("Name", ""),
                        "Description": cwe_item_data.get("Description", ""),
                        "Detection_Methods": cwe_item_data.get("Detection_Methods", []),
                        "Potential_Mitigations": cwe_item_data.get("Potential_Mitigations", []),
                        "Observed_Examples": cwe_item_data.get("Observed_Examples", [])
                    })
                else:
                    print(f"Warning: CWE_ID {cwe_item} not found in CWE data.")

        # Добавляем URL в Description для Observed_Examples
        for example in info["Examples"]:
            if "Reference" in example and example["Reference"] in cve_references:
                url = cve_references[example["Reference"]]
                example["Description"] += f" (URL: {url})"
        
        # Группируем Taxonomy_Mappings по Entry_ID
        for taxonomy in taxonomy_mappings:
            taxonomy_name = taxonomy.get("Taxonomy_Name")
            entry_id = taxonomy.get("Entry_ID")
            
            if taxonomy_name and entry_id:
                # Вставляем INFO в сам Taxonomy_Mapping
                if taxonomy_name == "ATTACK":
                    if any(t['Entry_ID'] == entry_id for t in taxonomy_grouped[entry_id]):
                        # Если Entry_ID уже есть, добавляем в существующий INFO
                        for existing_entry in taxonomy_grouped[entry_id]:
                            if existing_entry["Entry_ID"] == entry_id:
                                existing_entry["INFO"].append(info)
                    else:
                        # Если Entry_ID еще нет, создаем новую запись
                        taxonomy_grouped[entry_id].append({
                            "Taxonomy_Name": taxonomy_name,
                            "Entry_ID": entry_id,
                            "Entry_Name": taxonomy.get("Entry_Name", ""),
                            "INFO": [info]  # Оборачиваем INFO в список
                        })
            else:
                print(f"Warning: Missing 'Taxonomy_Name' or 'Entry_ID' in Taxonomy: {taxonomy}")
        
    # Формируем финальные записи для вывода
    for entry_id, taxonomy_entries in taxonomy_grouped.items():
        result_data.append({
            "Taxonomy_Mappings": taxonomy_entries
        })
    
    # Записываем результат в выходной JSON файл
    with open(output_json_path, 'w', encoding='utf-8') as output_file:
        json.dump(result_data, output_file, ensure_ascii=False, indent=4)

    print(f"Данные записаны в файл {output_json_path}.")

# Пути к файлам
capec_file = "capec_relationship.json"
cwe_file = "cwe_relationship.json"
cve_folder = "cve_files"
output_file = "capec_with_grouped_entry_id_with_urls.json"

# Выполнение
merge_capec_and_cwe_with_cve(capec_file, cwe_file, cve_folder, output_file)

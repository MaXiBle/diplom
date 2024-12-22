import json
import os

def merge_capec_and_cwe(capec_json_path, cwe_json_path, output_json_path):
    # Чтение данных из файла capec_relationship.json
    with open(capec_json_path, 'r', encoding='utf-8') as capec_file:
        capec_data = json.load(capec_file)
    
    # Чтение данных из файла cwe_relationship.json
    with open(cwe_json_path, 'r', encoding='utf-8') as cwe_file:
        cwe_data = json.load(cwe_file)
    
    # Создаем словарь для быстрого доступа по ID в cwe_data
    cwe_dict = {item["ID"]: item for item in cwe_data}
    
    # Создаем список для хранения итоговых данных
    result_data = []
    
    # Проходим по всем CAPEC записям
    for capec_item in capec_data:
        # Получаем CAPEC_ID, используем его как запасное, если 'ID' отсутствует
        capec_id = capec_item.get("ID") or capec_item.get("CAPEC_ID")
        
        # Выводим отладочную информацию, чтобы увидеть значение CAPEC_ID
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
        
        # Если Related_Weaknesses пустое, то добавляем объект с дефолтными значениями
        related_weaknesses = capec_item.get("Related_Weaknesses", [])
        if not related_weaknesses:
            related_weaknesses = [{
                "CWE_ID": "No information",
                "Name": "No information",
                "Description": "No information",
                "Detection_Methods": [
                    {
                        "Method": "No information",
                        "Description": "No information"
                    }
                ],
                "Potential_Mitigations": [
                    {
                        "Phase": "No information",
                        "Description": "No information."
                    }
                ],
                "Observed_Examples": [
                    {
                        "Reference": "No information",
                        "Description": "No information"
                    }
                ]
            }]
        
        # Процесс добавления связей с CWE
        for cwe_item in related_weaknesses:
            # Проверяем, является ли cwe_item словарем или строкой
            if isinstance(cwe_item, dict):  # Если это словарь, значит, внутри уже есть все данные
                info["Related_Weaknesses"].append(cwe_item)
            elif isinstance(cwe_item, str):  # Если это строка (CWE_ID), то ищем в словаре cwe_dict
                if cwe_item in cwe_dict:
                    cwe_item_data = cwe_dict[cwe_item]
                    # Проверка на пустые списки и замена их на "No information"
                    detection_methods = cwe_item_data.get("Detection_Methods", [])
                    if not detection_methods:
                        detection_methods = [
                            {
                                "Method": "No information",
                                "Description": "No information"
                            }
                        ]
                    
                    potential_mitigations = cwe_item_data.get("Potential_Mitigations", [])
                    if not potential_mitigations:
                        potential_mitigations = [
                            {
                                "Phase": "No information",
                                "Description": "No information."
                            }
                        ]
                    
                    observed_examples = cwe_item_data.get("Observed_Examples", [])
                    if not observed_examples:
                        observed_examples = [
                            {
                                "Reference": "No information",
                                "Description": "No information"
                            }
                        ]
                    
                    info["Related_Weaknesses"].append({
                        "CWE_ID": cwe_item_data["ID"],
                        "Name": cwe_item_data.get("Name", ""),
                        "Description": cwe_item_data.get("Description", ""),
                        "Detection_Methods": detection_methods,
                        "Potential_Mitigations": potential_mitigations,
                        "Observed_Examples": observed_examples
                    })
                else:
                    print(f"Warning: CWE_ID {cwe_item} not found in CWE data.")
            else:
                print(f"Warning: Invalid format for CWE item: {cwe_item}")

        
        # Заполняем данные по каждому Taxonomy_Mappings
        taxonomy_entries = []
        for taxonomy in taxonomy_mappings:
            taxonomy_name = taxonomy.get("Taxonomy_Name")
            entry_id = taxonomy.get("Entry_ID")
            
            if taxonomy_name and entry_id:
                # Вставляем INFO в сам Taxonomy_Mapping
                if taxonomy_name == "ATTACK":
                    taxonomy_entry = {
                        "Taxonomy_Name": taxonomy_name,
                        "Entry_ID": entry_id,
                        "Entry_Name": taxonomy.get("Entry_Name", ""),
                        "INFO": info  # Добавляем INFO внутрь Taxonomy_Mapping
                    }
                    taxonomy_entries.append(taxonomy_entry)
            else:
                print(f"Warning: Missing 'Taxonomy_Name' or 'Entry_ID' in Taxonomy: {taxonomy}")
        
        # Если Taxonomy_Mappings не пустое, добавляем в результат
        if taxonomy_entries:
            result_data.append({
                "Taxonomy_Mappings": taxonomy_entries
            })
    
    # Записываем результат в выходной JSON файл
    with open(output_json_path, 'w', encoding='utf-8') as output_file:
        json.dump(result_data, output_file, ensure_ascii=False, indent=4)

    print(f"Данные с полями INFO, вложенными в Taxonomy_Mappings, и обработанными пустыми списками записаны в файл {output_json_path}.")

# Пути к файлам
capec_file = "capec_relationship.json"  # Путь к файлу capec_relationship.json
cwe_file = "cwe_relationship.json"  # Путь к файлу cwe_relationship.json (если нужно для дальнейшей работы)
output_file = "capec_with_infos.json"  # Путь к выходному JSON файлу

# Выполнение объединения
merge_capec_and_cwe(capec_file, cwe_file, output_file)

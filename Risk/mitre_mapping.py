import json

def merge_capec_and_cwe(capec_json_path, cwe_json_path, output_json_path):
    # Чтение данных из файла capec_relationship.json
    with open(capec_json_path, 'r', encoding='utf-8') as capec_file:
        capec_data = json.load(capec_file)
    
    # Чтение данных из файла cwe_relationship.json
    with open(cwe_json_path, 'r', encoding='utf-8') as cwe_file:
        cwe_data = json.load(cwe_file)
    
    # Создаем словарь для быстрого доступа по ID в cwe_data
    cwe_dict = {item["ID"]: item for item in cwe_data}
    
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
                extended_weaknesses.append({
                    "CWE_ID": cwe_item["ID"],
                    "Name": cwe_item.get("Name", ""),
                    "Description": cwe_item.get("Description", ""),
                    "Detection_Methods": cwe_item.get("Detection_Methods", ""),
                    "Potential_Mitigations": cwe_item.get("Potential_Mitigations", "")
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
output_file = "merged_capec_cwe.json"  # Путь к выходному JSON файлу
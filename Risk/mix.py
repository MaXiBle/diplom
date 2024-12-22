import json

# Пути к файлам
extracted_data_file = 'extracted_data.json'
enriched_data_file = 'enriched_capec_with_cve.json'
output_file = 'updated_enriched_capec_with_cve.json'

# Загрузка данных из файлов
with open(extracted_data_file, 'r', encoding='utf-8') as f:
    extracted_data = json.load(f)

with open(enriched_data_file, 'r', encoding='utf-8') as f:
    enriched_data = json.load(f)

# Создаем словарь для быстрого поиска x_mitre_detection по имени
mitre_detection_map = {entry['name']: entry['x_mitre_detection'] for entry in extracted_data}

# Обновляем enriched_data
for entry in enriched_data:
    entry_name = entry.get('Entry_Name')
    if entry_name in mitre_detection_map:
        # Вставляем x_mitre_detection после Entry_Name
        detection_value = mitre_detection_map[entry_name]
        entry['x_mitre_detection'] = detection_value

# Сохранение обновленных данных
with open(output_file, 'w', encoding='utf-8') as f:
    json.dump(enriched_data, f, ensure_ascii=False, indent=4)

print(f"Обновленный файл сохранен как {output_file}")

import json

# Функция для обработки данных и создания соответствий CAPEC -> MITRE ATT&CK
def map_capec_to_mitre(relationship_data):
    # Словарь для хранения соответствий
    capec_to_mitre_map = {}

    # Перебираем все объекты
    for obj in relationship_data.get("objects", []):
        external_references = obj.get("external_references", [])

        capec_list = []
        mitre_list = []

        # Разделяем ссылки на CAPEC и MITRE ATT&CK
        for ref in external_references:
            external_id = ref.get("external_id")
            source_name = ref.get("source_name")

            if source_name == "capec":
                capec_list.append(external_id)
            elif source_name == "ATTACK":
                mitre_list.append(external_id)

        # Если есть хотя бы один CAPEC и хотя бы одна техника MITRE ATT&CK, добавляем в map
        for capec in capec_list:
            if capec and mitre_list:  # Убедимся, что есть техники для этого CAPEC
                # Удаляем букву "T" из всех техник
                cleaned_mitre_list = [mitre_id.lstrip('T') for mitre_id in mitre_list]

                # Добавляем в словарь
                capec_to_mitre_map[capec] = cleaned_mitre_list

    return capec_to_mitre_map

# Чтение данных из файла relationship.json
with open('relationship.json', 'r', encoding='utf-8') as file:
    data = json.load(file)

# Получаем соответствия CAPEC -> MITRE ATT&CK
capec_to_mitre_mapping = map_capec_to_mitre(data)

# Записываем результат в новый файл
with open('capec_to_mitre_mapping.json', 'w', encoding='utf-8') as outfile:
    json.dump(capec_to_mitre_mapping, outfile, ensure_ascii=False, indent=4)

print("Результаты успешно записаны в capec_to_mitre_mapping.json")

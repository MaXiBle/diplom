import os
import json

# Путь к папке с JSON файлами
folder_path = 'attack_data'

# Список для сохранения результатов
extracted_data = []

# Обходим все файлы в папке
for filename in os.listdir(folder_path):
    if filename.endswith('.json'):  # Проверяем, что файл имеет расширение .json
        file_path = os.path.join(folder_path, filename)
        
        # Открываем и читаем содержимое файла
        with open(file_path, 'r', encoding='utf-8') as f:
            try:
                data = json.load(f)  # Загружаем JSON
                
                # Проверяем, есть ли ключ "objects"
                if "objects" in data:
                    for obj in data["objects"]:
                        # Извлекаем "name" и "x_mitre_detection", если они есть
                        name = obj.get("name", "Нет имени")
                        detection = obj.get("x_mitre_detection", "Нет данных о обнаружении")
                        extracted_data.append({"name": name, "x_mitre_detection": detection})
            
            except json.JSONDecodeError as e:
                print(f"Ошибка чтения JSON из файла {filename}: {e}")

# Выводим собранные данные
for entry in extracted_data:
    print(f"Name: {entry['name']}")
    print(f"Detection: {entry['x_mitre_detection']}")
    print('-' * 50)

# Сохранение результатов в файл (по желанию)
output_path = 'extracted_data.json'
with open(output_path, 'w', encoding='utf-8') as f:
    json.dump(extracted_data, f, ensure_ascii=False, indent=4)

print(f"Данные сохранены в файл {output_path}")

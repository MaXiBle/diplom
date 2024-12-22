import json
from googletrans import Translator

def translate_json(input_file, output_file):
    # Инициализация переводчика
    translator = Translator()

    # Загрузка исходного JSON
    with open(input_file, 'r', encoding='utf-8') as f:
        data = json.load(f)

    # Функция для перевода строк в JSON
    def translate_field(content, keys_to_translate):
        if isinstance(content, dict):
            for key, value in content.items():
                if key in keys_to_translate and isinstance(value, str):
                    content[key] = translator.translate(value, src='en', dest='ru').text
                else:
                    translate_field(value, keys_to_translate)
        elif isinstance(content, list):
            for item in content:
                translate_field(item, keys_to_translate)

    # Определение полей для перевода
    translation_rules = {
        "Taxonomy_Mappings": ["Entry_Name"],
        "INFO": ["Name", "Description", "Mitigations", "Examples"],
        "Related_Weaknesses": ["Name", "Description"],
        "Detection_Methods": ["Method", "Description"],
        "Potential_Mitigations": ["Phase", "Description"],
        "Observed_Examples": ["Description"]
    }

    # Рекурсивная функция для обработки JSON
    def process_json(data, translation_rules):
        if isinstance(data, dict):
            for key, value in data.items():
                if key in translation_rules:
                    translate_field(value, translation_rules[key])
                else:
                    process_json(value, translation_rules)
        elif isinstance(data, list):
            for item in data:
                process_json(item, translation_rules)

    # Применение перевода
    process_json(data, translation_rules)

    # Сохранение нового JSON
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=4)

# Использование функции
input_file = 'capec_with_infos.json'
output_file = 'capec_with_infos_RU2.json'
translate_json(input_file, output_file)

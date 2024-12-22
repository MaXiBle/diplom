import xml.etree.ElementTree as ET
import json
import re

# Функция для извлечения текста, убирая лишние пробелы и символы новой строки
def clean_description_text(description_element):
    # Собираем весь текст из элемента, включая все вложенные теги <p>
    description_text = "".join(description_element.itertext()).strip()
    
    # Убираем символы новой строки и лишние пробелы внутри текста
    description_text = re.sub(r'\s+', ' ', description_text)  # Заменяем несколько пробелов и \n на один пробел
    return description_text

# Функция для извлечения данных и записи их в JSON
def extract_weaknesses_and_related_data_to_json(cwe_file_path, output_json_path):
    # Парсим исходный XML файл
    tree = ET.parse(cwe_file_path)
    root = tree.getroot()

    # Убираем пространство имен из тегов
    for elem in root.iter():
        elem.tag = elem.tag.split('}')[-1]  # Оставляем только имя тега без пространства имен

    # Список для хранения данных о Weakness и дополнительной информации
    weaknesses_data = []

    # Проходим по всем элементам <Weakness> в <Weaknesses>
    for weakness in root.findall(".//Weakness"):
        weakness_id = weakness.attrib.get("ID")
        name = weakness.attrib.get("Name")
        description = weakness.find("Description").text if weakness.find("Description") is not None else None

        # Извлекаем данные из <Related_Attack_Patterns>
        related_attack_patterns_data = []
        for related_attack_pattern in weakness.findall(".//Related_Attack_Pattern"):
            capec_id = related_attack_pattern.attrib.get("CAPEC_ID")
            if capec_id:
                related_attack_patterns_data.append({"CAPEC_ID": capec_id})

        # Извлекаем данные из <Detection_Methods>
        detection_methods_data = []
        for detection_method in weakness.findall(".//Detection_Method"):
            method = detection_method.find("Method").text if detection_method.find("Method") is not None else None
            method_description = detection_method.find("Description").text if detection_method.find("Description") is not None else None

            if method and method_description:
                detection_methods_data.append({
                    "Method": method,
                    "Description": clean_description_text(detection_method.find("Description"))
                })

        # Извлекаем данные из <Potential_Mitigations>
        potential_mitigations_data = []
        for mitigation in weakness.findall(".//Mitigation"):
            phase = mitigation.find("Phase").text if mitigation.find("Phase") is not None else None
            mitigation_description = mitigation.find("Description")
            cleaned_mitigation_description = clean_description_text(mitigation_description) if mitigation_description else None

            if phase and cleaned_mitigation_description:
                potential_mitigations_data.append({
                    "Phase": phase,
                    "Description": cleaned_mitigation_description
                })

        # Извлекаем данные из <Observed_Examples> без поля <Link>
        observed_examples_data = []
        for observed_example in weakness.findall(".//Observed_Example"):
            reference = observed_example.find("Reference").text if observed_example.find("Reference") is not None else None
            description = observed_example.find("Description").text if observed_example.find("Description") is not None else None

            if reference and description:
                observed_examples_data.append({
                    "Reference": reference,
                    "Description": clean_description_text(observed_example.find("Description"))
                })

        # Добавляем данные о weakness и связанных данных в список
        if weakness_id and name:
            weaknesses_data.append({
                "ID": weakness_id,
                "Name": name,
                "Description": description,
                "Related_Attack_Patterns": related_attack_patterns_data,
                "Detection_Methods": detection_methods_data,
                "Potential_Mitigations": potential_mitigations_data,
                "Observed_Examples": observed_examples_data
            })

    # Записываем данные в JSON файл
    with open(output_json_path, "w", encoding="utf-8") as json_file:
        json.dump(weaknesses_data, json_file, ensure_ascii=False, indent=4)

    print(f"Данные о Weakness и связанные данные записаны в файл {output_json_path}.")

# Указываем пути к файлам
cwe_file = "new_CWE.xml"  # Путь к исходному файлу
output_json = "cwe_relationship.json"  # Путь к новому JSON файлу

# Извлекаем данные и записываем их в JSON файл
extract_weaknesses_and_related_data_to_json(cwe_file, output_json)

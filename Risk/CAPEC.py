import xml.etree.ElementTree as ET
import json

def extract_attack_patterns_to_json(capec_file_path, output_json_path):
    # Парсим исходный XML файл
    tree = ET.parse(capec_file_path)
    root = tree.getroot()
    
    # Убираем пространство имен из тегов
    for elem in root.iter():
        elem.tag = elem.tag.split('}')[-1]  # Оставляем только имя тега без пространства имен

    # Находим все элементы <Attack_Pattern> в <Attack_Patterns>
    attack_patterns = root.findall(".//Attack_Pattern")

    # Список для хранения данных об Attack Patterns
    attack_patterns_data = []

    # Проходим по всем элементам <Attack_Pattern> и извлекаем нужные данные
    for pattern in attack_patterns:
        capec_id = pattern.attrib.get("ID")
        name = pattern.attrib.get("Name")
        description = pattern.find("Description").text if pattern.find("Description") is not None else None

        # Извлекаем <Related_Weaknesses>
        related_weaknesses = []
        weaknesses = pattern.find("Related_Weaknesses")
        if weaknesses is not None:
            for weakness in weaknesses.findall("Related_Weakness"):
                cwe_id = weakness.attrib.get("CWE_ID")
                if cwe_id:
                    related_weaknesses.append(cwe_id)

        # Извлекаем <Taxonomy_Mappings>
        taxonomy_mappings = []
        taxonomies = pattern.find("Taxonomy_Mappings")
        if taxonomies is not None:
            for mapping in taxonomies.findall("Taxonomy_Mapping"):
                taxonomy_name = mapping.attrib.get("Taxonomy_Name")
                entry_id = mapping.find("Entry_ID").text if mapping.find("Entry_ID") is not None else None
                entry_name = mapping.find("Entry_Name").text if mapping.find("Entry_Name") is not None else None

                if taxonomy_name and entry_id and entry_name:
                    taxonomy_mappings.append({
                        "Taxonomy_Name": taxonomy_name,
                        "Entry_ID": entry_id,
                        "Entry_Name": entry_name
                    })

        # Извлекаем <Mitigations>
        mitigations = []
        mitigation_elements = pattern.find("Mitigations")
        if mitigation_elements is not None:
            for mitigation in mitigation_elements.findall("Mitigation"):
                # Текст каждого Mitigation добавляем в список
                mitigation_text = mitigation.text.strip() if mitigation.text else ""
                if mitigation_text:
                    mitigations.append(mitigation_text)

        # Если Mitigations пусто, добавляем текст по умолчанию
        if not mitigations:
            mitigations.append("No mitigation information available.")  # Добавление текста по умолчанию

        # Извлекаем <Example_Instances>
        examples = []
        example_elements = pattern.find("Example_Instances")
        if example_elements is not None:
            for example in example_elements.findall("Example"):
                example_text = " ".join([p.text for p in example.findall(".//p") if p.text])
                if example_text:
                    examples.append(example_text)

        # Если Examples пусто, добавляем текст по умолчанию
        if not examples:
            examples.append("No example information available.")  # Добавление текста по умолчанию

        # Добавляем данные об Attack Pattern в список
        if capec_id and name:
            attack_patterns_data.append({
                "CAPEC_ID": capec_id,
                "Name": name,
                "Description": description,
                "Related_Weaknesses": related_weaknesses if related_weaknesses else None,
                "Taxonomy_Mappings": taxonomy_mappings if taxonomy_mappings else None,
                "Mitigations": mitigations,
                "Examples": examples
            })

    # Записываем данные в JSON файл
    with open(output_json_path, "w", encoding="utf-8") as json_file:
        json.dump(attack_patterns_data, json_file, ensure_ascii=False, indent=4)

    print(f"Данные о всех Attack Patterns записаны в файл {output_json_path}.")

# Указываем пути к файлам
capec_file = "capec_v3.9.xml"  # Путь к исходному XML файлу
output_json = "capec_relationship.json"  # Путь к новому JSON файлу

# Извлекаем данные и записываем их в JSON файл
extract_attack_patterns_to_json(capec_file, output_json)

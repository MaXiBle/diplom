import json
import os


def enrich_capec_with_cve(cve_data_path, capec_file_path, output_file_path):
    """
    Добавляет данные из CVE файлов в структуру CAPEC.
    """
    # Загружаем извлечённые CVE данные
    with open(cve_data_path, 'r', encoding='utf-8') as cve_file:
        cve_data = json.load(cve_file)

    # Преобразуем CVE данные в словарь для быстрого поиска по CVE_ID
    cve_dict = {cve["CVE_ID"]: cve for cve in cve_data}

    # Загружаем CAPEC данные
    with open(capec_file_path, 'r', encoding='utf-8') as capec_file:
        capec_data = json.load(capec_file)

    # Обновляем CAPEC данные
    for capec_entry in capec_data:
        for weakness in capec_entry.get("Taxonomy_Mappings", []):
            for info in weakness.get("INFO", []):
                for related_weakness in info.get("Related_Weaknesses", []):
                    for observed_example in related_weakness.get("Observed_Examples", []):
                        cve_id = observed_example.get("Reference")
                        if cve_id and cve_id in cve_dict:
                            # Добавляем данные CVE
                            observed_example["References"] = cve_dict[cve_id].get("References", [])
                            observed_example["Impact"] = cve_dict[cve_id].get("Impact", {})

    # Записываем обновлённые данные в новый JSON файл
    with open(output_file_path, 'w', encoding='utf-8') as output_file:
        json.dump(capec_data, output_file, ensure_ascii=False, indent=4)

    print(f"Файл успешно обновлён: {output_file_path}")


# Пути к файлам
cve_data_file = "extracted_cve_data.json"  # Извлечённые данные CVE
capec_file = "updated_capec_with_infos.json"  # Исходный CAPEC файл
output_file = "enriched_capec_with_cve.json"  # Обновлённый файл

# Выполнение
enrich_capec_with_cve(cve_data_file, capec_file, output_file)

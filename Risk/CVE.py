import json
import os


def extract_cve_data(cve_folder_path, output_json_path):
    """
    Извлекает информацию из файлов CVE и записывает её в новый JSON-файл.
    """
    extracted_data = []

    # Обходим все файлы в папке
    for filename in os.listdir(cve_folder_path):
        if filename.endswith(".json"):
            file_path = os.path.join(cve_folder_path, filename)
            with open(file_path, 'r', encoding='utf-8') as cve_file:
                try:
                    cve_data = json.load(cve_file)  # Загрузка JSON данных
                    # Обрабатываем все элементы CVE
                    for item in cve_data.get("CVE_Items", []):
                        cve_id = item.get("cve", {}).get("CVE_data_meta", {}).get("ID", "Unknown")
                        references = [
                            ref.get("url", "Unknown") for ref in item.get("cve", {}).get("references", {}).get("reference_data", [])
                        ]
                        impact_data = item.get("impact", {}).get("baseMetricV2", {}).get("cvssV2", {})
                        base_score = impact_data.get("baseScore", "Unknown")
                        vector_string = impact_data.get("vectorString", "Unknown")
                        version = impact_data.get("version", "Unknown")  # Извлечение версии

                        # Добавляем данные в общий список
                        extracted_data.append({
                            "CVE_ID": cve_id,
                            "References": references,
                            "Impact": {
                                "BaseScore": base_score,
                                "VectorString": vector_string,
                                "Version": version
                            }
                        })

                except json.JSONDecodeError as e:
                    print(f"Ошибка при чтении файла {file_path}: {e}")

    # Запись извлеченных данных в новый JSON-файл
    with open(output_json_path, 'w', encoding='utf-8') as output_file:
        json.dump(extracted_data, output_file, ensure_ascii=False, indent=4)

    print(f"Данные успешно записаны в файл {output_json_path}.")


# Пути к папке с CVE-файлами и выходному файлу
cve_folder = "cve_files"
output_file = "extracted_cve_data.json"

# Выполнение
extract_cve_data(cve_folder, output_file)

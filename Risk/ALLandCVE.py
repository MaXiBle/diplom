import json

def merge_cve_with_capec(cve_json_path, capec_json_path, output_json_path):
    # Чтение данных из cve.json
    with open(cve_json_path, 'r', encoding='utf-8') as cve_file:
        cve_data = json.load(cve_file)

    # Чтение данных из capec_with_infos.json
    with open(capec_json_path, 'r', encoding='utf-8') as capec_file:
        capec_data = json.load(capec_file)

    # Создаем словарь для быстрого доступа к URLs по CVE_ID
    cve_references = {}
    for cve_item in cve_data:  # Итерируем по списку
        cve_id = cve_item.get("CVE_ID")
        urls = cve_item.get("URLs", [])
        if cve_id:
            cve_references[cve_id] = urls  # Сохраняем список URL по CVE_ID

    # Процесс обновления CAPEC данных
    for capec_item in capec_data:  # capec_data - это список, поэтому используем прямой цикл
        for weakness in capec_item.get("Related_Weaknesses", []):  # Пройдем по Related_Weaknesses
            for example in weakness.get("Observed_Examples", []):  # Пройдем по Observed_Examples
                if "Reference" in example:
                    reference = example["Reference"]
                    # Если найдено совпадение с CVE_ID, добавляем URL
                    if reference in cve_references:
                        example["CVE_URLS"] = cve_references[reference]  # Добавляем URL-ы в "CVE_URLS"

    # Записываем обновленные данные в новый файл
    with open(output_json_path, 'w', encoding='utf-8') as output_file:
        json.dump(capec_data, output_file, ensure_ascii=False, indent=4)

    print(f"Данные записаны в файл {output_json_path}.")
# Пути к файлам
cve_file = "cve.json"
capec_file = "capec_with_infos.json"
output_file = "updated_capec_with_infos.json"

# Выполнение
merge_cve_with_capec(cve_file, capec_file, output_file)

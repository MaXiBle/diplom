import json
import os


def load_all_cve_files(cve_folder_path):
    """
    Загружает и объединяет все JSON-файлы из указанной папки в один список.
    """
    all_cve_data = []
    for filename in os.listdir(cve_folder_path):
        if filename.endswith(".json"):
            file_path = os.path.join(cve_folder_path, filename)
            with open(file_path, 'r', encoding='utf-8') as cve_file:
                try:
                    cve_data = json.load(cve_file)
                    all_cve_data.extend(cve_data)  # Предполагаем, что каждый файл содержит список CVE
                except json.JSONDecodeError as e:
                    print(f"Ошибка при чтении файла {file_path}: {e}")
    return all_cve_data


def merge_cve_with_technique(cve_folder_path, capec_json_path, output_json_path):
    """
    Объединяет данные CVE с техниками через CAPEC.
    """
    # Загрузка всех CVE файлов из папки
    all_cve_data = load_all_cve_files(cve_folder_path)

    # Создаем словарь для быстрого доступа к URL по CVE_ID
    cve_references = {}
    for cve_item in all_cve_data:
        cve_id = cve_item.get("CVE_ID")
        urls = cve_item.get("URLs", [])
        if cve_id:
            cve_references[cve_id] = urls  # Сохраняем список URL по CVE_ID

    # Чтение данных из capec_with_infos.json
    with open(capec_json_path, 'r', encoding='utf-8') as capec_file:
        capec_data = json.load(capec_file)

    # Создаем структуру для хранения техники и их уникальных CVE
    technique_cve_map = {}

    # Процесс обработки CAPEC данных
    for capec_item in capec_data:
        # Получаем ID CAPEC и связанные техники
        capec_id = capec_item.get("CAPEC_ID")
        attack_mappings = capec_item.get("Taxonomy_Mappings", [])

        # Ищем техники, связанные с текущей CAPEC
        for mapping in attack_mappings:
            if mapping.get("Taxonomy_Name") == "ATTACK":
                technique_name = mapping.get("Entry_Name")
                if not technique_name:
                    continue

                # Если техники еще нет в карте, добавляем её
                if technique_name not in technique_cve_map:
                    technique_cve_map[technique_name] = set()  # Используем set для уникальности CVE

                # Обрабатываем связанные CVE через Related_Weaknesses
                for weakness in capec_item.get("Related_Weaknesses", []):
                    for example in weakness.get("Observed_Examples", []):
                        cve_id = example.get("Reference")
                        if cve_id and cve_id in cve_references:
                            technique_cve_map[technique_name].add(cve_id)  # Добавляем CVE для техники

    # Преобразуем данные для сохранения в JSON
    output_data = []
    for technique, cve_ids in technique_cve_map.items():
        output_data.append({
            "Technique_Name": technique,
            "CVE_List": list(cve_ids)  # Преобразуем set в list
        })

    # Записываем обновленные данные в файл
    with open(output_json_path, 'w', encoding='utf-8') as output_file:
        json.dump(output_data, output_file, ensure_ascii=False, indent=4)

    print(f"Данные записаны в файл {output_json_path}.")


# Пути к файлам
cve_folder = "cve_files"
capec_file = "capec_with_infos.json"
output_file = "technique_to_cve.json"

# Выполнение
merge_cve_with_technique(cve_folder, capec_file, output_file)

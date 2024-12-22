import json


def minimize_all_cves(input_file, output_file):
    """
    Минимизирует JSON-файл, оставляя только минимальные данные для всех CVE.

    :param input_file: Путь к исходному JSON-файлу.
    :param output_file: Путь для сохранения минимизированного JSON-файла.
    """
    with open(input_file, "r", encoding="utf-8") as file:
        data = json.load(file)

    minimized_data = []

    for item in data:
        cve_id = item.get('cve', {}).get('CVE_data_meta', {}).get('ID', None)
        if not cve_id:
            continue  # Пропускаем записи без CVE-ID

        # Сохраняем только необходимые данные
        minimized_item = {
            "cve": {
                "CVE_data_meta": {
                    "ID": cve_id
                }
            },
            "impact": {
                "baseMetricV2": {
                    "cvssV2": {
                        "vectorString": item.get('impact', {}).get('baseMetricV2', {}).get('cvssV2', {}).get(
                            'vectorString', ''),
                        "baseScore": item.get('impact', {}).get('baseMetricV2', {}).get('cvssV2', {}).get('baseScore',
                                                                                                          0)
                    }
                }
            }
        }
        minimized_data.append(minimized_item)

    # Сохраняем результат в файл
    with open(output_file, "w", encoding="utf-8") as file:
        json.dump(minimized_data, file, ensure_ascii=False, indent=4)


# Пример использования
input_file = "C:\\PycharmProjects\\diplom\\CVE2CAPEC\\resultscve\\merged_data.json"
output_file = "C:\\PycharmProjects\\diplom\\CVE2CAPEC\\resultscve\\minimal_all_data.json"

minimize_all_cves(input_file, output_file)

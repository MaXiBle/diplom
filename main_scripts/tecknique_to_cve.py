import json

# Задаем список TECHNIQUES, по которым будем искать CVE
target_techniques = ["1036.001", "1040", "1083"]

# Открываем файл и читаем его построчно
result = {}

with open('C:\PycharmProjects\diplom\CVE2CAPEC\\results\\new_cves.jsonl', 'r') as file:
    for line in file:
        data = json.loads(line.strip())

        for cve_id, cve_data in data.items():
            for technique in cve_data.get("TECHNIQUES", []):
                # Если техника из списка target_techniques, добавляем в результат
                if technique in target_techniques:
                    if technique not in result:
                        result[technique] = []
                    result[technique].append(cve_id)

# Выводим результат
print(json.dumps(result, indent=4))

import json

def main(technique_ids):
    print("Генерация мер обнаружения и ликвидации для заданных техник...\n")
    # Путь к файлу
    file_path = 'C:\PycharmProjects\diplom\mitigations_and_detections.json'

    # Чтение данных из JSON файла
    with open(file_path, 'r', encoding='utf-8') as file:
        data = json.load(file)

    # Инициализация выходных словарей
    mitigations_dict = {}
    detections_dict = {}

    # Обработка данных
    for tech_id in technique_ids:
        if 'T'+tech_id in data:
            technique = data['T'+tech_id]

            # Обработка mitigations
            mitigations_dict['T'+tech_id] = [
                (m[0], m[1], m[2]) for m in technique.get("mitigations", [])
            ]

            # Обработка detections
            detections_dict['T'+tech_id] = [
                (d[0], d[1], d[2], d[3]) for d in technique.get("detections", [])
            ]

    return mitigations_dict, detections_dict
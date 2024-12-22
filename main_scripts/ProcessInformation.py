import os
import json

def get_tactics_and_techniques_for_ids(folder_path, technique_ids, dictionaty_tecknique_capec):
    """
    Загружает данные из JSON-файлов MITRE, сопоставляет заданные техники с тактиками
    (используя phase_name из kill_chain_phases) и возвращает словарь {тактика: [(id техники, полное название)]}.

    :param folder_path: Путь к папке с JSON-файлами
    :param technique_ids: Список ID техник, для которых нужно найти тактики
    :param dictionaty_tecknique_capec: Словарь, где ключи это id техники Mitre, а значения это списки CAPEC
    :return: Словарь {тактика: [(id техники, полное название)]} для заданных техник
    """
    technique_map = {}  # Словарь: {название тактики: [(id техники, полное название)]}
    relevant_techniques = set(technique_ids)  # Преобразуем список в множество для быстрого поиска

    # Проход по всем JSON-файлам в папке
    for filename in os.listdir(folder_path):
        if filename.endswith(".json"):
            filepath = os.path.join(folder_path, filename)
            with open(filepath, 'r', encoding='utf-8') as file:
                data = json.load(file)
                objects = data.get("objects", [])

                # Обработка объектов в файле
                for obj in objects:
                    if obj["type"] == "attack-pattern":
                        # Обрабатываем технику
                        external_references = obj.get("external_references", [])
                        if not external_references:
                            continue

                        technique_id = external_references[0].get("external_id", "")
                        if technique_id.replace('T','') not in relevant_techniques:
                            continue

                        technique_name = obj["name"]
                        technique_full_name = f"{technique_id} {technique_name}"

                        # Извлечение тактик через kill_chain_phases
                        kill_chain_phases = obj.get("kill_chain_phases", [])
                        for phase in kill_chain_phases:
                            if phase.get("kill_chain_name") == "mitre-attack":
                                tactic_name = phase.get("phase_name", "Unknown").capitalize()
                                if tactic_name not in technique_map:
                                    technique_map[tactic_name] = []
                                # Сохраняем как ID техники, так и полное название
                                technique_map[tactic_name].append((technique_full_name, dictionaty_tecknique_capec[technique_id.replace('T','')]))

    return technique_map


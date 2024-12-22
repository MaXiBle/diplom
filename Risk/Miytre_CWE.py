import json

# Функция для преобразования значений в C, I, A
def get_impact_value(impact_letter):
    if impact_letter == 'N':  # None
        return 0.001
    elif impact_letter == 'P':  # Partial
        return 0.5
    elif impact_letter == 'C':  # Complete
        return 1
    return 0.001  # Для любых других значений (хотя их быть не должно)

# Функция для расчета ущерба по формуле
def calculate_damage(C, I, A):
    return 1 - (1 - C) * (1 - I) * (1 - A)

# Функция для извлечения значений C, I, A из VectorString
def extract_impact_values(vector_string):
    if not vector_string:
        return {'C': 0.001, 'I': 0.001, 'A': 0.001}  # Изменено на 0.001
    
    # Разбиваем строку VectorString на части, используя символ "/"
    vector_parts = vector_string.split('/')

    # Проверяем, что длина parts соответствует ожидаемому формату
    if len(vector_parts) < 6:
        return {'C': 0.001, 'I': 0.001, 'A': 0.001}  # Изменено на 0.001

    # Извлекаем C, I, A из нужных позиций строки
    C = get_impact_value(vector_parts[3][2])  # C - Confidentiality (например, "C:P" или "C:N")
    I = get_impact_value(vector_parts[4][2])  # I - Integrity (например, "I:P" или "I:N")
    A = get_impact_value(vector_parts[5][2])  # A - Availability (например, "A:P" или "A:N")

    return {'C': C, 'I': I, 'A': A}

# Функция для расчета вероятностей
def calculate_probabilities(data):
    technique_probabilities = {}

    for entry in data:
        entry_id = entry.get("Taxonomy_Mappings", [{}])[0].get("Entry_ID")
        if not entry_id:
            continue  # Пропускаем технику, если нет Entry_ID

        taxonomy_mappings = entry.get("Taxonomy_Mappings", [])
        for mapping in taxonomy_mappings:
            infos = mapping.get("INFO", [])
            for info in infos:
                related_weaknesses = info.get("Related_Weaknesses", [])
                for weakness in related_weaknesses:
                    observed_examples = weakness.get("Observed_Examples", [])
                    base_scores = []

                    # Собираем BaseScore, проверяя, что оно числовое
                    for example in observed_examples:
                        impact = example.get("Impact", {})
                        base_score = impact.get("BaseScore")

                        # Преобразуем BaseScore в число, если оно строка
                        if base_score:
                            try:
                                # Если значение BaseScore "Unknown", присваиваем его как 1.000001
                                if base_score == "Unknown":
                                    base_score = 1.000001
                                base_scores.append(float(base_score))
                            except ValueError:
                                pass  # Если преобразовать не удается, пропускаем это значение

                    if base_scores:
                        max_score = max(base_scores)
                        total_score = sum(base_scores)
                        probability = max_score / total_score if total_score > 0 else 0

                        # Добавляем или обновляем вероятность для этой техники
                        if entry_id not in technique_probabilities:
                            technique_probabilities[entry_id] = []

                        technique_probabilities[entry_id].append({
                            "CWE_ID": weakness.get("CWE_ID"),
                            "Probability": probability,
                            "VectorString": observed_examples[0].get("Impact", {}).get("VectorString", "")
                        })

    # Выбираем максимальную и минимальную вероятность для каждой техники
    results = []
    for entry_id, weaknesses in technique_probabilities.items():
        max_probability_weakness = max(weaknesses, key=lambda x: x["Probability"])
        min_probability_weakness = min(weaknesses, key=lambda x: x["Probability"])

        # Получаем C, I, A для максимальной и минимальной вероятности
        max_values = extract_impact_values(max_probability_weakness["VectorString"])
        min_values = extract_impact_values(min_probability_weakness["VectorString"])

        # Рассчитываем ущерб для максимальной и минимальной вероятности
        max_damage = calculate_damage(max_values['C'], max_values['I'], max_values['A'])
        min_damage = calculate_damage(min_values['C'], min_values['I'], min_values['A'])

        # Проверка, если ущерб при максимальной вероятности меньше, чем при минимальной
        if max_damage < min_damage:
            # Меняем местами ущерб и вероятности
            max_probability_weakness, min_probability_weakness = min_probability_weakness, max_probability_weakness
            max_damage, min_damage = min_damage, max_damage

        results.append({
            "Entry_ID": entry_id,
            "Max_Probability": max_probability_weakness["Probability"],
            "Max_C": max_values['C'],
            "Max_I": max_values['I'],
            "Max_A": max_values['A'],
            "Max_Damage": max_damage,
            "Min_Probability": min_probability_weakness["Probability"],
            "Min_C": min_values['C'],
            "Min_I": min_values['I'],
            "Min_A": min_values['A'],
            "Min_Damage": min_damage
        })

    return results

# Функция для записи результатов в JSON файл
def write_results_to_file(results, filename="output_results.json"):
    with open(filename, "w", encoding="utf-8") as file:
        json.dump(results, file, ensure_ascii=False, indent=4)

# Чтение данных из JSON-файла
file_path = "output.json"  # Укажите путь к вашему JSON-файлу

with open(file_path, "r", encoding="utf-8") as file:
    data = json.load(file)

# Расчет вероятностей
results = calculate_probabilities(data)

# Запись результатов в файл
write_results_to_file(results)

print("Результаты успешно записаны в output_results.json")

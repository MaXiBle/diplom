import json
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor, as_completed

# Функции для извлечения и расчётов
def get_impact_value(impact_letter):
    if impact_letter == 'N':  # None
        return 0.001
    elif impact_letter == 'P':  # Partial
        return 0.5
    elif impact_letter == 'C':  # Complete
        return 1
    return 0.001


def calculate_damage(C, I, A):
    return 1 - (1 - C) * (1 - I) * (1 - A)


def extract_impact_values(vector_string):
    if not vector_string:
        return {'C': 0.001, 'I': 0.001, 'A': 0.001}
    vector_parts = vector_string.split('/')
    C = get_impact_value(next((part[2] for part in vector_parts if part.startswith("C:")), 'N'))
    I = get_impact_value(next((part[2] for part in vector_parts if part.startswith("I:")), 'N'))
    A = get_impact_value(next((part[2] for part in vector_parts if part.startswith("A:")), 'N'))
    return {'C': C, 'I': I, 'A': A}


def process_cve_item(item, cve_list, cache):
    cve_id = item['cve']['CVE_data_meta']['ID']
    if cve_id not in cve_list:
        return None

    # Проверяем кеш
    if cve_id in cache:
        return cache[cve_id]

    vector_string = item.get('impact', {}).get('baseMetricV2', {}).get('cvssV2', {}).get('vectorString', '')
    base_score = item.get('impact', {}).get('baseMetricV2', {}).get('cvssV2', {}).get('baseScore', 0)

    # Расчет значений C, I, A
    impact_values = extract_impact_values(vector_string)
    damage = calculate_damage(impact_values['C'], impact_values['I'], impact_values['A'])

    # Создаем результат и кешируем
    result = {
        "CVE_ID": cve_id,
        "BaseScore": base_score,
        "C": impact_values['C'],
        "I": impact_values['I'],
        "A": impact_values['A'],
        "Damage": damage
    }
    cache[cve_id] = result
    return result


def analyze_cve_data(data, tecknique_name, cve_list, max_workers=4, batch_size=100):
    results = []
    cve_probabilities = {}
    cache = {}

    # Разделение на батчи
    batches = [data[i:i + batch_size] for i in range(0, len(data), batch_size)]
    total_tasks = len(data)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        with tqdm(total=total_tasks, desc=f"Расчет риска и фильтрация CVE для {tecknique_name}", ncols=80) as pbar:
            for batch in batches:
                futures = [executor.submit(process_cve_item, item, cve_list, cache) for item in batch]
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        results.append(result)
                        cve_id = result['CVE_ID']
                        if cve_id not in cve_probabilities:
                            cve_probabilities[cve_id] = []
                        cve_probabilities[cve_id].append(result['BaseScore'])
                    pbar.update(1)

    total_score = sum(score[0] for score in cve_probabilities.values())

    # Вычисление вероятностей и рисков
    for result in results:
        cve_id = result['CVE_ID']
        if cve_id in cve_probabilities and total_score > 0:
            probability = cve_probabilities[cve_id][0] / total_score
            result['Probability'] = probability
            result['Risk'] = result['Probability'] * result['Damage']

    return results


def write_results_to_file(results, filename="cve_results.json"):
    with open(filename, "w", encoding="utf-8") as file:
        json.dump(results, file, ensure_ascii=False, indent=4)

import requests
import math


def normalize(value, min_val, max_val):
    """ Нормализация значения от 0 до 1 """
    return (value - min_val) / (max_val - min_val)


def get_cvss_score(cve_id):
    """ Получаем CVSS оценку из NVD (National Vulnerability Database). """
    url = f"https://services.nvd.nist.gov/rest/json/cve/2.0/{cve_id}"
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        if "vulnerabilities" in data and len(data["vulnerabilities"]) > 0:
            vuln = data["vulnerabilities"][0]
            metrics = vuln["cve"].get("metrics", [])
            for metric in metrics:
                if "cvssV3" in metric:
                    return metric["cvssV3"]["baseScore"]
                elif "cvssV2" in metric:
                    return metric["cvssV2"]["baseScore"]
    return None


def get_epps_score(cve_id):
    """ Получаем EPSS оценку (Exploit Prediction Scoring System). """
    url = f"https://api.first.org/data/v1/epss?cveId={cve_id}"
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        if "data" in data and cve_id in data["data"]:
            epss = data["data"][cve_id]["epss"]
            return epss
    return None


def owasp_risk_rating(cvss_score):
    """ Рассчитываем оценку риска по методологии OWASP на основе CVSS. """
    if cvss_score >= 9.0:
        return 1.0  # Критический
    elif 7.0 <= cvss_score < 9.0:
        return 0.75  # Высокий
    elif 4.0 <= cvss_score < 7.0:
        return 0.5  # Средний
    else:
        return 0.25  # Низкий


def normalize_owasp(cvss_score):
    """ Нормализуем OWASP Risk Rating от 0 до 1 """
    risk = owasp_risk_rating(cvss_score)
    return normalize(risk, 0, 1)


def calculate_final_score(cvss_normalized, epss_normalized, owasp_normalized):
    """ Рассчитываем финальное значение по среднеквадратичному методу """
    return math.sqrt((cvss_normalized ** 2 + epss_normalized ** 2 + owasp_normalized ** 2) / 3)


def get_cve_scores(cve_id):
    """ Получаем все оценки для заданного CVE. """
    # Получаем CVSS балл
    cvss = get_cvss_score(cve_id)
    # Получаем EPSS оценку
    epss = get_epps_score(cve_id)

    # Нормализация значений
    if cvss is not None:
        normalized_cvss = normalize(cvss, 0, 10)
    else:
        normalized_cvss = None

    if epss is not None:
        normalized_epps = normalize(epss, 0, 1)
    else:
        normalized_epps = None

    normalized_owasp = None
    if cvss is not None:
        normalized_owasp = normalize_owasp(cvss)

    # Выводим результаты
    print(f"CVE ID: {cve_id}")

    if normalized_cvss is not None:
        print(f"Нормализованный CVSS Score: {normalized_cvss:.2f}")
    else:
        print("CVSS Score: Не найдено")

    if normalized_epps is not None:
        print(f"Нормализованный EPSS Score: {normalized_epps:.2f}")
    else:
        print("EPSS Score: Не найдено")

    if normalized_owasp is not None:
        print(f"Нормализованный OWASP Risk Rating: {normalized_owasp:.2f}")
    else:
        print("OWASP Risk Rating: Не доступно")

    # Расчет финального значения
    if normalized_cvss is not None and normalized_epps is not None and normalized_owasp is not None:
        final_score = calculate_final_score(normalized_cvss, normalized_epps, normalized_owasp)
        print(f"Финальное значение (среднеквадратичное): {final_score:.2f}")
        return final_score
    else:
        print("Финальное значение: Не доступно")
        return None


def calculate_attack_probability(cve_id, cve_technique_dict):
    """ Рассчитываем вероятность единичной атаки для CVE по техникам. """
    # Шаг 1: Получаем финальные значения для всех CVE в словаре
    final_scores = {}
    total_score = 0.0

    for technique, cve_list in cve_technique_dict.items():
        for cve in cve_list:
            final_score = get_cve_scores(cve)
            if final_score is not None:
                final_scores[cve] = final_score
                total_score += final_score

    # Шаг 2: Получаем финальное значение для целевого CVE
    target_score = final_scores.get(cve_id, None)
    if target_score is None:
        print(f"Ошибка: Финальное значение для {cve_id} не найдено.")
        return None

    # Шаг 3: Рассчитываем вероятность единичной атаки
    attack_probability = target_score / total_score if total_score > 0 else 0
    print(f"Вероятность единичной атаки для {cve_id}: {attack_probability:.4f}")
    return attack_probability


# Пример использования
cve_technique_dict = {
    "technique_1": ['CVE-2021-34527', 'CVE-2017-0144'],
    "technique_2": ['CVE-2021-3449', 'CVE-2020-0601']
}

cve_id = 'CVE-2021-34527'
calculate_attack_probability(cve_id, cve_technique_dict)

import json
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm


def process_line(line, techniques_list):
    """
    Обрабатывает одну строку файла и возвращает словарь с техниками и их соответствующими CVE.

    :param line: строка JSONL
    :param techniques_list: Список техник для поиска
    :return: Словарь с техниками и списками CVE
    """
    result = {technique: [] for technique in techniques_list}
    try:
        # Загружаем строку как JSON
        data = json.loads(line.strip())
        for cve_id, details in data.items():
            # Проверяем, содержатся ли интересующие техники
            if "TECHNIQUES" in details:
                for technique in techniques_list:
                    if technique in details["TECHNIQUES"]:
                        # Добавляем CVE к технике
                        result[technique].append(cve_id)
    except json.JSONDecodeError:
        pass
    return result


def merge_results(global_result, local_result):
    """
    Объединяет локальный результат обработки строки с глобальным результатом.

    :param global_result: Глобальный результат
    :param local_result: Локальный результат для одной строки
    """
    for technique, cve_list in local_result.items():
        global_result[technique].extend(cve_list)


def find_cves_by_techniques(techniques_list):
    file_path = "C:\\PycharmProjects\\diplom\\CVE2CAPEC\\results\\new_cves.jsonl"
    """
    Найти CVE, соответствующие списку техник.

    :param techniques_list: Список техник, которые нужно искать
    :return: Словарь с техниками в качестве ключей и списками CVE в качестве значений
    """
    # Инициализируем словарь для результатов
    result = {technique: [] for technique in techniques_list}

    with open(file_path, 'r', encoding='utf-8') as file:
        lines = file.readlines()

    # Создаем прогресс-бар
    with tqdm(total=len(lines), desc="Поиск уязвимостей для предоставленных техник", unit="строк") as progress_bar:
        with ThreadPoolExecutor() as executor:
            futures = [executor.submit(process_line, line, techniques_list) for line in lines]

            for future in futures:
                local_result = future.result()
                merge_results(result, local_result)
                progress_bar.update(1)

    return result
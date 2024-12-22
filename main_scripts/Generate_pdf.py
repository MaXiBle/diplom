import csv
import json
import os
from translation import translate_text
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph
from reportlab.lib.styles import ParagraphStyle
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont


# Регистрация шрифта, поддерживающего кириллицу
pdfmetrics.registerFont(TTFont('DejaVuSans', 'C:\\PycharmProjects\\diplom\\DejaVuSans.ttf'))

# Создаем стиль для основного текста
default_style = ParagraphStyle(
    name='DefaultStyle',
    fontName='DejaVuSans',  # Указываем шрифт по умолчанию
    fontSize=10,
    spaceAfter=6,
)

# Создаем стиль для заголовков таблиц
header_style = ParagraphStyle(
    name='HeaderStyle',
    fontName='DejaVuSans',  # Указываем шрифт для заголовков
    fontSize=14,
    spaceAfter=12,
    alignment=1  # Выравнивание по центру
)

# Общий стиль таблиц
common_table_style = TableStyle([
    ('BACKGROUND', (0, 0), (-1, 0), colors.black),  # Чёрный фон для заголовка
    ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),  # Белый текст для заголовка
    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),  # Текст выравнен по левому краю
    ('FONTNAME', (0, 0), (-1, -1), 'DejaVuSans'),  # Используем шрифт с поддержкой кириллицы
    ('FONTSIZE', (0, 0), (-1, -1), 10),  # Общий размер шрифта
    ('BOTTOMPADDING', (0, 0), (-1, 0), 10),  # Отступы в заголовке
    ('BACKGROUND', (0, 1), (-1, -1), colors.white),  # Белый фон строк данных
    ('TEXTCOLOR', (0, 1), (-1, -1), colors.black),  # Чёрный текст для строк данных
    ('GRID', (0, 0), (-1, -1), 0.5, colors.black),  # Чёрная сетка
    ('WORDWRAP', (0, 0), (-1, -1), 'CJK'),  # Автоматический перенос строк
])

# Установка ширины столбцов (для переноса текста)
def set_table_column_widths(table, widths):
    for i, width in enumerate(widths):
        table._argW[i] = width


# Функция для создания таблицы
# Функция для создания таблицы
def create_table_1(input_technique_ids):
    """
    Создает таблицу в формате ReportLab на основе данных из JSON-файлов.
    """
    json_folder_path = "C:\\PycharmProjects\\diplom\\Mitre Teckniques"

    # Маппинг английских названий этапов на русские
    mitre_phases_translation = {
        "reconnaissance": "Разведка",
        "resource-development": "Подготовка ресурсов",
        "initial-access": "Первоначальный доступ",
        "execution": "Выполнение",
        "persistence": "Закрепление",
        "privilege-escalation": "Повышение привилегий",
        "defense-evasion": "Предотвращение обнаружения",
        "credential-access": "Получение учетных данных",
        "discovery": "Обнаружение",
        "lateral-movement": "Перемещение внутри периметра",
        "collection": "Сбор данных",
        "exfiltration": "Эксфильтрация данных",
        "impact": "Деструктивное воздействие"
    }

    # Загружаем JSON-файлы
    json_data = []
    for filename in os.listdir(json_folder_path):
        if filename.endswith('.json'):
            with open(os.path.join(json_folder_path, filename), 'r', encoding='utf-8') as file:
                json_data.extend(json.load(file).get("objects", []))

    # Этапы MITRE ATT&CK в правильной последовательности
    mitre_phases_order = [
        "Разведка", "Подготовка ресурсов", "Первоначальный доступ",
        "Выполнение", "Закрепление", "Повышение привилегий",
        "Предотвращение обнаружения", "Получение учетных данных",
        "Обнаружение", "Перемещение внутри периметра", "Сбор данных",
        "Эксфильтрация данных", "Деструктивное воздействие"
    ]

    # Извлекаем техники
    techniques_info = []

    for obj in json_data:
        if obj['type'] == 'attack-pattern' and obj['external_references']:
            technique_id = next(
                (ref['external_id'] for ref in obj['external_references'] if ref['source_name'] == 'mitre-attack'),
                None
            )
            if technique_id and technique_id.replace('T', '') in input_technique_ids:
                for phase in obj.get('kill_chain_phases', []):
                    if phase['kill_chain_name'] == 'mitre-attack':  # Проверяем, что это цепочка MITRE ATT&CK
                        tactic_name = mitre_phases_translation.get(phase['phase_name'],
                                                                   phase['phase_name']).capitalize()
                        techniques_info.append((tactic_name, technique_id, obj['name']))

    # Сортируем данные по этапности MITRE ATT&CK
    techniques_info.sort(
        key=lambda x: mitre_phases_order.index(x[0].lower()) if x[0].lower() in mitre_phases_order else float('inf'))

    # Заголовок таблицы
    table_data = [['Этап Mitre', 'Техника Mitre']]

    # Заполняем таблицу данными
    for tactic, technique_id, technique_name in techniques_info:
        table_data.append([
            Paragraph(tactic, default_style),
            Paragraph(f"{technique_id}. {translate_text(technique_name.replace('-', ' '))}", default_style)
        ])

    # Создаем таблицу
    table = Table(table_data)
    table.setStyle(common_table_style)
    table._argW = [170, 230]  # Ширина столбцов

    # Установка высоты строк и разрешение на перенос текста
    table._argH = [None] * len(table_data)  # Высота строк будет вычисляться автоматически
    table.splitByRow = True  # Разрешение на разделение строк при переносе текста

    # Формируем элементы для PDF
    title = Paragraph("Таблица 1 – Данные техники по сценарию атаки", header_style)

    return [table, title]

def create_table_2(input_dict):
    """
    Создает таблицу в формате ReportLab, отображающую техники MITRE, CVE и описание CVE.

    :param input_dict: Словарь, связывающий техники MITRE с их CVE.
    :return: Список элементов ReportLab для включения в PDF.
    """

    json_folder_path = "C:\PycharmProjects\diplom\Mitre Teckniques"
    cve_csv_path = "C:\PycharmProjects\diplom\описание_cve.csv"


    # Загрузка данных из JSON-файлов
    techniques = {}
    for filename in os.listdir(json_folder_path):
        if filename.endswith('.json'):
            with open(os.path.join(json_folder_path, filename), 'r', encoding='utf-8') as file:
                json_data = json.load(file).get("objects", [])
                for obj in json_data:
                    if obj['type'] == 'attack-pattern' and obj['external_references']:
                        technique_id = next(
                            (ref['external_id'] for ref in obj['external_references'] if
                             ref['source_name'] == 'mitre-attack'),
                            None
                        )
                        if technique_id:
                            techniques[technique_id] = obj['name']

    # Загрузка описаний CVE из CSV-файла
    cve_descriptions = {}
    with open(cve_csv_path, 'r', encoding='utf-8') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            cve_descriptions[row['id']] = row['description']

    # Формирование данных для таблицы
    table_data = [['Техника Mitre', 'ID уязвимости', 'Описание уязвимости']]  # Заголовок таблицы
    for technique_id, cve_list in input_dict.items():
        technique_name = techniques.get(f"T{technique_id}", "Неизвестная техника")
        if not cve_list:  # Если список CVE пустой
            table_data.append([
                Paragraph(f"T{technique_id}. {translate_text(technique_name.replace('-', ' '))}", default_style),
                Paragraph("-", default_style),
                Paragraph("-", default_style),
            ])
        else:
            for cve_id in cve_list:
                cve_description = cve_descriptions.get(cve_id, "Описание отсутствует")
                table_data.append([
                    Paragraph(f"T{technique_id}. {translate_text(technique_name.replace('-', ' '))}", default_style),
                    Paragraph(cve_id, default_style),
                    Paragraph(translate_text(cve_description.replace('-', ' ')), default_style),
                ])

    # Создание таблицы
    table = Table(table_data, colWidths=[150, 100, 250])  # Ширина столбцов
    table.setStyle(common_table_style)

    # Формирование заголовка таблицы
    title = Paragraph("Таблица 2 – Вывод наиболее опасных сочетаний уязвимость - техника", header_style)

    return [table, title]

def create_table_3(data_list):
    """
    Создает таблицу в формате ReportLab, отображающую объект, технику MITRE, CVE и объект защиты.

    :param data_list: Список кортежей (id объекта, id техники, id уязвимости, название объекта защиты).
    :param json_folder_path: Путь к папке с JSON-файлами MITRE.
    :return: Список элементов ReportLab для включения в PDF.
    """

    json_folder_path = "C:\PycharmProjects\diplom\Mitre Teckniques"

    # Загрузка данных о техниках из JSON-файлов
    techniques = {}
    for filename in os.listdir(json_folder_path):
        if filename.endswith('.json'):
            with open(os.path.join(json_folder_path, filename), 'r', encoding='utf-8') as file:
                json_data = json.load(file).get("objects", [])
                for obj in json_data:
                    if obj['type'] == 'attack-pattern' and obj['external_references']:
                        technique_id = next(
                            (ref['external_id'] for ref in obj['external_references'] if
                             ref['source_name'] == 'mitre-attack'),
                            None
                        )
                        if technique_id:
                            techniques[technique_id] = obj['name']

    # Формирование данных для таблицы
    table_data = [['ID объекта', 'ID техники', 'ID уязвимости', 'Название объекта защиты']]  # Заголовок таблицы
    for obj_id, tech_id, cve_id, obj_name in data_list:
        technique_name = techniques.get("T"+tech_id, "Неизвестная техника")
        table_data.append([
            Paragraph("O"+str(obj_id), default_style),
            Paragraph(f"{tech_id}. {translate_text(technique_name.replace('-', ' '))}", default_style),
            Paragraph(cve_id, default_style),
            Paragraph(obj_name, default_style),
        ])

    # Создание таблицы
    table = Table(table_data, colWidths=[100, 200, 100, 200])  # Ширина столбцов
    table.setStyle(common_table_style)

    # Формирование заголовка таблицы
    title = Paragraph("Таблица 3 – Объекты защиты", header_style)

    return [table, title]

def create_table_4(data_list):
    """
    Создает таблицу в формате ReportLab, отображающую данные о нарушителях, технику MITRE, CVE и объект.

    :param data_list: Список кортежей (id нарушителя, тип нарушителя, id техники, id уязвимости, id объекта, мотивация).
    :param json_folder_path: Путь к папке с JSON-файлами MITRE.
    :return: Список элементов ReportLab для включения в PDF.
    """

    json_folder_path = "C:\PycharmProjects\diplom\Mitre Teckniques"

    # Загрузка данных о техниках из JSON-файлов
    techniques = {}
    for filename in os.listdir(json_folder_path):
        if filename.endswith('.json'):
            with open(os.path.join(json_folder_path, filename), 'r', encoding='utf-8') as file:
                json_data = json.load(file).get("objects", [])
                for obj in json_data:
                    if obj['type'] == 'attack-pattern' and obj['external_references']:
                        technique_id = next(
                            (ref['external_id'] for ref in obj['external_references'] if
                             ref['source_name'] == 'mitre-attack'),
                            None
                        )
                        if technique_id:
                            techniques[technique_id] = obj['name']

    # Формирование данных для таблицы
    table_data = [['ID нарушителя', 'Тип нарушителя', 'Техника MITRE', 'ID уязвимости', 'ID объекта', 'Мотивация нарушителя']]  # Заголовок таблицы
    for actor_id, actor_type, tech_id, cve_id, obj_id, motivation in data_list:
        technique_name = techniques.get(f"T{tech_id}", "Неизвестная техника")
        table_data.append([
            Paragraph(f"N{actor_id}", default_style),
            Paragraph(actor_type, default_style),
            Paragraph(f"T{tech_id}. {translate_text(technique_name.replace('-', ' '))}", default_style),
            Paragraph(cve_id, default_style),
            Paragraph(f"O{obj_id}", default_style),
            Paragraph(motivation, default_style),
        ])

    # Создание таблицы
    table = Table(table_data, colWidths=[40, 100, 130, 120, 40, 150])  # Ширина столбцов
    table.setStyle(common_table_style)

    # Формирование заголовка таблицы
    title = Paragraph("Таблица 4 – Модель нарушителя", header_style)

    return [table, title]

def create_table_5(detections):
    """
    Создает таблицу в формате ReportLab, отображающую данные о техниках MITRE и мерах обнаружения.

    :param detections: Словарь, где ключи — ID техник MITRE, а значения — список кортежей (ID меры, категория меры, название меры, регламент).
    :return: Список элементов ReportLab для включения в PDF.
    """

    # Формирование данных для таблицы
    table_data = [['id Техники', 'id Меры', 'Название меры обнаружения', 'Регламент обнаружения и регистрации']]  # Заголовок таблицы

    for technique_id, measures in detections.items():
        for measure_id, _, measure_name, measure_regulation in measures:
            table_data.append([
                Paragraph(f"{technique_id}", default_style),
                Paragraph(measure_id, default_style),
                Paragraph(translate_text(measure_name.replace('-', ' ')), default_style),
                Paragraph(translate_text(measure_regulation.replace('-', ' ')), default_style),
            ])

    # Создание таблицы
    table = Table(table_data, colWidths=[65, 70, 100, 355])  # Ширина столбцов
    table.setStyle(common_table_style)
    table.splitByRow = True

    # Формирование заголовка таблицы
    title = Paragraph("Таблица 5 – Меры обнаружения инцидентов относительно техники", header_style)

    return [table, title]

def create_table_6(mitigations):
    """
    Создает таблицу в формате ReportLab, отображающую данные о техниках MITRE и мерах ликвидации последствий.

    :param mitigations: Словарь, где ключи — ID техник MITRE, а значения — список кортежей (ID меры, название меры, регламент).
    :return: Список элементов ReportLab для включения в PDF.
    """

    # Формирование данных для таблицы
    table_data = [['id Техники', 'id Меры', 'Название меры ликвидации последствий', 'Регламент ликвидации последствий']]  # Заголовок таблицы

    for technique_id, measures in mitigations.items():
        for measure_id, measure_name, measure_regulation in measures:
            table_data.append([
                Paragraph(technique_id, default_style),
                Paragraph(measure_id, default_style),
                Paragraph(translate_text(measure_name.replace('-', ' ')), default_style),
                Paragraph(translate_text(measure_regulation.replace('-', ' ')), default_style),
            ])

    # Создание таблицы
    table = Table(table_data, colWidths=[70, 70, 70, 400])  # Ширина столбцов
    table.setStyle(common_table_style)
    table.splitByRow = True

    # Формирование заголовка таблицы
    title = Paragraph("Таблица 6 – Меры ликвидации последствий инцидентов относительно техники", header_style)

    return [table, title]

def create_table_7(data_list):
    """
    Создает таблицу в формате ReportLab для отображения должностей и компетенций сотрудников ИБ.

    :param data_list: Список кортежей (id должности, название должности, id техники, список компетенций).
    :return: Список элементов ReportLab для включения в PDF.
    """

    # Заголовок таблицы
    table_data = [['id Должности', 'Должность ИБ', 'id Техники', 'Компетенции сотрудника ИБ']]  # Заголовок таблицы

    for position_id, position_name, technique_id, competencies in data_list:
        # Объединяем список компетенций в строку
        competencies_str = ', '.join(competencies)

        table_data.append([
            Paragraph(f"E{position_id}", default_style),  # Форматирование ID должности
            Paragraph(position_name, default_style),  # Название должности
            Paragraph(technique_id, default_style),  # ID техники
            Paragraph(competencies_str, default_style)  # Компетенции сотрудника
        ])

    # Создание таблицы
    table = Table(table_data, colWidths=[40, 100, 60, 400])  # Ширина столбцов
    table.setStyle(common_table_style)
    table.splitByRow = True

    # Формирование заголовка таблицы
    title = Paragraph("Таблица 7 – Функциональные знания и умения", header_style)

    return [table, title]

def create_table_8(data_list):
    """
    Создает таблицу в формате ReportLab для отображения информации по технике.

    :param data_list: Список кортежей (id Техники, Требования к сотрудникам, Название СЗИ, Функции СЗИ).
    :return: Список элементов ReportLab для включения в PDF.
    """
    # Заголовок таблицы
    table_data = [['id Техники', 'Требования к сотрудникам', 'Название СЗИ', 'Функции СЗИ']]

    for technique_id, requirements, zsi_name, zsi_functions in data_list:
        table_data.append([
            Paragraph(technique_id, default_style),
            Paragraph(requirements, default_style),
            Paragraph(zsi_name, default_style),
            Paragraph(zsi_functions, default_style)
        ])

    # Создание таблицы
    table = Table(table_data, colWidths=[60, 200, 150, 200])  # Задаем ширину столбцов
    table.setStyle(common_table_style)

    # Формирование заголовка таблицы
    title = Paragraph("Таблица 8 – Описание функций выбранных СЗИ", header_style)

    return [table, title]

def create_pdf(tables, output_file):
    """
    Создает PDF-файл с несколькими таблицами.

    :param tables: Список таблиц для добавления в PDF
    :param output_file: Имя выходного PDF-файла
    """
    # Создаем PDF-документ
    pdf = SimpleDocTemplate(output_file, pagesize=letter)

    # Список элементов для PDF-документа
    elements = []

    # Добавляем все таблицы в элементы
    for table in tables:
        # Добавляем заголовок таблицы
        elements.append(table[1])

        # Добавляем таблицу
        elements.append(table[0])

        # Добавляем отступ после таблицы
        elements.append(Paragraph("<br/><br/>", default_style))  # Пустой абзац для отступа

    # Генерируем PDF
    pdf.build(elements)

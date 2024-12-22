import json

# Чтение данных из файла с указанием кодировки
with open('output.json', 'r', encoding='utf-8') as file:
    data = json.load(file)

# Группы для вычислений
groups = [
    ["1498.001", "1499"],
    ["1562.003", "1574.006", "1574.007"],
    ["1003", "1119", "1213", "1530", "1555", "1602"],
    ["1534", "1566.001", "1566.002", "1566.003", "1598.001", "1598.002", "1598.003"],
    ["1217", "1592", "1595"]
]

# Создаем словарь для быстрого поиска данных по Entry_ID
data_dict = {}
for item in data:
    if "Entry_ID" in item:  # Проверка наличия ключа Entry_ID
        data_dict[item["Entry_ID"]] = item

# Процесс добавления новых ключей для каждой группы
for group in groups:
    # Инициализация для каждой группы
    group_max_probability = 1
    group_min_probability = 1
    group_max_damage = 0
    group_min_damage = 0

    # Для каждого Entry_ID в группе
    for entry_id in group:
        if entry_id in data_dict:
            item = data_dict[entry_id]
            
            # Для Probability — перемножаем значения
            group_max_probability *= item['Max_Probability']
            group_min_probability *= item['Min_Probability']
            
            # Для Damage — складываем значения
            group_max_damage += item['Max_Damage']
            group_min_damage += item['Min_Damage']
    
    # Применяем полученные значения для всех Entry_ID в группе
    for entry_id in group:
        if entry_id in data_dict:
            item = data_dict[entry_id]
            # Добавляем новые вычисленные поля
            item['Max_allProbability'] = group_max_probability
            item['Min_allProbability'] = group_min_probability
            item['Max_allDamage'] = group_max_damage
            item['Min_allDamage'] = group_min_damage

# Запись обновленных данных обратно в файл
with open('output_updated.json', 'w', encoding='utf-8') as file:
    json.dump(data, file, indent=4, ensure_ascii=False)


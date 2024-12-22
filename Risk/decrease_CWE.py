import xml.etree.ElementTree as ET

# Функция для извлечения всех Weakness и записи их в новый XML файл без пространства имен
def extract_weaknesses_to_new_xml(cwe_file_path, output_file_path):
    # Парсим исходный XML файл
    tree = ET.parse(cwe_file_path)
    root = tree.getroot()

    # Убираем пространство имен из тегов
    for elem in root.iter():
        elem.tag = elem.tag.split('}')[-1]  # Оставляем только имя тега без пространства имен

    # Находим все элементы <Weakness> в <Weaknesses>
    weaknesses = root.findall(".//Weakness")

    # Создаем новый элемент корня для нового документа
    new_root = ET.Element("Weaknesses")

    # Копируем все найденные элементы <Weakness> в новый корень
    for weakness in weaknesses:
        new_root.append(weakness)

    # Создаем новый объект ElementTree с новым корнем
    new_tree = ET.ElementTree(new_root)

    # Записываем новый XML файл
    new_tree.write(output_file_path, encoding="utf-8", xml_declaration=True)

    print(f"Все данные в <Weaknesses> записаны в файл {output_file_path}.")

# Указываем пути к файлам
cwe_file = "cwec_v4.15.xml"  # Путь к исходному файлу
output_file = "extracted_weaknesses.xml"  # Путь к новому файлу

# Извлекаем данные и записываем в новый XML файл
extract_weaknesses_to_new_xml(cwe_file, output_file)

import os
import zipfile
import json

def extract_and_merge_zip_files(folder_path, output_file="C:\\PycharmProjects\\diplom\\CVE2CAPEC\\resultscve\\merged_data.json"):
    """
    Извлекает данные из всех ZIP-файлов в папке и объединяет их в один JSON-файл.
    """
    merged_data = []

    for file_name in os.listdir(folder_path):
        if file_name.endswith('.json.zip'):
            zip_path = os.path.join(folder_path, file_name)

            with zipfile.ZipFile(zip_path, 'r') as z:
                json_file_name = z.namelist()[0]  # Предполагается, что в архиве только один JSON-файл
                with z.open(json_file_name) as f:
                    data = json.load(f)
                    merged_data.extend(data.get('CVE_Items', []))  # Добавляем все CVE_Items в общий список

    # Сохраняем объединенные данные в общий файл
    with open(output_file, "w", encoding="utf-8") as file:
        json.dump(merged_data, file, ensure_ascii=False, indent=4)

    print(f"Данные из ZIP-файлов объединены в {output_file}.")

# Путь к папке с архивами
folder_path = "C:\\PycharmProjects\\diplom\\CVE2CAPEC\\resultscve"

# Выполняем единожды распаковку и объединение
extract_and_merge_zip_files(folder_path)


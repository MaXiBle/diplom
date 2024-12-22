# 1.6. Вариант с нейросетью

import pandas as pd
import numpy as np
from sklearn.metrics.pairwise import cosine_similarity
from transformers import BertTokenizer, BertModel
import torch
from tqdm import tqdm  # Импортируем tqdm для отображения прогресса

# Загрузка модели BERT и токенизатора
tokenizer = BertTokenizer.from_pretrained('bert-base-uncased')
model = BertModel.from_pretrained('bert-base-uncased')


def encode_text(text):
    """Функция для кодирования текста в векторное представление с помощью BERT."""
    inputs = tokenizer(text, return_tensors='pt', padding=True, truncation=True)
    with torch.no_grad():
        outputs = model(**inputs)
    # Берем средний вектор по всем токенам
    return outputs.last_hidden_state.mean(dim=1).numpy()


def load_data():
    """Загрузка данных из CSV файлов в DataFrame."""
    objects_df = pd.read_csv("../Объекты защиты.csv")  # Предполагаем, что этот файл существует
    cve_data = pd.read_csv("../описание_cve.csv")  # Предполагаем, что этот файл существует
    cwe_data = pd.read_csv("../описание_CWE.csv")  # Предполагаем, что этот файл существует
    capec_data = pd.read_csv("../описание_capec.csv")  # Предполагаем, что этот файл существует
    technique_data = pd.read_csv("../описание_technique.csv")  # Предполагаем, что этот файл существует
    return objects_df, cve_data, cwe_data, capec_data, technique_data


def get_descriptions(input_dict, cve_data, cwe_data, capec_data, technique_data):
    """Получение описаний на основе предоставленного входного словаря."""
    descriptions = []

    # Получение описаний CVE
    for cve in input_dict.get("cve", []):
        description = cve_data[cve_data['id'] == cve]['description']
        if not description.empty:
            descriptions.append(description.values[0])

    # Получение описаний CWE
    for cwe in input_dict.get("cwe", []):
        description = cwe_data[cwe_data['id'] == cwe]['description']
        if not description.empty:
            descriptions.append(description.values[0])

    # Получение описаний CAPEC
    for capec in input_dict.get("capec", []):
        description = capec_data[capec_data['id'] == capec]['description']
        if not description.empty:
            descriptions.append(description.values[0])

    # Получение описаний техник
    for technique in input_dict.get("technique", []):
        description = technique_data[technique_data['id'] == technique]['description']
        if not description.empty:
            descriptions.append(description.values[0])

    return descriptions


def find_similarity(objects_df, input_descriptions, similarity_threshold=0.8):
    """Расчет коэффициентов схожести для объектов защиты по входным описаниям."""
    # Кодируем описания объектов защиты
    print("Кодирование описаний объектов защиты...")
    objects_df['vector'] = [encode_text(desc) for desc in tqdm(objects_df['description'])]

    # Кодируем входные описания
    print("Кодирование входных описаний...")
    input_vectors = np.vstack([encode_text(desc) for desc in tqdm(input_descriptions)])

    # Вычисляем схожесть между векторами объектов и входными
    similarities = cosine_similarity(input_vectors, np.vstack(objects_df['vector'].values))

    # Собираем все совпадения с учетом порога схожести
    all_matches = []
    for i, row in enumerate(similarities):
        for j, score in enumerate(row):
            if score > similarity_threshold:  # Учитываем только значения схожести выше порога
                all_matches.append({
                    "object_id": objects_df.iloc[j]['id'],
                    "object_name": objects_df.iloc[j]['name'],  # Предполагаем, что имя в этом столбце
                    "similarity_score": score
                })

    # Создаем DataFrame из совпадений
    matches_df = pd.DataFrame(all_matches)
    return matches_df.groupby(['object_id', 'object_name'], as_index=False).agg(
        {'similarity_score': 'max'}).sort_values(by='similarity_score', ascending=False)



def main(input_dict):
    """Основная функция для обработки входного словаря и нахождения совпадений."""
    # Загрузка всех необходимых данных
    objects_df, cve_data, cwe_data, capec_data, technique_data = load_data()

    # Получение описаний на основе входных данных
    input_descriptions = get_descriptions(input_dict, cve_data, cwe_data, capec_data, technique_data)

    # Нахождение схожести
    all_matches_df = find_similarity(objects_df, input_descriptions)

    print("Все совпадающие объекты и их коэффициенты схожести:")
    print(all_matches_df)


# # Пример входного словаря
# input_dict = {
#     "cve": ["CVE-2023-32790", "CVE-2018-3820"],
#     "cwe": [707, 118, 74],
#     "capec": [267, 277],
#     "technique": ["T1130"]
# }
#
# if __name__ == "__main__":
#     main(input_dict)

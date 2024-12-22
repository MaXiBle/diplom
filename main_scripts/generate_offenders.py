import pandas as pd
import re
import nltk
from nltk.corpus import stopwords
from nltk.stem import WordNetLemmatizer
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

# Убедитесь, что ресурсы NLTK загружены
nltk.download('stopwords')
nltk.download('wordnet')
nltk.download('punkt')

# Определение стоп-слов и лемматизатора
stop_words = set(stopwords.words("english"))
lemmatizer = WordNetLemmatizer()


def preprocess_text(text):
    """Функция для предобработки текста: очистка, токенизация и лемматизация."""
    text = re.sub(r'[^\w\s]', '', text)  # Удаление специальных символов
    text = re.sub(r'\d+', '', text)  # Удаление цифр
    text = text.lower()  # Приведение к нижнему регистру
    words = nltk.word_tokenize(text)  # Токенизация
    words = [lemmatizer.lemmatize(word) for word in words if word not in stop_words]
    return " ".join(words)


def load_data():
    """Загрузка данных из CSV файлов в DataFrame."""
    violators_df = pd.read_csv("C:\\PycharmProjects\\diplom\\Нарушители.csv")  # Нарушители
    tecknique_data = pd.read_csv("C:\\PycharmProjects\\diplom\\описание_technique.csv")  # Описание техник
    cve_data = pd.read_csv("C:\\PycharmProjects\\diplom\\описание_cve.csv")  # Описание CVE
    objects_df = pd.read_csv("C:\\PycharmProjects\\diplom\\Объекты защиты.csv")  # Объекты защиты
    return violators_df, tecknique_data, cve_data, objects_df


def find_top_similarity(violators_df, description):
    """Находит нарушителя с максимальным сходством для данного описания."""
    # Предобработка описания
    description_processed = preprocess_text(description)

    # Предобработка описаний нарушителей
    violators_df['processed_description'] = violators_df['description'].apply(preprocess_text)

    # Создание модели TF-IDF
    vectorizer = TfidfVectorizer()
    tfidf_matrix_violators = vectorizer.fit_transform(violators_df['processed_description'])
    tfidf_description = vectorizer.transform([description_processed])

    # Вычисление косинусного сходства
    similarity_scores = cosine_similarity(tfidf_description, tfidf_matrix_violators).flatten()

    # Нахождение нарушителя с максимальным коэффициентом сходства
    max_index = similarity_scores.argmax()
    top_match = {
        "violator_id": violators_df.iloc[max_index]['id'],  # ID нарушителя
        "violator_type": violators_df.iloc[max_index]['type'],  # Тип нарушителя
        "motiv": violators_df.iloc[max_index]['motiv'],  # Мотив
    }

    return top_match


def main(pairs):
    """Основная функция для обработки списка пар и поиска наиболее похожих нарушителей."""
    print("Генерация модели нарушителя...\n")
    violators_df, tecknique_data, cve_data, objects_df = load_data()

    # Преобразование данных для ускорения поиска
    tecknique_data = tecknique_data.set_index('id') if not tecknique_data.empty else pd.DataFrame()
    cve_data = cve_data.set_index('id') if not cve_data.empty else pd.DataFrame()
    objects_df = objects_df.set_index('id') if not objects_df.empty else pd.DataFrame()

    results = []
    violator_type_to_id = {}
    current_id = 1

    for object_id, technique_id, cve_id in pairs:

        # Извлекаем описание для техники
        tecknique_description = tecknique_data.loc['T'+technique_id, 'description'] if 'T'+technique_id in tecknique_data.index else ""

        # Извлекаем описание для объекта защиты
        object_description = objects_df.loc[int(object_id), 'description'] if int(object_id) in objects_df.index else ""

        # Проверяем, нужно ли добавлять описание CVE
        if cve_id != "-":
            cve_description = cve_data.loc[cve_id, 'description'] if cve_id in cve_data.index else " "
            # Объединяем описания
            combined_description = " ".join(filter(None, [tecknique_description, cve_description, object_description]))
        else:
            combined_description = " ".join(filter(None, [tecknique_description, object_description]))

        if combined_description:
            top_match = find_top_similarity(violators_df, combined_description)
            violator_type = top_match["violator_type"]

            # Проверяем, есть ли уже violator_type в словаре
            if violator_type not in violator_type_to_id:
                violator_type_to_id[violator_type] = current_id
                current_id += 1

            # Добавляем результат с уникальным ID для violator_type
            results.append((
                violator_type_to_id[violator_type],  # Уникальный ID для violator_type
                violator_type,
                technique_id,
                cve_id,
                object_id,
                top_match["motiv"]
            ))

    # Сортировка результатов по уникальному ID нарушителя
    results.sort(key=lambda x: x[0])

    return results

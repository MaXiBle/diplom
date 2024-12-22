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
    objects_df = pd.read_csv("C:\\PycharmProjects\\diplom\\Объекты защиты.csv")  # Объекты защиты
    tecknique_data = pd.read_csv("C:\\PycharmProjects\\diplom\\описание_technique.csv")  # Описание техник
    cve_data = pd.read_csv("C:\\PycharmProjects\\diplom\\описание_cve.csv")  # Описание CVE
    return objects_df, tecknique_data, cve_data


def find_top_similarity(objects_df, description):
    """Находит объект защиты с максимальным сходством для данного описания."""
    # Предобработка описания
    description_processed = preprocess_text(description)

    # Предобработка описаний объектов защиты
    objects_df['processed_description'] = objects_df['description'].apply(preprocess_text)

    # Создание модели TF-IDF
    vectorizer = TfidfVectorizer()
    tfidf_matrix_objects = vectorizer.fit_transform(objects_df['processed_description'])
    tfidf_description = vectorizer.transform([description_processed])

    # Вычисление косинусного сходства
    similarity_scores = cosine_similarity(tfidf_description, tfidf_matrix_objects).flatten()

    # Нахождение объекта с максимальным коэффициентом сходства
    max_index = similarity_scores.argmax()
    top_match = {
        "object_name": objects_df.iloc[max_index]['name'],  # Имя объекта защиты
        "object_id": objects_df.iloc[max_index]['id']  # ID объекта защиты
    }

    return top_match


def main(pairs):
    """Основная функция для обработки списка пар и поиска наиболее похожих объектов защиты."""
    print("Генерация объектов защиты...\n")
    objects_df, tecknique_data, cve_data = load_data()

    # Преобразование данных для ускорения поиска
    tecknique_data = tecknique_data.set_index('id') if not tecknique_data.empty else pd.DataFrame()
    cve_data = cve_data.set_index('id') if not cve_data.empty else pd.DataFrame()

    results = []
    object_name_to_id = {}
    current_id = 1

    for technique_id, cve_id in pairs:
        # Извлекаем описание для техники
        tecknique_description = tecknique_data.loc['T'+technique_id, 'description'] if 'T'+technique_id in tecknique_data.index else ""

        # Проверяем, нужно ли добавлять описание CVE
        if cve_id != "-":
            cve_description = cve_data.loc[cve_id, 'description'] if cve_id in cve_data.index else " "
            # Объединяем описания
            combined_description = " ".join(filter(None, [tecknique_description, cve_description]))
        else:
            combined_description = tecknique_description

        if combined_description:
            top_match = find_top_similarity(objects_df, combined_description)
            object_name = top_match["object_name"]

            # Проверяем, есть ли уже object_name в словаре
            if object_name not in object_name_to_id:
                object_name_to_id[object_name] = current_id
                current_id += 1

            # Добавляем результат с уникальным ID
            results.append((
                object_name_to_id[object_name],
                technique_id,
                cve_id,
                object_name
            ))

    # Сортировка результатов по ID объекта
    results.sort(key=lambda x: x[0])

    return results

import json
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
import re
import nltk
from nltk.corpus import stopwords
from nltk.stem import WordNetLemmatizer

# Загрузка ресурсов NLTK
nltk.download('punkt')
nltk.download('stopwords')
nltk.download('wordnet')

# Определение стоп-слов и лемматизатора
stop_words = set(stopwords.words("english"))
lemmatizer = WordNetLemmatizer()


# Предобработка текста
def preprocess_text(text):
    text = re.sub(r'[^\w\s]', '', text)  # Удаление специальных символов
    text = re.sub(r'\d+', '', text)  # Удаление цифр
    text = text.lower()  # Приведение к нижнему регистру
    words = nltk.word_tokenize(text)  # Токенизация
    words = [lemmatizer.lemmatize(word) for word in words if word not in stop_words]
    return " ".join(words)


# Основная функция
def match_techniques_with_szi(technique_ids):
    print("Генерация средств защиты информации...\n")
    # Пути к файлам
    techniques_csv = r"C:\PycharmProjects\diplom\описание_technique.csv"
    szi_json = r"C:\PycharmProjects\diplom\СЗИ.json"

    # Загрузка данных
    techniques = pd.read_csv(techniques_csv)
    with open(szi_json, encoding='utf-8') as f:
        szi_data = json.load(f)

    # Фильтрация техник по заданным ID
    techniques = techniques[techniques['id'].isin(technique_ids)]

    # Предобработка описаний техник
    techniques['processed_description'] = techniques['description'].apply(preprocess_text)

    # Создание текстов для СЗИ
    szi_descriptions = []
    szi_mappings = []  # Хранит оригинальные данные для вывода
    for entry in szi_data:
        en_data = entry['en']
        ru_data = entry['ru']
        concatenated_text = f"{en_data['Requirements for employees']} {en_data['Function']}"
        szi_descriptions.append(preprocess_text(concatenated_text))
        szi_mappings.append((ru_data['Requirements for employees'], ru_data['Name'], ru_data['Function']))

    # Создание TF-IDF матрицы для СЗИ
    vectorizer = TfidfVectorizer()
    szi_matrix = vectorizer.fit_transform(szi_descriptions)

    results = []

    # Сравнение каждой техники с описаниями СЗИ
    for _, technique in techniques.iterrows():
        technique_id = technique['id']
        technique_desc = technique['processed_description']
        technique_vector = vectorizer.transform([technique_desc])

        # Вычисление сходства
        similarity_scores = cosine_similarity(technique_vector, szi_matrix).flatten()

        # Находим СЗИ с максимальным сходством
        best_match_index = similarity_scores.argmax()
        best_szi = szi_mappings[best_match_index]

        # Добавляем результат
        results.append((technique_id, *best_szi))

    return results
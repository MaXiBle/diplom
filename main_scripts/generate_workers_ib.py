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

# Функция для обработки данных и сопоставления компетенций и техник
def match_competencies_with_techniques(technique_ids):
    print("Генерация компетенций сотрудников...\n")
    json_file = "C:\PycharmProjects\diplom\Компетенции.json"
    techniques_csv = "C:\PycharmProjects\diplom\описание_technique.csv"

    # Загрузка JSON-файла с компетенциями
    with open(json_file, encoding='utf-8') as f:
        competencies = json.load(f)

    for i in range(len(technique_ids)):
        technique_ids[i] = 'T'+technique_ids[i]

    # Загрузка CSV-файла с техниками
    techniques = pd.read_csv(techniques_csv)
    techniques = techniques[techniques['id'].isin(technique_ids)]  # Фильтрация по списку ID

    # Предобработка описаний техник
    techniques['processed_description'] = techniques['description'].apply(preprocess_text)

    results = []

    # Перебор сотрудников
    for emp_index, (role, data) in enumerate(competencies.items()):
        employee_competencies = data["Компетенции сотрудника ИБ"]

        # Список компетенций для текущего сотрудника
        competencies_list = [comp[2] for comp in employee_competencies]  # Берём английские описания
        competencies_processed = [preprocess_text(comp) for comp in competencies_list]

        # Создание TF-IDF матрицы для компетенций сотрудника
        vectorizer = TfidfVectorizer()
        competency_matrix = vectorizer.fit_transform(competencies_processed)

        # Перебор техник
        for _, technique in techniques.iterrows():
            technique_id = technique['id']
            technique_desc = technique['processed_description']

            # TF-IDF для описания техники
            technique_vector = vectorizer.transform([technique_desc])

            # Расчёт косинусного сходства
            similarity_scores = cosine_similarity(technique_vector, competency_matrix).flatten()

            # Нахождение топ-10 компетенций
            top_indices = similarity_scores.argsort()[-10:][::-1]
            top_competencies = [employee_competencies[i][1] for i in top_indices]  # Берём русские описания

            # Добавление результата
            results.append((emp_index+1, role, technique_id, top_competencies))

    return results
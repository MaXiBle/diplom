from transformers import MarianMTModel, MarianTokenizer
import os

# Отключение предупреждения о символьных ссылках
os.environ["HF_HUB_DISABLE_SYMLINKS_WARNING"] = "1"

# Загрузка модели и токенизатора
model_name = "Helsinki-NLP/opus-mt-en-ru"
tokenizer = MarianTokenizer.from_pretrained(model_name)
model = MarianMTModel.from_pretrained(model_name)

def split_text(text, max_length=512):
    """
    Разделяет текст на части, чтобы каждая часть была не больше max_length токенов.
    """
    words = text.split()  # Разбиваем текст на слова
    chunks = []
    current_chunk = []

    for word in words:
        # Проверяем длину текущего пакета в токенах
        current_chunk.append(word)
        if len(tokenizer(" ".join(current_chunk), return_tensors="pt")["input_ids"][0]) > max_length:
            # Если превышен лимит, добавляем текущий пакет в список и начинаем новый
            chunks.append(" ".join(current_chunk[:-1]))
            current_chunk = [word]

    # Добавляем последний пакет
    if current_chunk:
        chunks.append(" ".join(current_chunk))

    return chunks

def translate(text):
    """
    Переводит текст с английского на русский.
    """
    # Токенизация текста
    inputs = tokenizer(text, return_tensors="pt", padding=True, truncation=True)
    # Генерация перевода
    translated = model.generate(**inputs)
    # Декодирование перевода
    translated_text = tokenizer.decode(translated[0], skip_special_tokens=True)
    return translated_text

def translate_text(text, max_length=512):
    """
    Переводит текст любой длины, разбивая его на части при необходимости.
    """
    # Разбиваем текст на части
    chunks = split_text(text, max_length)
    # Переводим каждую часть
    translations = [translate(chunk) for chunk in chunks]
    # Объединяем переводы в единый текст
    return " ".join(translations)

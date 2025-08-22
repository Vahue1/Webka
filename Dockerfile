# Webka – LagSw Key Verifier
FROM python:3.12-slim

# Создадим рабочую директорию
WORKDIR /app

# Установим зависимости для Python
COPY backend/requirements.txt /app/backend/requirements.txt
RUN pip install --no-cache-dir -r /app/backend/requirements.txt

# Скопируем весь проект
COPY . /app

# Создадим каталог для базы и загрузок
RUN mkdir -p /data /app/downloads

# Переменные окружения
ENV PYTHONUNBUFFERED=1
ENV PORT=8080

# Запускаем наш сервер
CMD ["python", "backend/verifier.py", "serve",
     "--host", "0.0.0.0",
     "--port", "8080",
     "--static-dir", "frontend",
     "--downloads-dir", "downloads",
     "--db", "/data/keys.db"]

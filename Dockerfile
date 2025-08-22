# Webka – LagSw Key Verifier
FROM python:3.12-slim

WORKDIR /app
COPY . /app

# Непривилегированный пользователь и каталог под БД/загрузки
RUN useradd -m -u 10001 appuser && \
    mkdir -p /data /app/downloads && \
    chown -R appuser:appuser /app /data
USER appuser

EXPOSE 8080
ENV PYTHONUNBUFFERED=1

# ВАЖНО: --db до подкоманды serve
CMD ["python","backend/verifier.py","--db","/data/keys.db","serve","--host","0.0.0.0","--port","8080","--static-dir","frontend","--downloads-dir","downloads"]

# syntax=docker/dockerfile:1
FROM python:3.12-slim AS builder
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

FROM python:3.12-slim
WORKDIR /app
COPY --from=builder /root/.local /root/.local
COPY security/ .
ENV PATH=/root/.local/bin:$PATH

# Создаём non-root пользователя
RUN addgroup --gid 1001 appgroup && \
    adduser --uid 1001 --gid 1001 --disabled-password --gecos "" appuser

USER appuser

CMD ["python", "main.py"]  # или конкретный файл, напр. integrity.py если отдельно

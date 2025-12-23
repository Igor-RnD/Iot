# syntax=docker/dockerfile:1

# Стадия сборки зависимостей
FROM python:3.12-alpine AS builder

WORKDIR /app

COPY requirements.txt .
RUN apk add --no-cache gcc musl-dev libffi-dev && \
    pip install --no-cache-dir --user -r requirements.txt && \
    apk del gcc musl-dev libffi-dev

# Финальная стадия — минимальный образ
FROM python:3.12-alpine

WORKDIR /app

COPY --from=builder /root/.local /root/.local
ENV PATH=/root/.local/bin:$PATH

# Копируем только код устройств
COPY devices/ .

# Создаём непривилегированного пользователя
RUN addgroup -g 1001 devices && \
    adduser -u 1001 -G devices -D devicesuser && \
    chown -R devicesuser:devices /app

USER devicesuser

# Запускаем главный файл устройств (можно менять через ENTRYPOINT или CMD)
CMD ["python", "main_devices.py"]

# syntax=docker/dockerfile:1

# Стадия сборки зависимостей
FROM python:3.12-alpine AS builder

WORKDIR /app

# Устанавливаем только необходимые системные пакеты для cryptography (если нужен)
RUN apk add --no-cache gcc musl-dev libffi-dev

COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Финальная стадия — минимальный и безопасный образ
FROM python:3.12-alpine

WORKDIR /app

# Копируем только установленные Python-пакеты
COPY --from=builder /root/.local /root/.local
ENV PATH=/root/.local/bin:$PATH

# Копируем код контроллера и критичные модули (TCB)
COPY controller/ .
COPY security/ ./security/          # Важно: TCB доступен внутри контейнера

# Создаём непривилегированного пользователя
RUN addgroup -g 1001 controller && \
    adduser -u 1001 -G controller -D controlleruser && \
    chown -R controlleruser:controller /app

# Запускаем от непривилегированного пользователя
USER controlleruser

# Открываем только нужный порт (если используешь API, например, Flask/FastAPI)
# EXPOSE 8000

CMD ["python", "main.py"]

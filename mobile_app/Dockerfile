# syntax=docker/dockerfile:1

# Стадия сборки
FROM python:3.12-alpine AS builder

WORKDIR /app

# Устанавливаем зависимости (cryptography и т.д.)
RUN apk add --no-cache gcc musl-dev libffi-dev

COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Финальная стадия — минимальный образ
FROM python:3.12-alpine

WORKDIR /app

# Копируем только необходимые пакеты
COPY --from=builder /root/.local /root/.local
ENV PATH=/root/.local/bin:$PATH

# Копируем код мобильного приложения
COPY mobile_app/ .

# Создаём непривилегированного пользователя
RUN addgroup -g 1001 mobile && \
    adduser -u 1001 -G mobile -D mobileuser && \
    chown -R mobileuser:mobile /app

USER mobileuser

CMD ["python", "mobile_app.py"]

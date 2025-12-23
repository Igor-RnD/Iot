# syntax=docker/dockerfile:1

# Стадия сборки зависимостей
FROM python:3.12-slim AS builder

WORKDIR /app

# Устанавливаем зависимости без кэша
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Финальная стадия — минимальный образ
FROM python:3.12-slim

WORKDIR /app

# Копируем только установленные пакеты
COPY --from=builder /root/.local /root/.local
ENV PATH=/root/.local/bin:$PATH

# Копируем код монитора
COPY monitor/ .

# Создаём непривилегированного пользователя
RUN addgroup --gid 1001 monitor && \
    adduser --uid 1001 --gid 1001 --disabled-password --gecos "" monitoruser && \
    chown -R monitoruser:monitor /app

# Запускаем от имени непривилегированного пользователя
USER monitoruser

# Запускаем монитор
CMD ["python", "monitor.py"]

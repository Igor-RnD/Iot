import time
import logging
from datetime import datetime
from typing import Dict, Any

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler("/app/logs/monitor.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("SecurityMonitor")

# Пример: в реальном проекте это может быть очередь (Redis, RabbitMQ) или shared volume
# Здесь для простоты — имитация получения событий
def get_events() -> list[Dict[str, Any]]:
    """Имитация получения событий из других контейнеров"""
    # В реальности: чтение из shared volume, Docker socket, или message broker
    return [
        {"type": "access_denied", "source": "controller", "details": "Invalid signature", "timestamp": time.time()},
        {"type": "integrity_violation", "source": "devices/lock", "details": "Firmware hash mismatch", "timestamp": time.time()},
        {"type": "normal", "source": "controller", "details": "Command executed", "timestamp": time.time()},
    ]


def is_critical_event(event: Dict[str, Any]) -> bool:
    """Определяем, является ли событие критичным"""
    critical_types = {"access_denied", "integrity_violation"}
    return event.get("type") in critical_types


def send_notification(event: Dict[str, Any]):
    """Имитация отправки уведомления пользователю"""
    # В реальном проекте: push через BLE, MQTT, или локальный канал
    timestamp = datetime.fromtimestamp(event["timestamp"]).strftime("%Y-%m-%d %H:%M:%S")
    message = (
        f"[ALERT] Критичное событие: {event['type']} "
        f"от {event['source']} в {timestamp}\n"
        f"Детали: {event['details']}"
    )
    logger.warning(message)
    # Здесь можно добавить: отправка push, запись в защищённый лог и т.д.


def main():
    logger.info("Security Monitor started")
    logger.info("Monitoring events from all domains...")

    while True:
        try:
            events = get_events()
            for event in events:
                logger.info(f"Event received: {event['type']} from {event['source']}")

                if is_critical_event(event):
                    send_notification(event)
                    # Здесь можно добавить автоматические действия:
                    # - запись в quarantine-файл
                    # - сигнал в controller для блокировки
                    # - обновление метрик

        except Exception as e:
            logger.error(f"Monitor error: {e}")

        time.sleep(5)  # Частота проверки — каждые 5 секунд


if __name__ == "__main__":
    main()

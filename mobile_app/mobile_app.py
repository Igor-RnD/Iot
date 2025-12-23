# mobile_app/mobile_app.py
# Имитация мобильного приложения пользователя

import time
import logging
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [MOBILE] %(levelname)s %(message)s'
)
log = logging.getLogger("MobileApp")

class MobileApp:
    def __init__(self, user_name="admin"):
        self.user_name = user_name
        self.private_key = None
        self.public_key = None
        self._generate_or_load_key()  # Имитация TEE — ключ "внутри устройства"

        log.info(f"Mobile App initialized for user: {user_name}")
        log.info("Private key securely stored in TEE (simulated)")

    def _generate_or_load_key(self):
        """Генерация или загрузка ключевой пары (имитация TEE/TPM)"""
        # В реальном приложении ключ хранится в Secure Enclave / Titan M / TPM
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.public_key = self.private_key.public_key()

    def get_public_key_pem(self) -> bytes:
        """Возвращает публичный ключ для регистрации в Security Controller"""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def sign_command(self, command: str) -> (bytes, bytes):
        """
        Формирует и подписывает команду в доверенной среде
        Возвращает: (message_bytes, signature_bytes)
        """
        message = command.encode("utf-8")
        signature = self.private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        log.info(f"Command '{command}' signed in TEE")
        return message, signature

    def send_command(self, command: str):
        """Имитация отправки команды в Security Controller"""
        message, signature = self.sign_command(command)

        log.info(f"Sending command to Internal Gateway: {command}")
        # В реальном проекте — HTTP/gRPC/MQTT/BLE отправка на controller
        # Здесь — просто возвращаем для теста
        return {
            "user": self.user_name,
            "message": message,
            "signature": signature,
            "timestamp": time.time()
        }


def main():
    app = MobileApp("admin")

    # Публичный ключ нужно один раз зарегистрировать в Security Controller
    public_pem = app.get_public_key_pem()
    log.info("Public key for registration (send to admin once):")
    print(public_pem.decode())

    print("\n" + "="*50)
    log.info("Simulating user actions...")

    # Нормальные команды
    commands = [
        "OPEN_LOCK",
        "CLOSE_LOCK",
        "OPEN_GARAGE",
        "READ_CAMERA LivingRoomCam",
        "TRIGGER_ALARM OFF"
    ]

    for cmd in commands:
        result = app.send_command(cmd)
        log.info(f"Command packet ready: {cmd}")
        time.sleep(2)

    # Попытка вредоносной команды (будет отклонена на контроллере)
    log.warning("Simulating malicious attempt...")
    app.send_command("FORMAT_DISK")  # Не в whitelist — будет заблокировано

    log.info("Mobile App demo finished")


if __name__ == "__main__":
    main()

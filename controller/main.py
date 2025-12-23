# controller/main.py

import time
import logging
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

# Импорты из TCB (домен security)
from security.policy import PolicyStore
from security.session import SessionStore
from security.auth import AuthService
from security.integrity import IntegrityModule

# Для простоты — имитация устройств (в реальности через message broker или Docker network)
from devices.lock import Lock
from devices.camera import Camera

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[logging.StreamHandler()]
)
log = logging.getLogger("SecurityController")

class SecurityController:
    def __init__(self):
        self.policy = PolicyStore()
        self.auth = AuthService()
        self.sessions = SessionStore()
        self.integrity = IntegrityModule()
        self.user_public_keys = {}          # Загружаются из Policy & Key Store / TPM
        self.devices = {}

        # Регистрация устройств (в реальности — динамически)
        self.register_device(Lock("FrontDoorLock"))
        self.register_device(Camera("LivingRoomCam"))

        # Загрузка публичных ключей пользователей (имитация из TPM)
        self.load_user_keys()

        log.info("Security Controller initialized (Internal Gateway active)")

    def load_user_keys(self):
        # В реальности — из TPM или зашифрованного хранилища
        # Здесь — генерация для демо
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()

        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.user_public_keys["admin"] = public_key
        log.info("Loaded public key for user 'admin'")

        # Возвращаем приватный ключ для мобильного приложения (только для теста!)
        return private_key

    def register_device(self, device):
        self.devices[device.name] = device
        self.integrity.register(device)
        log.info(f"Device registered: {device.name}")

    def verify_signature(self, public_key, message: bytes, signature: bytes) -> bool:
        try:
            public_key.verify(
                signature,
                message,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
            return True
        except Exception as e:
            log.warning(f"Signature verification failed: {e}")
            return False

    def process_command(self, session: dict, message: bytes, signature: bytes):
        """Основная функция — единственная точка входа для всех команд"""
        user = session["user"]
        role = session["role"]
        public_key = self.user_public_keys.get(user)

        if not public_key or not self.verify_signature(public_key, message, signature):
            log.warning(f"[{user}] Invalid or missing signature — command rejected")
            return False

        command = message.decode("utf-8")
        log.info(f"[{user}] Command received: {command}")

        if not self.policy.is_allowed(role, command):
            log.warning(f"[{user}] RBAC denied: {command}")
            return False

        # Рассылка команды устройствам (только разрешённым)
        for device in self.devices.values():
            if command.startswith("OPEN_LOCK") and "Lock" in device.name:
                device.execute(command)
            elif command.startswith("READ_CAMERA") and "Cam" in device.name:
                device.execute(command)

        log.info(f"[{user}] Command {command} successfully processed")
        return True

    def start_monitoring(self):
        """Непрерывная проверка целостности (фоновый цикл)"""
        log.info("Integrity monitoring started")
        while True:
            self.integrity.periodic_check(self.devices.values())
            time.sleep(3)  # Проверка каждые 3 секунды → соответствует цели ≤3 сек на quarantine


def main():
    controller = SecurityController()

    # Для демо: имитация аутентификации и сессии
    role = controller.auth.authenticate("admin", "1234")  # MFA в реальности
    if not role:
        log.error("Authentication failed")
        return

    session_id = controller.sessions.create_session("admin", role)
    session = controller.sessions.validate(session_id)

    if not session:
        log.error("Session invalid")
        return

    # Запуск мониторинга целостности в фоне (в реальности — отдельный поток/threading)
    import threading
    threading.Thread(target=controller.start_monitoring, daemon=True).start()

    log.info("Controller ready to receive signed commands")

    # === ДЕМО: нормальная команда ===
    message = b"OPEN_LOCK"
    # Подпись (в реальности — в mobile_app)
    private_key = controller.load_user_keys()  # повторно для демо
    signature = private_key.sign(
        message,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    controller.process_command(session, message, signature)

    # === ДЕМО: атака (нарушение целостности) ===
    time.sleep(5)
    log.warning("=== SIMULATING ATTACK: firmware tampering ===")
    controller.devices["FrontDoorLock"].firmware = "hacked_malware"  # имитация компрометации

    # Повторная команда — должна быть заблокирована на уровне устройства после quarantine
    controller.process_command(session, message, signature)


if __name__ == "__main__":
    main()

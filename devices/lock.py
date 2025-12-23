import hashlib
import logging

logger = logging.getLogger("Lock")

class Lock:
    def __init__(self, name):
        self.name = name
        self.firmware = "clean"          # начальное состояние прошивки
        self.quarantined = False

    def get_firmware_hash(self):
        return hashlib.sha256(self.firmware.encode()).hexdigest()

    def quarantine(self):
        self.quarantined = True
        logger.warning(f"[QUARANTINE] {self.name} isolated due to integrity violation")

    def execute(self, command):
        if self.quarantined:
            logger.error(f"[DENIED] Command '{command}' to quarantined device {self.name}")
            return False
        logger.info(f"[EXEC] {self.name}: {command}")
        return True

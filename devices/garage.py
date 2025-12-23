import hashlib
import logging

logger = logging.getLogger("Garage")

class Garage:
    def __init__(self, name):
        self.name = name
        self.firmware = "clean"
        self.quarantined = False

    def get_firmware_hash(self):
        return hashlib.sha256(self.firmware.encode()).hexdigest()

    def quarantine(self):
        self.quarantined = True
        logger.warning(f"[QUARANTINE] {self.name} isolated")

    def execute(self, command):
        if self.quarantined:
            logger.error(f"[DENIED] Command '{command}' to quarantined {self.name}")
            return False
        logger.info(f"[EXEC] {self.name}: {command}")
        return True

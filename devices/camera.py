import hashlib
import logging

logger = logging.getLogger("Camera")

class Camera:
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
        if command.startswith("READ_CAMERA"):
            logger.info(f"[EXEC] {self.name}: Streaming video (simulated)")
        else:
            logger.info(f"[EXEC] {self.name}: {command}")
        return True

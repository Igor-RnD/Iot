import hashlib
from core.monitor import log

class IntegrityModule:
    def __init__(self):
        self.reference_hashes = {}

    def register_device(self, device):
        self.reference_hashes[device.name] = device.firmware_hash()

    def check_device(self, device):
        current = device.firmware_hash()
        reference = self.reference_hashes.get(device.name)

        if current != reference:
            log(f"[INTEGRITY] Violation detected on {device.name}")
            device.quarantine()


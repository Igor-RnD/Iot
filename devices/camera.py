from devices.base_device import BaseDevice

class Camera(BaseDevice):
    def stream(self):
        if self.quarantined:
            return "[BLOCKED]"
        return "[VIDEO STREAM]"


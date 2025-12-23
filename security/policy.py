class PolicyStore:
    def is_allowed(self, role, command):
        if role == "ADMIN":
            return True
        if role == "USER" and command == "READ_CAMERA":
            return True
        return False


import hashlib

class AuthService:
    def __init__(self):
        self.users = {
            "admin": {
                "pin": hashlib.sha256(b"1234").hexdigest(),
                "role": "ADMIN"
            },
            "user": {
                "pin": hashlib.sha256(b"0000").hexdigest(),
                "role": "USER"
            }
        }

    def authenticate(self, username, pin):
        if username not in self.users:
            return None
        if self.users[username]["pin"] != hashlib.sha256(pin.encode()).hexdigest():
            return None
        return self.users[username]["role"]

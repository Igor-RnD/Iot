import time

class SessionStore:
    def __init__(self):
        self.sessions = {}

    def create_session(self, user, role):
        sid = f"{user}-{int(time.time())}"
        self.sessions[sid] = {
            "user": user,
            "role": role,
            "expires": time.time() + 300
        }
        return sid

    def validate(self, sid):
        session = self.sessions.get(sid)
        if not session:
            return None
        if time.time() > session["expires"]:
            return None
        return session

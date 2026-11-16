"""Keep Web session rotations separate from revisioned admin configuration."""
import hashlib
import json
import threading

from .connectors.web import SiteSession
from .credentials import EncryptedFileStore
from .web_profiles import PROFILE_ENV, SESSION_ENV, WebProfile, connection_origins


def session_ref(conn, values):
    key = conn.secret_env[SESSION_ENV]
    profile = conn.env[PROFILE_ENV]
    # Replacing the imported session or profile supersedes old rotations.
    return hashlib.sha256((key + "\0" + profile + "\0" + values[key]).encode()).hexdigest()


class WebSessions:
    def __init__(self, cfg):
        path = cfg.admin.state
        self.file = EncryptedFileStore(path.with_name(path.name + ".web-sessions"), cfg.secrets.key_file)
        self.live = {}
        self.lock = threading.RLock()

    def get(self, conn, values):
        ref = session_ref(conn, values)
        with self.lock:
            origins = connection_origins(conn)
            if ref not in self.live or self.live[ref].origins != frozenset(origins):
                raw, redactions = values[conn.secret_env[SESSION_ENV]], ()
                if ref in self.file.names():
                    record = json.loads(self.file.get(ref))
                    raw, redactions = record["cookies"], record["redactions"]
                profile = WebProfile.saved(conn.env[PROFILE_ENV])

                def persist(raw, redactions):
                    with self.lock:
                        if self.live.get(ref) is session:
                            self.file.set(ref, json.dumps({"cookies": raw, "redactions": sorted(redactions)}))

                session = self.live[ref] = SiteSession(profile, raw, persist=persist, redactions=redactions, extra_origins=origins[1:])
            return self.live[ref]

    def prune(self, cfg, values):
        refs = {session_ref(c, values) for c in cfg.connections if c.plugin and PROFILE_ENV in c.env}
        with self.lock:
            for key in self.live.keys() - refs:
                self.live.pop(key)
            for key in set(self.file.names()) - refs:
                self.file.delete(key)

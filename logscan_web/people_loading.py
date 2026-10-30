"""One shared People refresh with fast snapshots and observable progress."""

import threading
import time
from concurrent.futures import ThreadPoolExecutor


class PeopleLoader:
    def __init__(self, build, *, ttl=300, on_error=None):
        self.build = build
        self.ttl = ttl
        self.on_error = on_error
        self.executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="people-list")
        self.lock = threading.Lock()
        self.snapshot = None
        self.running = False
        self.expires_at = 0
        self.generation = 0
        self.state = {"phase": "queued", "message": "Preparing the People list."}

    def invalidate(self):
        with self.lock:
            self.generation += 1
            self.snapshot = None
            self.expires_at = 0

    def read(self, *, retry=False):
        with self.lock:
            if not self.running and (retry or time.monotonic() >= self.expires_at):
                self.running = True
                self.state = {"phase": "queued", "message": "Preparing the People list.", "started_at": time.time()}
                self.future = self.executor.submit(self._refresh, self.generation)
            return self.snapshot, {**self.state, "refreshing": self.running}

    def _refresh(self, generation):
        def progress(phase, message, completed=None, total=None):
            with self.lock:
                self.state.update(phase=phase, message=message, completed=completed, total=total)

        try:
            people = self.build(progress)
            with self.lock:
                if generation == self.generation:
                    self.snapshot = people
                    self.expires_at = time.monotonic() + self.ttl
                    self.state.update(phase="complete", message="People and poster checks updated.", checked_at=time.time())
                else:
                    self.state.update(phase="queued", message="Updating changes to the People list.")
        except Exception:
            if self.on_error:
                self.on_error()
            with self.lock:
                self.expires_at = time.monotonic() + 60
                self.state.update(phase="failed", message="People verification could not finish. Saved people are still available; try again shortly.")
        finally:
            with self.lock:
                self.running = False

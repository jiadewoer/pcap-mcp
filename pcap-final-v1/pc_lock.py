"""Process lock; protected file bytes are never read before locking on Windows."""
import os
from pathlib import Path

class RunLock:
    """OS lock is released after process death; a leftover file is harmless."""
    def __init__(self, run: Path):
        self.path = run / "run.lock"
        self.handle = None

    def __enter__(self):
        if self.handle is not None:
            raise RuntimeError("This lock object already holds a run lock")
        try:
            # Windows byte-range locks also deny reads by other handles. Do not
            # read or initialize the protected byte before acquiring the lock.
            # msvcrt.locking permits a range extending past EOF, including an
            # empty file. Unbuffered mode also avoids deferred I/O on close.
            self.handle = self.path.open("a+b", buffering=0)
            self.handle.seek(0)
            self._change_lock(acquire=True)
        except BaseException as exc:
            self._close()
            if isinstance(exc, OSError):
                raise RuntimeError("Cannot acquire run lock; no request sent: " + str(exc)) from exc
            raise
        return self

    def __exit__(self, *args):
        if self.handle is None:
            return
        try:
            self.handle.seek(0)
            self._change_lock(acquire=False)
        finally:
            self._close()

    def _change_lock(self, *, acquire):
        if os.name == "nt":
            import msvcrt
            mode = msvcrt.LK_NBLCK if acquire else msvcrt.LK_UNLCK
            msvcrt.locking(self.handle.fileno(), mode, 1)
        else:
            import fcntl
            mode = fcntl.LOCK_EX | fcntl.LOCK_NB if acquire else fcntl.LOCK_UN
            fcntl.flock(self.handle, mode)

    def _close(self):
        handle, self.handle = self.handle, None
        if handle is not None:
            handle.close()


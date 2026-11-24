"""Bounded pool of session buffers."""


class SessionPool:
    def __init__(self, capacity: int) -> None:
        if capacity < 1:
            raise ValueError("capacity must be positive")
        self.capacity = capacity
        self._free: list[bytearray] = []
        self.allocated = 0

    def acquire(self) -> bytearray:
        if self._free:
            return self._free.pop()
        if self.allocated >= self.capacity:
            raise RuntimeError("session pool exhausted")
        self.allocated += 1
        return bytearray(1500)

    def release(self, buffer: bytearray) -> None:
        if len(self._free) < self.capacity:
            self._free.append(buffer)

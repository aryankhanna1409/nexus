import pytest

from pgw.session_pool import SessionPool


def test_reuses_released_buffers() -> None:
    pool = SessionPool(2)
    first = pool.acquire()
    pool.release(first)
    assert pool.acquire() is first
    assert pool.allocated == 1


def test_capacity_enforced() -> None:
    pool = SessionPool(1)
    pool.acquire()
    with pytest.raises(RuntimeError):
        pool.acquire()

"""Database engine, session factory and advisory-lock helpers."""

from __future__ import annotations

import contextlib
import hashlib
import threading
from collections.abc import Iterator

from sqlalchemy import create_engine, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.config import get_settings

settings = get_settings()

engine = create_engine(
    settings.db_url,
    pool_pre_ping=True,
    pool_size=10,
    max_overflow=10,
    future=True,
)

# SSE endpoints and the worker use their own connections; the default pool is
# sized for the API's request handlers.
SSE_LOCK = threading.Lock()

SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False, future=True)


class Base(DeclarativeBase):
    pass


def get_db() -> Iterator[Session]:
    """FastAPI dependency yielding a session that commits on success."""
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


@contextlib.contextmanager
def session_scope() -> Iterator[Session]:
    """Transactional scope for scripts and background threads."""
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def lock_key(name: str) -> int:
    """Map a logical lock name to a signed 64-bit advisory lock key."""
    digest = hashlib.sha256(name.encode()).digest()
    return int.from_bytes(digest[:8], "big", signed=True)


class AdvisoryLock:
    """A Postgres session-level advisory lock held on a dedicated connection.

    Used to cap concurrency per target across worker processes. Holding the
    lock on its own connection means it is released automatically if the
    process dies, which is exactly the failure mode we want to survive.
    """

    def __init__(self, name: str) -> None:
        self.name = name
        self.key = lock_key(name)
        self._conn = None

    def acquire(self) -> bool:
        if self._conn is not None:
            return True
        conn = engine.connect()
        try:
            got = conn.execute(
                text("SELECT pg_try_advisory_lock(:k)"), {"k": self.key}
            ).scalar_one()
        except Exception:
            conn.close()
            raise
        if got:
            self._conn = conn
            return True
        conn.close()
        return False

    def release(self) -> None:
        if self._conn is None:
            return
        try:
            self._conn.execute(text("SELECT pg_advisory_unlock(:k)"), {"k": self.key})
        except Exception:
            pass
        finally:
            with contextlib.suppress(Exception):
                self._conn.close()
            self._conn = None

    def __enter__(self) -> "AdvisoryLock":
        self.acquire()
        return self

    def __exit__(self, *exc: object) -> None:
        self.release()


def try_advisory_xact_lock(session: Session, name: str) -> bool:
    """Transaction-scoped lock; released automatically at commit/rollback."""
    return bool(
        session.execute(
            text("SELECT pg_try_advisory_xact_lock(:k)"), {"k": lock_key(name)}
        ).scalar_one()
    )


def db_server_time(session: Session):
    """Timestamps come from the database so all records share one clock."""
    return session.execute(text("SELECT now()")).scalar_one()

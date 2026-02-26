from __future__ import annotations

import os
import json
import base64
import hashlib
import hmac
import secrets
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, Optional

from sqlalchemy import (
    create_engine,
    String,
    DateTime,
    Text,
    Integer,
    ForeignKey,
    Index,
)
from sqlalchemy.orm import (
    declarative_base,
    sessionmaker,
    Mapped,
    mapped_column,
    relationship,
)

DB_URL = os.environ.get("ASSURE_DB_URL")
DB_PATH = os.environ.get("ASSURE_DB_PATH", "./assure.db")

if DB_URL:
    # Render often provides postgres:// but SQLAlchemy expects postgresql://
    if DB_URL.startswith("postgres://"):
        DB_URL = DB_URL.replace("postgres://", "postgresql://", 1)
else:
    if DB_PATH.startswith("sqlite:"):
        DB_URL = DB_PATH
    else:
        if DB_PATH.startswith("./"):
            DB_URL = f"sqlite:///{DB_PATH[2:]}"
        elif DB_PATH.startswith("/"):
            DB_URL = f"sqlite:///{DB_PATH}"
        else:
            DB_URL = f"sqlite:///{DB_PATH}"

engine = create_engine(
    DB_URL,
    connect_args={"check_same_thread": False} if DB_URL.startswith("sqlite") else {},
    pool_pre_ping=True,
    pool_size=5,
    max_overflow=10,
    pool_recycle=300,
    future=True,
)

SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
Base = declarative_base()


def utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


_PBKDF2_ITERATIONS = int(os.environ.get("ASSURE_PBKDF2_ITERATIONS", "210000"))


def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("utf-8").rstrip("=")


def _b64d(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("utf-8"))


def hash_password(password: str, *, iterations: int = _PBKDF2_ITERATIONS) -> str:
    if not isinstance(password, str) or len(password) < 8:
        raise ValueError("Password must be at least 8 characters.")
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, dklen=32)
    return f"pbkdf2_sha256${iterations}${_b64e(salt)}${_b64e(dk)}"


def verify_password(password: str, password_hash: str) -> bool:
    try:
        scheme, iters_s, salt_b64, hash_b64 = (password_hash or "").split("$", 3)
        if scheme != "pbkdf2_sha256":
            return False
        iterations = int(iters_s)
        salt = _b64d(salt_b64)
        expected = _b64d(hash_b64)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, dklen=len(expected))
        return hmac.compare_digest(dk, expected)
    except Exception:
        return False


def new_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


class Firm(Base):
    __tablename__ = "firms"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False, unique=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)

    users: Mapped[list["User"]] = relationship("User", back_populates="firm", cascade="all, delete-orphan")
    runs: Mapped[list["Run"]] = relationship("Run", back_populates="firm", cascade="all, delete-orphan")


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    firm_id: Mapped[int] = mapped_column(Integer, ForeignKey("firms.id", ondelete="CASCADE"), nullable=False, index=True)

    email: Mapped[str] = mapped_column(String(320), nullable=False, unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)

    role: Mapped[str] = mapped_column(String(32), nullable=False, default="member")

    is_active: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    last_login_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    firm: Mapped["Firm"] = relationship("Firm", back_populates="users")
    sessions: Mapped[list["Session"]] = relationship("Session", back_populates="user", cascade="all, delete-orphan")
    runs: Mapped[list["Run"]] = relationship("Run", back_populates="user")


class Session(Base):
    __tablename__ = "sessions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)

    token: Mapped[str] = mapped_column(String(128), nullable=False, unique=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    user: Mapped["User"] = relationship("User", back_populates="sessions")


class Run(Base):
    __tablename__ = "runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now, index=True)

    firm_id: Mapped[int] = mapped_column(Integer, ForeignKey("firms.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )

    ruleset_id: Mapped[str] = mapped_column(String(200), nullable=False)
    ruleset_version: Mapped[str] = mapped_column(String(50), nullable=False)
    checked_at: Mapped[str] = mapped_column(String(64), nullable=False)

    advice_type: Mapped[str] = mapped_column(String(50), nullable=False)
    investment_element: Mapped[str] = mapped_column(String(10), nullable=False)
    ongoing_service: Mapped[str] = mapped_column(String(10), nullable=False)

    sr_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    sr_len: Mapped[int] = mapped_column(Integer, nullable=False)

    ok_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    pi_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    na_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    completeness_pct: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    summary_json: Mapped[str] = mapped_column(Text, nullable=False)
    sections_json: Mapped[str] = mapped_column(Text, nullable=False)

    firm: Mapped["Firm"] = relationship("Firm", back_populates="runs")
    user: Mapped[Optional["User"]] = relationship("User", back_populates="runs")

    @staticmethod
    def dumps(obj: Dict[str, Any]) -> str:
        return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


Index("ix_runs_firm_created", Run.firm_id, Run.created_at)
Index("ix_runs_firm_srhash", Run.firm_id, Run.sr_hash)
Index("ix_runs_firm_user_created", Run.firm_id, Run.user_id, Run.created_at)
Index("ix_runs_firm_user_completeness", Run.firm_id, Run.user_id, Run.completeness_pct)


_DEFAULT_SESSION_DAYS = int(os.environ.get("ASSURE_SESSION_DAYS", "14"))


def create_session(db, user_id: int, *, days: int = _DEFAULT_SESSION_DAYS) -> str:
    token = new_token(32)
    expires = utc_now() + timedelta(days=days)
    s = Session(user_id=user_id, token=token, expires_at=expires)
    db.add(s)
    db.commit()
    return token


def delete_session(db, token: str) -> None:
    if not token:
        return
    s = db.query(Session).filter(Session.token == token).first()
    if s:
        db.delete(s)
        db.commit()


def get_user_by_session_token(db, token: str) -> Optional[User]:
    if not token:
        return None
    s = db.query(Session).filter(Session.token == token).first()
    if not s:
        return None
    if s.expires_at <= utc_now():
        db.delete(s)
        db.commit()
        return None
    u = db.query(User).filter(User.id == s.user_id).first()
    if not u or not u.is_active:
        return None
    return u


def init_db() -> None:
    Base.metadata.create_all(bind=engine)
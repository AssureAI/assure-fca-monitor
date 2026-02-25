from __future__ import annotations

import os
import json
import uuid
import secrets
import hashlib
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from sqlalchemy import (
    create_engine,
    String,
    DateTime,
    Text,
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

# -------------------------------------------------------------------
# ENGINE / SESSION
# -------------------------------------------------------------------

DB_URL = os.environ.get("ASSURE_DB_URL", "sqlite:///./assure.db")

engine = create_engine(
    DB_URL,
    connect_args={"check_same_thread": False} if DB_URL.startswith("sqlite") else {},
    future=True,
)

SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
Base = declarative_base()


def utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def new_uuid() -> str:
    return str(uuid.uuid4())


# -------------------------------------------------------------------
# SIMPLE PASSWORD HASHING (MVP)
# - Good enough for demo; later swap to passlib/bcrypt/argon2.
# -------------------------------------------------------------------

def hash_password(password: str, *, salt: Optional[str] = None) -> str:
    if salt is None:
        salt = secrets.token_hex(16)
    # PBKDF2-SHA256
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 200_000)
    return f"pbkdf2_sha256${salt}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, salt, hex_digest = stored.split("$", 2)
        if scheme != "pbkdf2_sha256":
            return False
        return hash_password(password, salt=salt) == stored
    except Exception:
        return False


# -------------------------------------------------------------------
# MODELS
# -------------------------------------------------------------------

class Firm(Base):
    __tablename__ = "firms"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)

    users: Mapped[list["User"]] = relationship("User", back_populates="firm", cascade="all, delete-orphan")
    runs: Mapped[list["Run"]] = relationship("Run", back_populates="firm", cascade="all, delete-orphan")


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    firm_id: Mapped[str] = mapped_column(String(36), ForeignKey("firms.id"), nullable=False, index=True)

    email: Mapped[str] = mapped_column(String(320), nullable=False, unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(500), nullable=False)

    # keep it simple for MVP: "admin" or "member"
    role: Mapped[str] = mapped_column(String(50), nullable=False, default="admin")

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)

    firm: Mapped["Firm"] = relationship("Firm", back_populates="users")
    sessions: Mapped[list["Session"]] = relationship("Session", back_populates="user", cascade="all, delete-orphan")
    runs: Mapped[list["Run"]] = relationship("Run", back_populates="user")


class Session(Base):
    __tablename__ = "sessions"

    # cookie token
    token: Mapped[str] = mapped_column(String(80), primary_key=True)
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)

    user: Mapped["User"] = relationship("User", back_populates="sessions")


class Run(Base):
    __tablename__ = "runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now, index=True)

    # tenancy
    firm_id: Mapped[str] = mapped_column(String(36), ForeignKey("firms.id"), nullable=False, index=True)
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), nullable=False, index=True)

    # context
    advice_type: Mapped[str] = mapped_column(String(50), nullable=False)
    investment_element: Mapped[str] = mapped_column(String(10), nullable=False)  # "true"/"false" (keep consistent)
    ongoing_service: Mapped[str] = mapped_column(String(10), nullable=False)     # "true"/"false"

    ruleset_id: Mapped[str] = mapped_column(String(200), nullable=False)
    ruleset_version: Mapped[str] = mapped_column(String(50), nullable=False)
    checked_at: Mapped[str] = mapped_column(String(50), nullable=False)

    sr_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    sr_len: Mapped[int] = mapped_column(nullable=False)

    summary_json: Mapped[str] = mapped_column(Text, nullable=False)
    sections_json: Mapped[str] = mapped_column(Text, nullable=False)  # store only sections for history

    firm: Mapped["Firm"] = relationship("Firm", back_populates="runs")
    user: Mapped["User"] = relationship("User", back_populates="runs")

    @staticmethod
    def dumps(obj: Dict[str, Any]) -> str:
        return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


Index("ix_runs_firm_created", Run.firm_id, Run.created_at)


# -------------------------------------------------------------------
# DB INIT
# -------------------------------------------------------------------

def init_db() -> None:
    Base.metadata.create_all(bind=engine)


# -------------------------------------------------------------------
# HELPERS (OPTIONAL BUT USEFUL)
# -------------------------------------------------------------------

def create_session(db, user_id: str) -> str:
    token = secrets.token_urlsafe(32)
    db.add(Session(token=token, user_id=user_id))
    db.commit()
    return token
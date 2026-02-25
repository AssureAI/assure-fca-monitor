from __future__ import annotations

import os
import json
from datetime import datetime
from typing import Any, Dict, Optional

from sqlalchemy import create_engine, String, DateTime, Text
from sqlalchemy.orm import declarative_base, sessionmaker, Mapped, mapped_column

# SQLite file lives in project root by default
DB_URL = os.environ.get("ASSURE_DB_URL", "sqlite:///./assure.db")

engine = create_engine(
    DB_URL,
    connect_args={"check_same_thread": False} if DB_URL.startswith("sqlite") else {},
    future=True,
)

SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
Base = declarative_base()


class Run(Base):
    __tablename__ = "runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)  # UUID string
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, index=True)

    ruleset_id: Mapped[str] = mapped_column(String(200), nullable=False)
    ruleset_version: Mapped[str] = mapped_column(String(50), nullable=False)

    advice_type: Mapped[str] = mapped_column(String(50), nullable=False)
    investment_element: Mapped[str] = mapped_column(String(10), nullable=False)  # "true"/"false"
    ongoing_service: Mapped[str] = mapped_column(String(10), nullable=False)     # "true"/"false"

    sr_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    sr_len: Mapped[int] = mapped_column(nullable=False)

    summary_json: Mapped[str] = mapped_column(Text, nullable=False)
    result_json: Mapped[str] = mapped_column(Text, nullable=False)

    @staticmethod
    def dumps(obj: Dict[str, Any]) -> str:
        return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def init_db() -> None:
    Base.metadata.create_all(bind=engine)

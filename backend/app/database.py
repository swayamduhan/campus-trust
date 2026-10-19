from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker

DATA_DIR = Path(__file__).resolve().parents[1] / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)
DATABASE_URL = f"sqlite:///{(DATA_DIR / 'campustrust.db').as_posix()}"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


class Enrollment(Base):
    __tablename__ = "enrollments"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    full_name: Mapped[str] = mapped_column(String(140))
    email: Mapped[str] = mapped_column(String(254), index=True)
    university_id: Mapped[str] = mapped_column(String(40), unique=True, index=True)
    role: Mapped[str] = mapped_column(String(20))
    status: Mapped[str] = mapped_column(String(20), default="pending", index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    certificate: Mapped["Certificate | None"] = relationship(back_populates="enrollment", uselist=False)


class Certificate(Base):
    __tablename__ = "certificates"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    enrollment_id: Mapped[int] = mapped_column(ForeignKey("enrollments.id"), unique=True)
    serial_number: Mapped[str] = mapped_column(String(80), unique=True)
    fingerprint: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    certificate_pem: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(20), default="active", index=True)
    chain_status: Mapped[str] = mapped_column(String(20), default="pending")
    chain_tx: Mapped[str | None] = mapped_column(String(80), nullable=True)
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    enrollment: Mapped[Enrollment] = relationship(back_populates="certificate")


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    event_type: Mapped[str] = mapped_column(String(40), index=True)
    actor: Mapped[str] = mapped_column(String(100), default="IT Security Admin")
    subject: Mapped[str] = mapped_column(String(160))
    details: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, index=True)

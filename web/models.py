"""
ORM models for the Trend Vision One Reporter web application.
"""

from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    func,
    Index,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from database import Base


def _utcnow() -> datetime:
    return datetime.now(tz=timezone.utc)


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )

    customers: Mapped[list["Customer"]] = relationship(
        "Customer", back_populates="created_by", lazy="select"
    )


class Customer(Base):
    __tablename__ = "customers"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=True)
    contact_email: Mapped[str] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )
    created_by_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    created_by: Mapped["User"] = relationship("User", back_populates="customers")
    api_keys: Mapped[list["CustomerApiKey"]] = relationship(
        "CustomerApiKey", back_populates="customer", cascade="all, delete-orphan"
    )
    reports: Mapped[list["Report"]] = relationship(
        "Report", back_populates="customer", cascade="all, delete-orphan"
    )


class CustomerApiKey(Base):
    __tablename__ = "customer_api_keys"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    customer_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("customers.id", ondelete="CASCADE"), nullable=False, index=True
    )
    label: Mapped[str] = mapped_column(String(128), nullable=False)
    encrypted_key: Mapped[str] = mapped_column(Text, nullable=False)
    base_url: Mapped[str] = mapped_column(
        String(255), nullable=False, default="https://api.xdr.trendmicro.com"
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )

    customer: Mapped["Customer"] = relationship("Customer", back_populates="api_keys")
    reports: Mapped[list["Report"]] = relationship(
        "Report", back_populates="api_key", lazy="select"
    )


class AppSetting(Base):
    """Application-wide key/value settings, stored in the DB.

    Sensitive values (is_encrypted=True) are stored as Fernet-encrypted
    ciphertext using the same FERNET_KEY as CustomerApiKey.
    """
    __tablename__ = "app_settings"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(Text, nullable=True)
    is_encrypted: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    description: Mapped[str] = mapped_column(String(256), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow, nullable=False
    )


class CVECache(Base):
    """Local cache of NVD CVE enrichment data."""
    __tablename__ = "cve_cache"

    cve_id: Mapped[str] = mapped_column(String(20), primary_key=True)
    description: Mapped[str] = mapped_column(Text, nullable=True)
    cvss_score: Mapped[float] = mapped_column(Float, nullable=True)
    cvss_severity: Mapped[str] = mapped_column(String(16), nullable=True)
    cvss_vector: Mapped[str] = mapped_column(String(128), nullable=True)
    cwe: Mapped[str] = mapped_column(String(128), nullable=True)
    patch_url: Mapped[str] = mapped_column(Text, nullable=True)
    refs_json: Mapped[str] = mapped_column(Text, nullable=True)  # JSON list
    published: Mapped[str] = mapped_column(String(32), nullable=True)
    modified: Mapped[str] = mapped_column(String(32), nullable=True)
    nvd_status: Mapped[str] = mapped_column(String(32), nullable=True)
    cached_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    customer_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("customers.id", ondelete="CASCADE"), nullable=False, index=True
    )
    api_key_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("customer_api_keys.id", ondelete="SET NULL"), nullable=True
    )
    filename: Mapped[str] = mapped_column(String(255), nullable=True)
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default="pending"
    )  # pending | running | done | failed
    error_message: Mapped[str] = mapped_column(Text, nullable=True)
    report_type: Mapped[str] = mapped_column(
        String(32), nullable=False, default="security_overview"
    )  # security_overview | patch_remediation
    days_back: Mapped[int] = mapped_column(Integer, nullable=False, default=30)
    severity_filter: Mapped[str] = mapped_column(
        Text, nullable=True
    )  # JSON string, e.g. '["critical","high"]'
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )
    completed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)

    customer: Mapped["Customer"] = relationship("Customer", back_populates="reports")
    api_key: Mapped["CustomerApiKey"] = relationship("CustomerApiKey", back_populates="reports")


class AuditLog(Base):
    """
    Immutable record of security-relevant events.
    Written on admin actions, auth events, and access denials.
    Never updated or deleted by the application.
    """
    __tablename__ = "audit_log"
    __table_args__ = (
        Index("ix_audit_log_actor", "actor"),
        Index("ix_audit_log_event_time", "event_time"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    event_time: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )
    actor: Mapped[str] = mapped_column(String(64), nullable=False)   # username or "anonymous"
    event: Mapped[str] = mapped_column(String(64), nullable=False)   # e.g. "user.create"
    target: Mapped[str] = mapped_column(String(255), nullable=True)  # e.g. "user:alice"
    detail: Mapped[str] = mapped_column(Text, nullable=True)         # extra context
    ip_address: Mapped[str] = mapped_column(String(45), nullable=True)

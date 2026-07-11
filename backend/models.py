"""
models.py — SQLAlchemy ORM models for DRM Guard.

Tables:
  users        — Creator accounts (web dashboard login)
  drm_files    — Files registered by creators with their access policies
  access_keys  — Per-file AES key shards stored server-side (Phase 3)
  audit_logs   — Every key request / decrypt attempt logged here
"""

import uuid
from datetime import datetime

from sqlalchemy import (
    Column, String, Boolean, DateTime, Integer,
    ForeignKey, Text, Enum as SAEnum
)
from sqlalchemy.orm import relationship
import enum

from database import Base


def _uuid() -> str:
    return str(uuid.uuid4())


# ─── Enums ───────────────────────────────────────────────────────────────────

class LockType(str, enum.Enum):
    MAC  = "MAC"
    IP   = "IP"
    NONE = "NONE"


class AuditAction(str, enum.Enum):
    ENCRYPT     = "ENCRYPT"
    KEY_REQUEST = "KEY_REQUEST"
    KEY_GRANTED = "KEY_GRANTED"
    KEY_DENIED  = "KEY_DENIED"
    REVOKE      = "REVOKE"


# ─── User ────────────────────────────────────────────────────────────────────

class User(Base):
    """
    A content creator who registers on the web dashboard.
    """
    __tablename__ = "users"

    id            = Column(String(36), primary_key=True, default=_uuid)
    email         = Column(String(255), unique=True, nullable=False, index=True)
    hashed_password = Column(String(128), nullable=False)
    full_name     = Column(String(128), nullable=False, default="")
    is_active     = Column(Boolean, default=True, nullable=False)
    created_at    = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at    = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    drm_files = relationship("DRMFile", back_populates="owner", cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<User id={self.id!r} email={self.email!r}>"


# ─── DRM File ────────────────────────────────────────────────────────────────

class DRMFile(Base):
    """
    A file that has been encrypted and registered with the KMS.
    The actual file is stored wherever the user wants (cloud / local).
    This record holds the access POLICY.
    """
    __tablename__ = "drm_files"

    id              = Column(String(36), primary_key=True, default=_uuid)
    owner_id        = Column(String(36), ForeignKey("users.id"), nullable=False, index=True)

    # File metadata
    original_name   = Column(String(255), nullable=False)
    original_ext    = Column(String(32),  nullable=False)
    file_size_bytes = Column(Integer,     nullable=True)
    description     = Column(Text,        nullable=True)

    # Access policy
    lock_type       = Column(SAEnum(LockType), nullable=False, default=LockType.MAC)
    lock_identifier = Column(String(128), nullable=True)   # the MAC or IP value
    expiry_dt       = Column(DateTime,    nullable=False)
    is_revoked      = Column(Boolean,     default=False, nullable=False)

    # Watermark
    watermark_text    = Column(String(512), nullable=True, default="")
    watermark_opacity = Column(Integer,     nullable=True, default=0)

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    owner       = relationship("User",       back_populates="drm_files")
    access_key  = relationship("AccessKey",  back_populates="drm_file",  uselist=False,
                               cascade="all, delete-orphan")
    audit_logs  = relationship("AuditLog",   back_populates="drm_file",
                               cascade="all, delete-orphan")

    @property
    def is_expired(self) -> bool:
        return datetime.utcnow() > self.expiry_dt

    @property
    def is_accessible(self) -> bool:
        return not self.is_revoked and not self.is_expired

    def __repr__(self) -> str:
        return f"<DRMFile id={self.id!r} name={self.original_name!r}>"


# ─── Access Key ──────────────────────────────────────────────────────────────

class AccessKey(Base):
    """
    The AES-256 decryption key (base64-encoded) stored server-side.
    The desktop client requests this key per-file; the server validates
    MAC/expiry/revocation before returning it.

    Phase 3 will move the encryption key here entirely, removing the
    key from the .drm file header.
    """
    __tablename__ = "access_keys"

    id          = Column(String(36), primary_key=True, default=_uuid)
    file_id     = Column(String(36), ForeignKey("drm_files.id"), nullable=False, unique=True)

    # AES key stored as base64 string (32 raw bytes → 44 chars b64)
    aes_key_b64 = Column(String(64), nullable=False)
    iv_b64      = Column(String(32), nullable=False)   # 16 bytes IV → 24 chars b64

    created_at  = Column(DateTime, default=datetime.utcnow, nullable=False)

    drm_file = relationship("DRMFile", back_populates="access_key")

    def __repr__(self) -> str:
        return f"<AccessKey file_id={self.file_id!r}>"


# ─── Audit Log ───────────────────────────────────────────────────────────────

class AuditLog(Base):
    """
    Every key request (granted or denied) is logged here.
    Gives creators full visibility into who is accessing their files.
    """
    __tablename__ = "audit_logs"

    id           = Column(String(36), primary_key=True, default=_uuid)
    file_id      = Column(String(36), ForeignKey("drm_files.id"), nullable=False, index=True)

    action       = Column(SAEnum(AuditAction), nullable=False)
    requester_mac= Column(String(17),  nullable=True)   # XX:XX:XX:XX:XX:XX
    requester_ip = Column(String(45),  nullable=True)   # supports IPv6
    user_agent   = Column(String(512), nullable=True)

    # The reason a key was denied (if applicable)
    deny_reason  = Column(String(256), nullable=True)

    timestamp    = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)

    drm_file = relationship("DRMFile", back_populates="audit_logs")

    def __repr__(self) -> str:
        return f"<AuditLog file_id={self.file_id!r} action={self.action!r}>"

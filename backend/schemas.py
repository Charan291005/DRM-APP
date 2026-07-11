"""
schemas.py — Pydantic v2 request / response schemas.

Organized by domain:
  - Auth   (register, login, token)
  - User   (profile read)
  - DRMFile (create, list, detail)
  - KMS    (key request / response)
  - Audit  (log entries)
"""

from __future__ import annotations
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, EmailStr, Field, model_validator


# ─── Auth ────────────────────────────────────────────────────────────────────

class RegisterRequest(BaseModel):
    email:     EmailStr
    password:  str = Field(min_length=8, max_length=128)
    full_name: str = Field(min_length=1, max_length=128)

    @model_validator(mode="after")
    def check_password_strength(self) -> "RegisterRequest":
        pw = self.password
        if not any(c.isdigit() for c in pw):
            raise ValueError("Password must contain at least one digit.")
        if len(pw) < 8:
            raise ValueError("Password must be at least 8 characters.")
        return self


class LoginRequest(BaseModel):
    email:    EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type:   str = "bearer"
    expires_in:   int   # seconds


# ─── User ────────────────────────────────────────────────────────────────────

class UserProfile(BaseModel):
    id:         str
    email:      str
    full_name:  str
    is_active:  bool
    created_at: datetime

    model_config = {"from_attributes": True}


# ─── DRM File ────────────────────────────────────────────────────────────────

class DRMFileCreate(BaseModel):
    """Sent by the desktop app (or creator dashboard) to register a new encrypted file."""
    original_name:     str = Field(max_length=255)
    original_ext:      str = Field(max_length=32)
    file_size_bytes:   Optional[int] = None
    description:       Optional[str] = None

    # Access policy
    lock_type:         str = Field(default="MAC", pattern="^(MAC|IP|NONE)$")
    lock_identifier:   Optional[str] = Field(default=None, max_length=128)
    expiry_dt:         datetime

    # Watermark
    watermark_text:    Optional[str] = Field(default="", max_length=512)
    watermark_opacity: Optional[int] = Field(default=0, ge=0, le=100)

    # The AES key and IV (base64) — stored server-side in access_keys table
    aes_key_b64:       str = Field(max_length=64)
    iv_b64:            str = Field(max_length=32)

    @model_validator(mode="after")
    def validate_lock_identifier(self) -> "DRMFileCreate":
        if self.lock_type != "NONE" and not self.lock_identifier:
            raise ValueError(
                f"lock_identifier is required when lock_type is '{self.lock_type}'."
            )
        return self


class DRMFileSummary(BaseModel):
    """Lightweight list item for the creator dashboard."""
    id:              str
    original_name:   str
    original_ext:    str
    lock_type:       str
    expiry_dt:       datetime
    is_revoked:      bool
    is_expired:      bool
    is_accessible:   bool
    created_at:      datetime
    total_requests:  int = 0
    denied_requests: int = 0

    model_config = {"from_attributes": True}


class DRMFileDetail(DRMFileSummary):
    """Full detail view including policy and watermark info."""
    lock_identifier:   Optional[str]
    description:       Optional[str]
    file_size_bytes:   Optional[int]
    watermark_text:    Optional[str]
    watermark_opacity: Optional[int]
    owner_id:          str

    model_config = {"from_attributes": True}


class RevokeResponse(BaseModel):
    message: str
    file_id: str


# ─── KMS — Key Request (desktop client) ──────────────────────────────────────

class KeyRequest(BaseModel):
    """
    Sent by the DRM Guard desktop app when the user opens a .drm file.
    The file_id is embedded in the .drm header (Phase 3).
    For now (Phase 2) this is scaffolded for future use.
    """
    file_id:       str
    requester_mac: str = Field(
        pattern=r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$",
        description="MAC address in XX:XX:XX:XX:XX:XX format",
    )
    requester_ip:  Optional[str] = None
    user_agent:    Optional[str] = None


class KeyResponse(BaseModel):
    """
    Returned when a key request is GRANTED.
    Desktop app uses aes_key_b64 + iv_b64 to decrypt the file in memory.
    """
    file_id:           str
    aes_key_b64:       str
    iv_b64:            str
    watermark_text:    str
    watermark_opacity: int
    original_ext:      str
    expiry_dt:         datetime


class KeyDenied(BaseModel):
    file_id: str
    reason:  str


# ─── Audit ───────────────────────────────────────────────────────────────────

class AuditLogEntry(BaseModel):
    id:            str
    file_id:       str
    action:        str
    requester_mac: Optional[str]
    requester_ip:  Optional[str]
    deny_reason:   Optional[str]
    timestamp:     datetime

    model_config = {"from_attributes": True}


class AuditLogList(BaseModel):
    file_id: str
    total:   int
    entries: list[AuditLogEntry]


# ─── Generic ─────────────────────────────────────────────────────────────────

class MessageResponse(BaseModel):
    message: str


class ErrorResponse(BaseModel):
    detail: str

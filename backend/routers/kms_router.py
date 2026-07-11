"""
routers/kms_router.py — Key Management System endpoint.

This is the CORE DRM enforcement endpoint.
The desktop client (drm_guard.py) calls this when a user tries to open a .drm file.

Flow:
  1. Desktop reads file_id from the .drm header
  2. Desktop sends { file_id, requester_mac, requester_ip } to POST /kms/request-key
  3. Server checks: revocation → expiry → MAC/IP lock → issues AES key
  4. Desktop decrypts in memory using the returned key (never writes to disk)

No authentication token required from the viewer —
the file_id + MAC is the access credential.
"""

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from database import get_db
from models import DRMFile, AccessKey, AuditLog, LockType, AuditAction
from schemas import KeyRequest, KeyResponse, KeyDenied

router = APIRouter(prefix="/kms", tags=["Key Management System"])


@router.post(
    "/request-key",
    summary="Request the AES decryption key for a .drm file",
    description=(
        "Called by the DRM Guard desktop client when opening a .drm file. "
        "Validates revocation, expiry, and device lock before issuing the key. "
        "Every request is logged to the audit log regardless of outcome."
    ),
    responses={
        200: {"model": KeyResponse, "description": "Key granted — desktop can decrypt in-memory"},
        403: {"model": KeyDenied,   "description": "Key denied — access policy violated"},
        404: {"description": "File ID not found"},
    },
)
async def request_key(
    body:    KeyRequest,
    request: Request,
    db:      AsyncSession = Depends(get_db),
):
    # 1. Look up the file and its key
    file_result = await db.execute(
        select(DRMFile).where(DRMFile.id == body.file_id)
    )
    drm_file = file_result.scalar_one_or_none()

    if drm_file is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No file registered with id '{body.file_id}'.",
        )

    requester_ip = body.requester_ip or request.client.host

    # Helper to log and return a denial
    async def _deny(reason: str):
        audit = AuditLog(
            file_id       = drm_file.id,
            action        = AuditAction.KEY_DENIED,
            requester_mac = body.requester_mac,
            requester_ip  = requester_ip,
            user_agent    = body.user_agent,
            deny_reason   = reason,
        )
        db.add(audit)
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=reason,
        )

    # 2. Check revocation
    if drm_file.is_revoked:
        await _deny("Access has been revoked by the file owner.")

    # 3. Check expiry
    if datetime.utcnow() > drm_file.expiry_dt:
        await _deny(
            f"This file expired on "
            f"{drm_file.expiry_dt.strftime('%Y-%m-%d %H:%M')} UTC."
        )

    # 4. Check device lock
    if drm_file.lock_type == LockType.MAC:
        if body.requester_mac.upper() != (drm_file.lock_identifier or "").upper():
            await _deny(
                f"Device MAC address mismatch. "
                f"File is locked to: {drm_file.lock_identifier}"
            )
    elif drm_file.lock_type == LockType.IP:
        if requester_ip != drm_file.lock_identifier:
            await _deny(
                f"IP address mismatch. "
                f"File is locked to: {drm_file.lock_identifier}"
            )
    # LockType.NONE — no device restriction

    # 5. Fetch the stored key
    key_result = await db.execute(
        select(AccessKey).where(AccessKey.file_id == drm_file.id)
    )
    access_key = key_result.scalar_one_or_none()

    if access_key is None:
        await _deny("Decryption key not found on server — file may need to be re-encrypted.")

    # 6. Log the grant
    audit = AuditLog(
        file_id       = drm_file.id,
        action        = AuditAction.KEY_GRANTED,
        requester_mac = body.requester_mac,
        requester_ip  = requester_ip,
        user_agent    = body.user_agent,
    )
    db.add(audit)
    await db.commit()

    return KeyResponse(
        file_id           = drm_file.id,
        aes_key_b64       = access_key.aes_key_b64,
        iv_b64            = access_key.iv_b64,
        watermark_text    = drm_file.watermark_text or "",
        watermark_opacity = drm_file.watermark_opacity or 0,
        original_ext      = drm_file.original_ext,
        expiry_dt         = drm_file.expiry_dt,
    )

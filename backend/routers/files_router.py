"""
routers/files_router.py — DRM file registration and management.

Endpoints:
  POST   /files/                  — Register a new encrypted file (stores key server-side)
  GET    /files/                  — List all files owned by the creator
  GET    /files/{file_id}         — Get full detail for one file
  DELETE /files/{file_id}/revoke  — Instantly revoke access (sets is_revoked=True)
  DELETE /files/{file_id}         — Permanently delete a file record
"""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from database import get_db
from models import User, DRMFile, AccessKey, AuditLog, LockType, AuditAction
from schemas import (
    DRMFileCreate, DRMFileSummary, DRMFileDetail,
    RevokeResponse, MessageResponse,
)
from auth import get_current_user

router = APIRouter(prefix="/files", tags=["DRM Files"])


def _to_summary(f: DRMFile, db_counts: dict) -> dict:
    return {
        "id":              f.id,
        "original_name":   f.original_name,
        "original_ext":    f.original_ext,
        "lock_type":       f.lock_type.value,
        "expiry_dt":       f.expiry_dt,
        "is_revoked":      f.is_revoked,
        "is_expired":      f.is_expired,
        "is_accessible":   f.is_accessible,
        "created_at":      f.created_at,
        "total_requests":  db_counts.get(f.id, {}).get("total", 0),
        "denied_requests": db_counts.get(f.id, {}).get("denied", 0),
    }


@router.post(
    "/",
    response_model=DRMFileDetail,
    status_code=status.HTTP_201_CREATED,
    summary="Register a newly encrypted file and store its AES key server-side",
)
async def register_file(
    body:         DRMFileCreate,
    db:           AsyncSession = Depends(get_db),
    current_user: User         = Depends(get_current_user),
):
    # Validate expiry is in the future
    if body.expiry_dt.replace(tzinfo=None) <= datetime.utcnow():
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="expiry_dt must be in the future.",
        )

    drm_file = DRMFile(
        owner_id          = current_user.id,
        original_name     = body.original_name,
        original_ext      = body.original_ext,
        file_size_bytes   = body.file_size_bytes,
        description       = body.description,
        lock_type         = LockType(body.lock_type),
        lock_identifier   = body.lock_identifier,
        expiry_dt         = body.expiry_dt.replace(tzinfo=None),
        watermark_text    = body.watermark_text or "",
        watermark_opacity = body.watermark_opacity or 0,
    )
    db.add(drm_file)
    await db.flush()   # Get the UUID before creating AccessKey

    access_key = AccessKey(
        file_id     = drm_file.id,
        aes_key_b64 = body.aes_key_b64,
        iv_b64      = body.iv_b64,
    )
    db.add(access_key)

    # Log the encrypt event
    audit = AuditLog(
        file_id       = drm_file.id,
        action        = AuditAction.ENCRYPT,
        requester_mac = body.lock_identifier if body.lock_type == "MAC" else None,
    )
    db.add(audit)

    await db.flush()
    return {
        **drm_file.__dict__,
        "lock_type":       drm_file.lock_type.value,
        "is_expired":      drm_file.is_expired,
        "is_accessible":   drm_file.is_accessible,
        "total_requests":  0,
        "denied_requests": 0,
    }


@router.get(
    "/",
    response_model=list[DRMFileSummary],
    summary="List all DRM files owned by the authenticated creator",
)
async def list_files(
    db:           AsyncSession = Depends(get_db),
    current_user: User         = Depends(get_current_user),
    skip:         int          = 0,
    limit:        int          = 50,
):
    result = await db.execute(
        select(DRMFile)
        .where(DRMFile.owner_id == current_user.id)
        .order_by(DRMFile.created_at.desc())
        .offset(skip)
        .limit(limit)
    )
    files = result.scalars().all()

    if not files:
        return []

    # Batch count audit events
    file_ids = [f.id for f in files]
    count_result = await db.execute(
        select(
            AuditLog.file_id,
            func.count(AuditLog.id).label("total"),
            func.sum(
                func.cast(AuditLog.action == AuditAction.KEY_DENIED, int)
            ).label("denied"),
        )
        .where(AuditLog.file_id.in_(file_ids))
        .group_by(AuditLog.file_id)
    )
    counts = {
        row.file_id: {"total": row.total, "denied": int(row.denied or 0)}
        for row in count_result
    }

    return [_to_summary(f, counts) for f in files]


@router.get(
    "/{file_id}",
    response_model=DRMFileDetail,
    summary="Get full detail for a single DRM file",
)
async def get_file(
    file_id:      str,
    db:           AsyncSession = Depends(get_db),
    current_user: User         = Depends(get_current_user),
):
    result = await db.execute(
        select(DRMFile).where(
            DRMFile.id == file_id,
            DRMFile.owner_id == current_user.id,
        )
    )
    f = result.scalar_one_or_none()
    if f is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File not found.")

    count_result = await db.execute(
        select(
            func.count(AuditLog.id).label("total"),
            func.sum(
                func.cast(AuditLog.action == AuditAction.KEY_DENIED, int)
            ).label("denied"),
        ).where(AuditLog.file_id == file_id)
    )
    counts_row = count_result.one()

    return {
        **f.__dict__,
        "lock_type":       f.lock_type.value,
        "is_expired":      f.is_expired,
        "is_accessible":   f.is_accessible,
        "total_requests":  counts_row.total or 0,
        "denied_requests": int(counts_row.denied or 0),
    }


@router.patch(
    "/{file_id}/revoke",
    response_model=RevokeResponse,
    summary="Instantly revoke access to a file — no key will be issued after this",
)
async def revoke_file(
    file_id:      str,
    db:           AsyncSession = Depends(get_db),
    current_user: User         = Depends(get_current_user),
):
    result = await db.execute(
        select(DRMFile).where(
            DRMFile.id == file_id,
            DRMFile.owner_id == current_user.id,
        )
    )
    f = result.scalar_one_or_none()
    if f is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File not found.")
    if f.is_revoked:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="File is already revoked.")

    f.is_revoked = True
    audit = AuditLog(file_id=f.id, action=AuditAction.REVOKE)
    db.add(audit)

    return RevokeResponse(message="Access revoked successfully.", file_id=file_id)


@router.delete(
    "/{file_id}",
    response_model=MessageResponse,
    summary="Permanently delete a file record and its access key",
)
async def delete_file(
    file_id:      str,
    db:           AsyncSession = Depends(get_db),
    current_user: User         = Depends(get_current_user),
):
    result = await db.execute(
        select(DRMFile).where(
            DRMFile.id == file_id,
            DRMFile.owner_id == current_user.id,
        )
    )
    f = result.scalar_one_or_none()
    if f is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File not found.")

    await db.delete(f)
    return MessageResponse(message=f"File '{f.original_name}' deleted permanently.")

"""
routers/audit_router.py — Audit log endpoints for the creator dashboard.

Endpoints:
  GET /audit/{file_id}       — Get all audit log entries for one file
  GET /audit/                — Get all audit entries across all creator's files (paginated)
"""

from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from database import get_db
from models import User, DRMFile, AuditLog
from schemas import AuditLogEntry, AuditLogList
from auth import get_current_user

router = APIRouter(prefix="/audit", tags=["Audit Log"])


@router.get(
    "/{file_id}",
    response_model=AuditLogList,
    summary="Get all audit log entries for a specific DRM file",
)
async def get_file_audit(
    file_id:      str,
    db:           AsyncSession = Depends(get_db),
    current_user: User         = Depends(get_current_user),
    skip:         int          = Query(default=0, ge=0),
    limit:        int          = Query(default=100, ge=1, le=500),
):
    # Verify the file belongs to the current user
    file_result = await db.execute(
        select(DRMFile).where(
            DRMFile.id == file_id,
            DRMFile.owner_id == current_user.id,
        )
    )
    if file_result.scalar_one_or_none() is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="File not found or you don't have permission to view its logs.",
        )

    total_result = await db.execute(
        select(func.count(AuditLog.id)).where(AuditLog.file_id == file_id)
    )
    total = total_result.scalar_one()

    logs_result = await db.execute(
        select(AuditLog)
        .where(AuditLog.file_id == file_id)
        .order_by(AuditLog.timestamp.desc())
        .offset(skip)
        .limit(limit)
    )
    entries = logs_result.scalars().all()

    return AuditLogList(
        file_id=file_id,
        total=total,
        entries=[AuditLogEntry.model_validate(e) for e in entries],
    )


@router.get(
    "/",
    response_model=list[AuditLogEntry],
    summary="Get all audit events across all files owned by the creator (most recent first)",
)
async def get_all_audit(
    db:           AsyncSession = Depends(get_db),
    current_user: User         = Depends(get_current_user),
    skip:         int          = Query(default=0, ge=0),
    limit:        int          = Query(default=100, ge=1, le=500),
):
    # Get IDs of all files owned by this user
    file_ids_result = await db.execute(
        select(DRMFile.id).where(DRMFile.owner_id == current_user.id)
    )
    file_ids = [row[0] for row in file_ids_result]

    if not file_ids:
        return []

    logs_result = await db.execute(
        select(AuditLog)
        .where(AuditLog.file_id.in_(file_ids))
        .order_by(AuditLog.timestamp.desc())
        .offset(skip)
        .limit(limit)
    )
    entries = logs_result.scalars().all()
    return [AuditLogEntry.model_validate(e) for e in entries]

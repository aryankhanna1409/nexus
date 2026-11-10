"""Deployments, security findings and the audit log."""

from __future__ import annotations

from fastapi import APIRouter, Query
from sqlalchemy import func, select

from app.api.common import MAX_PAGE
from app.api.deps import Admin, Operator, SessionDep, Viewer
from app.models import AuditLogRecord, Deployment, SecurityFindingRecord
from app.schemas.api import ChainVerificationResponse, Page
from app.schemas.entities import AuditLog, Deployment as DeploymentSchema, SecurityFinding
from app.security.audit import verify_chain

router = APIRouter(tags=["governance"])


@router.get("/api/deployments", response_model=list[DeploymentSchema])
def deployments(session: SessionDep, _: Viewer, run_id: int | None = Query(None, ge=1),
                limit: int = Query(100, ge=1, le=MAX_PAGE)) -> list[Deployment]:
    query = select(Deployment)
    if run_id is not None:
        query = query.where(Deployment.run_id == run_id)
    return list(session.scalars(query.order_by(Deployment.deployed_epoch.desc()).limit(limit)))


@router.get("/api/security/findings", response_model=list[SecurityFinding])
def security_findings(session: SessionDep, _: Viewer,
                      status: str | None = Query(None, pattern="^(open|remediated|accepted)$"),
                      limit: int = Query(200, ge=1, le=MAX_PAGE)) -> list[SecurityFindingRecord]:
    query = select(SecurityFindingRecord)
    if status:
        query = query.where(SecurityFindingRecord.status == status)
    return list(session.scalars(query.order_by(SecurityFindingRecord.created_epoch.desc()).limit(limit)))


@router.get("/api/audit", response_model=Page)
def audit_log(session: SessionDep, _: Operator,
              action: str | None = Query(None, pattern=r"^[a-z_.]{1,64}$"),
              limit: int = Query(100, ge=1, le=MAX_PAGE), offset: int = Query(0, ge=0)) -> Page:
    query = select(AuditLogRecord)
    count = select(func.count()).select_from(AuditLogRecord)
    if action:
        query = query.where(AuditLogRecord.action == action)
        count = count.where(AuditLogRecord.action == action)
    rows = session.scalars(query.order_by(AuditLogRecord.id.desc()).limit(limit).offset(offset)).all()
    return Page(total=session.scalar(count) or 0, limit=limit, offset=offset,
                items=[AuditLog.model_validate(r).model_dump() for r in rows])


@router.get("/api/audit/verify", response_model=ChainVerificationResponse)
def audit_verify(session: SessionDep, _: Admin) -> ChainVerificationResponse:
    result = verify_chain(session)
    return ChainVerificationResponse(valid=result.valid, rows=result.rows,
                                     first_invalid_id=result.first_invalid_id, reason=result.reason)

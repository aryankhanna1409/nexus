"""Incidents and their timelines."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Path, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.common import MAX_PAGE
from app.api.deps import SessionDep, Viewer
from app.models import IncidentAnomaly, IncidentCell, IncidentEventRecord, IncidentRecord
from app.schemas.entities import Incident, IncidentEvent, IncidentSummary

router = APIRouter(prefix="/api/incidents", tags=["incidents"])
INCIDENT_ID = r"^INC-\d{4}-\d{3,6}$"


def get_incident_or_404(session: Session, incident_id: str) -> IncidentRecord:
    incident = session.get(IncidentRecord, incident_id)
    if incident is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"incident {incident_id} not found")
    return incident


def incident_detail(session: Session, record: IncidentRecord) -> Incident:
    cells = session.scalars(select(IncidentCell).where(IncidentCell.incident_id == record.incident_id)
                            .order_by(IncidentCell.cell_id)).all()
    detail = Incident.model_validate(record)
    detail.affected_cells = [c.cell_id for c in cells]
    detail.affected_nodes = sorted({c.node_id for c in cells})
    detail.anomaly_ids = list(session.scalars(
        select(IncidentAnomaly.anomaly_id).where(IncidentAnomaly.incident_id == record.incident_id)
        .order_by(IncidentAnomaly.anomaly_id)))
    detail.events = [IncidentEvent.model_validate(e) for e in session.scalars(
        select(IncidentEventRecord).where(IncidentEventRecord.incident_id == record.incident_id)
        .order_by(IncidentEventRecord.epoch, IncidentEventRecord.id))]
    return detail


@router.get("", response_model=list[IncidentSummary])
def list_incidents(
    session: SessionDep, _: Viewer,
    status_filter: str | None = Query(None, alias="status",
                                      pattern="^(open|investigating|mitigated|resolved)$"),
    severity: str | None = Query(None, pattern="^(LOW|MEDIUM|HIGH|CRITICAL)$"),
    limit: int = Query(100, ge=1, le=MAX_PAGE),
) -> list[IncidentSummary]:
    query = select(IncidentRecord)
    if status_filter:
        query = query.where(IncidentRecord.status == status_filter)
    if severity:
        query = query.where(IncidentRecord.severity == severity)
    out = []
    for record in session.scalars(query.order_by(IncidentRecord.start_epoch.desc(),
                                                 IncidentRecord.incident_id.desc()).limit(limit)):
        summary = IncidentSummary.model_validate(record)
        summary.affected_cells = list(session.scalars(
            select(IncidentCell.cell_id).where(IncidentCell.incident_id == record.incident_id)
            .order_by(IncidentCell.cell_id)))
        out.append(summary)
    return out


@router.get("/{incident_id}", response_model=Incident)
def get_incident(session: SessionDep, _: Viewer,
                 incident_id: str = Path(..., pattern=INCIDENT_ID)) -> Incident:
    return incident_detail(session, get_incident_or_404(session, incident_id))

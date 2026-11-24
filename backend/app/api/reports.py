"""POST /api/reports/generate, GET /api/reports, GET /api/reports/{report_id}."""

from __future__ import annotations

import json
import time
from typing import Any

from fastapi import APIRouter, HTTPException, Path, Query, Request, Response, status
from pydantic import Field
from sqlalchemy import select

from app.api.common import MAX_PAGE
from app.api.deps import Operator, SessionDep, Viewer
from app.api.incidents import INCIDENT_ID
from app.models import IncidentRecord, ReportRecord, RootCauseAnalysisRecord
from app.reporting.builder import build_report
from app.reporting.render import render_html, render_markdown
from app.schemas.common import RequestModel, iso
from app.security.audit import record_audit

router = APIRouter(prefix="/api/reports", tags=["reports"])
REPORT_ID = r"^RPT-INC-\d{4}-\d{3,6}-\d{2}$"
HTML_HEADERS = {"Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'",
                "X-Content-Type-Options": "nosniff"}


class GenerateReportRequest(RequestModel):
    incident_id: str = Field(pattern=INCIDENT_ID)


def _summary(r: ReportRecord) -> dict[str, Any]:
    return {"report_id": r.report_id, "incident_id": r.incident_id, "rca_id": r.rca_id,
            "created_at": iso(r.created_epoch), "created_by": r.created_by,
            "formats": ["json", "markdown", "html"]}


@router.post("/generate", status_code=status.HTTP_201_CREATED)
def generate(body: GenerateReportRequest, request: Request, session: SessionDep,
             principal: Operator) -> dict[str, Any]:
    if session.get(IncidentRecord, body.incident_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"incident {body.incident_id} not found")
    doc = build_report(session, body.incident_id, request.app.state.llm, created_by=f"user:{principal.name}")
    rca_id = session.scalar(select(RootCauseAnalysisRecord.id).where(
        RootCauseAnalysisRecord.incident_id == body.incident_id, RootCauseAnalysisRecord.status == "completed")
        .order_by(RootCauseAnalysisRecord.id.desc()).limit(1))
    record = ReportRecord(report_id=doc.report_id, incident_id=body.incident_id, rca_id=rca_id,
                          created_epoch=int(time.time()), created_by=f"user:{principal.name}",
                          payload=doc.model_dump(mode="json"), markdown=render_markdown(doc),
                          html=render_html(doc))
    session.add(record)
    session.commit()
    record_audit(session, actor=principal.name, role=principal.role.name.lower(), action="report.generate",
                 resource_type="report", resource_id=doc.report_id,
                 details={"incident_id": body.incident_id, "rca_id": rca_id,
                          "narrative_provider": doc.narrative_provider})
    return {**_summary(record), "report": record.payload}


@router.get("")
def list_reports(session: SessionDep, _: Viewer, incident_id: str | None = Query(None, pattern=INCIDENT_ID),
                 limit: int = Query(100, ge=1, le=MAX_PAGE)) -> list[dict[str, Any]]:
    query = select(ReportRecord)
    if incident_id:
        query = query.where(ReportRecord.incident_id == incident_id)
    return [_summary(r) for r in session.scalars(query.order_by(ReportRecord.created_epoch.desc(),
                                                                ReportRecord.report_id.desc()).limit(limit))]


@router.get("/{report_id}")
def get_report(session: SessionDep, _: Viewer, report_id: str = Path(..., pattern=REPORT_ID),
               format: str = Query("json", pattern="^(json|markdown|html)$")) -> Response:
    record = session.get(ReportRecord, report_id)
    if record is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"report {report_id} not found")
    if format == "markdown":
        return Response(record.markdown, media_type="text/markdown; charset=utf-8")
    if format == "html":
        return Response(record.html, media_type="text/html; charset=utf-8", headers=HTML_HEADERS)
    return Response(json.dumps(record.payload, indent=2), media_type="application/json")

"""FastAPI dependencies: settings, DB session, authentication and role checks."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.config import Role, Settings
from app.security.audit import record_audit
from app.security.tokens import Principal, authenticate

_bearer = HTTPBearer(auto_error=False)


def get_settings(request: Request) -> Settings:
    settings: Settings = request.app.state.settings
    return settings


def get_session(request: Request) -> Iterator[Session]:
    session: Session = request.app.state.session_factory()
    try:
        yield session
    finally:
        session.close()


SessionDep = Annotated[Session, Depends(get_session)]
SettingsDep = Annotated[Settings, Depends(get_settings)]


def require_role(minimum: Role) -> Callable[..., Principal]:
    """Dependency factory: 401 without a valid token, 403 below `minimum`. Both are audited."""

    def dependency(
        request: Request,
        session: SessionDep,
        settings: SettingsDep,
        credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
    ) -> Principal:
        resource = f"{request.method} {request.url.path}"
        principal = authenticate(credentials.credentials, settings.api_tokens) if credentials else None
        if principal is None:
            record_audit(session, actor="anonymous", role="none", action="auth.denied",
                         resource_type="endpoint", resource_id=resource, outcome="denied",
                         details={"reason": "missing or invalid bearer token"})
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid or missing bearer token",
                                headers={"WWW-Authenticate": "Bearer"})
        if not principal.has(minimum):
            record_audit(session, actor=principal.name, role=principal.role.name.lower(),
                         action="auth.forbidden", resource_type="endpoint", resource_id=resource,
                         outcome="denied", details={"required_role": minimum.name.lower()})
            raise HTTPException(status.HTTP_403_FORBIDDEN,
                                f"requires role {minimum.name.lower()} or higher")
        request.state.principal = principal
        return principal

    return dependency


Viewer = Annotated[Principal, Depends(require_role(Role.VIEWER))]
Operator = Annotated[Principal, Depends(require_role(Role.OPERATOR))]
Approver = Annotated[Principal, Depends(require_role(Role.APPROVER))]
Admin = Annotated[Principal, Depends(require_role(Role.ADMIN))]

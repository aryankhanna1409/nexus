"""Action policy (spec §12): risk classes, approval rules and who may execute.

Enforced in application code by `app.agents.service.execute_action`, which
re-checks every rule immediately before execution. The API layer is only a
second line of defence.

| Risk class         | Policy                                                            |
|--------------------|-------------------------------------------------------------------|
| READ_ONLY          | runs automatically                                                |
| LOW_RISK           | runs automatically                                                |
| REQUIRES_APPROVAL  | approver (not the run's initiator) must approve; operator+ executes |
| HIGH_RISK          | as above, executed by an admin, and only if AGENT_ALLOW_HIGH_RISK  |
| BLOCKED            | never runs                                                        |
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from app.config import Role


class RiskClass(StrEnum):
    READ_ONLY = "READ_ONLY"
    LOW_RISK = "LOW_RISK"
    REQUIRES_APPROVAL = "REQUIRES_APPROVAL"
    HIGH_RISK = "HIGH_RISK"
    BLOCKED = "BLOCKED"


class Decision(StrEnum):
    ALLOW = "allow"
    NEEDS_APPROVAL = "needs_approval"
    DENY = "deny"


@dataclass(frozen=True)
class PolicyDecision:
    decision: Decision
    reason: str


def evaluate(risk: RiskClass, allow_high_risk: bool) -> PolicyDecision:
    if risk in (RiskClass.READ_ONLY, RiskClass.LOW_RISK):
        return PolicyDecision(Decision.ALLOW, f"{risk.value} actions run without approval")
    if risk is RiskClass.REQUIRES_APPROVAL:
        return PolicyDecision(Decision.NEEDS_APPROVAL, "requires approval by an approver")
    if risk is RiskClass.HIGH_RISK:
        if not allow_high_risk:
            return PolicyDecision(Decision.DENY, "HIGH_RISK actions are disabled by policy "
                                                 "(AGENT_ALLOW_HIGH_RISK=false); recommend to a human instead")
        return PolicyDecision(Decision.NEEDS_APPROVAL, "HIGH_RISK: approval plus admin execution required")
    return PolicyDecision(Decision.DENY, "BLOCKED actions never run")


def executor_role(risk: RiskClass) -> Role:
    """Minimum role allowed to execute an approved action."""
    return Role.ADMIN if risk is RiskClass.HIGH_RISK else Role.OPERATOR

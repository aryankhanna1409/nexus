"""JSON structured logging with request, incident and agent-run identifiers."""

from __future__ import annotations

import json
import logging
import time
from typing import Any

from app.observability.context import agent_run_id_var, incident_id_var, request_id_var

LOGGER_NAME = "aegis"
CONTEXT_FIELDS = ("request_id", "incident_id", "agent_run_id")
_RESERVED = (set(vars(logging.LogRecord("", 0, "", 0, "", None, None))) | {"message", "asctime"}
             | set(CONTEXT_FIELDS))
_installed = False


def _install_record_factory() -> None:
    """Stamp context identifiers onto each record when it is *created*, so handlers that
    format later (buffering, shipping, test capture) still see the right values."""
    global _installed
    if _installed:
        return
    previous = logging.getLogRecordFactory()

    def factory(*args: Any, **kwargs: Any) -> logging.LogRecord:
        record = previous(*args, **kwargs)
        record.request_id = request_id_var.get()
        record.incident_id = incident_id_var.get()
        record.agent_run_id = agent_run_id_var.get()
        return record

    logging.setLogRecordFactory(factory)
    _installed = True


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created)) + f".{int(record.msecs):03d}Z",
            "level": record.levelname, "logger": record.name, "message": record.getMessage(),
            **{name: getattr(record, name, None) for name in CONTEXT_FIELDS},
        }
        payload.update({k: v for k, v in vars(record).items() if k not in _RESERVED and not k.startswith("_")})
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def configure_logging(level: str = "INFO") -> logging.Logger:
    _install_record_factory()
    logger = logging.getLogger(LOGGER_NAME)
    if not any(getattr(h, "_aegis", False) for h in logger.handlers):
        handler = logging.StreamHandler()
        handler.setFormatter(JsonFormatter())
        handler._aegis = True  # type: ignore[attr-defined]
        logger.addHandler(handler)
    logger.setLevel(level)
    logger.propagate = True  # lets test harnesses capture records
    return logger


def get_logger(name: str = "") -> logging.Logger:
    return logging.getLogger(f"{LOGGER_NAME}.{name}" if name else LOGGER_NAME)

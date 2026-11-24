"""Renders a ReportDocument as JSON, Markdown or HTML (Jinja2; HTML autoescaped)."""

from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, StrictUndefined, select_autoescape

from app.reporting.document import ReportDocument

_TEMPLATES = Path(__file__).resolve().parent / "templates"


def _md_cell(value: object) -> str:
    """Escape Markdown table/HTML-significant characters in untrusted text."""
    text = str(value).replace("\\", "\\\\").replace("|", "\\|").replace("\n", " ")
    return text.replace("<", "&lt;").replace(">", "&gt;")


def _pct(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.0%}"


_html_env = Environment(loader=FileSystemLoader(_TEMPLATES), autoescape=select_autoescape(["html", "j2"]),
                        undefined=StrictUndefined, trim_blocks=True, lstrip_blocks=True)
_md_env = Environment(loader=FileSystemLoader(_TEMPLATES), autoescape=False, undefined=StrictUndefined,
                      trim_blocks=True, lstrip_blocks=True)
for _env in (_html_env, _md_env):
    _env.filters["pct"] = _pct
_md_env.filters["md"] = _md_cell


def render_json(doc: ReportDocument) -> str:
    return doc.model_dump_json(indent=2)


def render_markdown(doc: ReportDocument) -> str:
    return _md_env.get_template("report.md.j2").render(r=doc)


def render_html(doc: ReportDocument) -> str:
    return _html_env.get_template("report.html.j2").render(r=doc)

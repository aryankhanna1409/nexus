"""One self-contained HTML incident report (no external files, opens offline)."""
from __future__ import annotations

import html
import json
import statistics

from .simulate import METRICS, NOW, World, iso

CHART_METRICS = [("memory_pct", "Memory"), ("latency_ms", "Latency"), ("call_drop_pct", "Dropped calls")]
X0, X1 = 60, 240   # 13:00 to 16:00


def e(x) -> str:
    return html.escape(str(x))


def _series(world: World, cells: list[str], metric: str) -> list[float]:
    return [statistics.fmean(world.metrics[c][metric][m] for c in cells) for m in range(X0, X1)]


def chart(title: str, unit: str, before: list[float], after: list[float] | None, marks: list[tuple[int, str]]) -> str:
    w, h, pl, pr, pt, pb = 560, 190, 44, 12, 26, 26
    vals = before + (after or [])
    lo, hi = min(vals), max(vals)
    pad = (hi - lo) * 0.08 or 1
    lo, hi = max(0.0, lo - pad), hi + pad

    def x(m: int) -> float:
        return pl + (m - X0) / (X1 - X0 - 1) * (w - pl - pr)

    def y(v: float) -> float:
        return pt + (hi - v) / (hi - lo) * (h - pt - pb)

    def path(vs: list[float], start: int = 0) -> str:
        return "M" + " L".join(f"{x(X0 + i):.1f},{y(v):.1f}" for i, v in enumerate(vs) if i >= start)

    grid = "".join(f'<line x1="{pl}" x2="{w - pr}" y1="{y(t):.1f}" y2="{y(t):.1f}" class="grid"/>'
                   f'<text x="{pl - 6}" y="{y(t) + 4:.1f}" class="tick" text-anchor="end">{t:g}</text>'
                   for t in _ticks(lo, hi))
    xt = "".join(f'<text x="{x(m):.1f}" y="{h - 6}" class="tick" text-anchor="middle">{iso(m)[11:16]}</text>'
                 for m in range(X0, X1 + 1, 60) if m < X1)
    mk = "".join(f'<line x1="{x(m):.1f}" x2="{x(m):.1f}" y1="{pt}" y2="{h - pb}" class="mark"/>'
                 f'<text x="{x(m) + 4:.1f}" y="{pt - 8}" class="marklabel">{e(label)}</text>' for m, label in marks)
    lines = f'<path d="{path(before)}" class="{"bad" if after else "line"}"/>'
    if after:
        lines += f'<path d="{path(after, NOW - X0 - 1)}" class="good"/>'
    return (f'<figure class="chart"><figcaption>{e(title)} <span>{e(unit)}, average of affected cells</span></figcaption>'
            f'<svg viewBox="0 0 {w} {h}" role="img" aria-label="{e(title)} over time">{grid}{xt}{mk}{lines}</svg></figure>')


def _ticks(lo: float, hi: float) -> list[float]:
    span = hi - lo
    step = next(s for s in (0.5, 1, 2, 5, 10, 20, 25, 50, 100, 200, 250, 500) if span / s <= 4)
    t = (lo // step + 1) * step
    out = []
    while t < hi:
        out.append(round(t, 2))
        t += step
    return out


def build(world: World, incident: dict, anomalies: list[dict], calls: dict, rca: dict, agent: dict,
          audit_status: tuple[bool, str]) -> str:
    fixed = agent.get("fixed_world")
    cells = incident["cells"]
    deploy = next(d for d in world.deployments if d["node"] == incident["node"] and d["minute"] <= incident["onset_minute"])
    marks = [(deploy["minute"], f"{deploy['to_version']} deployed")]
    if fixed:
        marks.append((NOW, "rollback"))
    charts = "".join(chart(t, METRICS[m][0], _series(world, cells, m), _series(fixed, cells, m) if fixed else None, marks)
                     for m, t in CHART_METRICS)

    flagged = {a["cell_id"] for a in calls["anomalies"]}
    status = incident["status"]
    evid = {x["id"]: x for x in rca["evidence"]}

    def chips(ids: list[str]) -> str:
        return "".join(f'<span class="chip" title="{e(evid[i]["tool"])} {e(json.dumps(evid[i]["input"]))}">{e(i)}</span>'
                       for i in ids if i in evid)

    facts = "".join(f"<li>{e(f['statement'])} {chips(f['evidence'])}</li>" for f in rca["facts"])
    alts = "".join(f"<li><b>{e(a['cause_type'].replace('_', ' '))}</b> {a['confidence']:.0%}: {e(a['why_less_likely'])}</li>"
                   for a in rca["alternatives"]) or "<li>None given.</li>"
    trail = "".join(f"<tr><td class='mono'>{e(x['id'])}</td><td class='mono'>{e(x['tool'])}</td>"
                    f"<td class='mono small'>{e(json.dumps(x['input']) if x['input'] else '')}</td></tr>" for x in rca["evidence"])
    symptoms = "".join(f"<tr><td>{e(s['onset'][11:16])}</td><td class='mono'>{e(s['metric'])}</td><td>{s['baseline']}</td>"
                       f"<td>{s['worst']}</td><td><span class='sev {e(s['severity'])}'>{e(s['severity'])}</span></td></tr>"
                       for s in incident["symptoms"])
    call_rows = "".join(
        f"<tr class='{'flag' if c['cell_id'] in flagged else ''}'><td class='mono'>{e(c['cell_id'])}</td><td>{c['total']}</td>"
        f"<td>{100 * c['drop_rate']:.2f}</td><td>{100 * c['setup_failure_rate']:.2f}</td>"
        f"<td>{c['avg_signal_dbm']:.1f}</td><td>{c['avg_packet_loss']:.2f}</td></tr>" for c in calls["cells"])

    def short(r) -> str:
        if isinstance(r, dict):
            for k in ("rolled_back", "changed", "summary"):
                if k in r:
                    return str(r[k])
            if "recovered" in r:
                return "recovered" if r["recovered"] else "NOT recovered"
            if "passed" in r:
                return "tests passed" if r["passed"] else "tests FAILED"
            if "vulnerable" in r:
                return f"{len(r['vulnerable'])} vulnerable" + "".join(f" ({v['package']} {v['advisory']})" for v in r["vulnerable"])
            return "ok"
        return str(r)

    actions = "".join(
        f"<tr><td class='mono'>{e(a['tool'])}</td><td><span class='risk {e(a['risk'])}'>{e(a['risk'].replace('_', ' '))}</span></td>"
        f"<td>{'approved' if a.get('approved') else ('denied' if a['status'] == 'denied' else '')}</td>"
        f"<td><span class='st {e(a['status'])}'>{e(a['status'])}</span></td><td>{e(short(a.get('result')))}</td></tr>"
        for a in agent["actions"])
    reasons = "".join(f"<li><span class='mono'>{e(a['tool'])}</span>: {e(a['input'].get('reason', ''))}</li>"
                      for a in agent["actions"] if a["risk"] == "needs_approval")
    lead = incident["onset_minute"] - deploy["minute"]
    dropped = sum(round(c["drop_rate"] * (c["completed"] + c["dropped"])) for c in calls["cells"] if c["cell_id"] in cells)
    failed = sum(round(c["setup_failure_rate"] * c["total"]) for c in calls["cells"] if c["cell_id"] in cells)
    ok, chain = audit_status

    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{e(incident['id'])} incident report</title><style>{CSS}</style></head><body><main>
<header><div class="eyebrow">nexus incident report · synthetic data</div>
<h1>{e(incident['id'])} <span class="sev {e(incident['severity'].lower())}">{e(incident['severity'])}</span>
<span class="status {e(status)}">{e(status)}</span></h1>
<p class="lede">{e(rca['root_cause'])}</p></header>

<section class="cards">
<div class="card"><div class="k">Root cause</div><div class="v">{e(rca['cause_type'].replace('_', ' '))}</div><div class="s">{rca['confidence']:.0%} confidence, a hypothesis</div></div>
<div class="card"><div class="k">Detected</div><div class="v">{lead} min</div><div class="s">after the {e(deploy['to_version'])} deploy at {e(deploy['time'][11:16])}</div></div>
<div class="card"><div class="k">Calls hurt (14:00-15:00)</div><div class="v">{dropped + failed}</div><div class="s">{dropped} dropped, {failed} failed to connect</div></div>
<div class="card"><div class="k">Outcome</div><div class="v">{'recovered' if status == 'resolved' else 'still open'}</div><div class="s">{e((agent.get('finished') or {}).get('summary', ''))}</div></div>
</section>

<section><h2>Before and after the fix</h2>
<p class="note">{'<span class="key bad"></span>without the fix &nbsp; <span class="key good"></span>after the agent rolled back at 15:00' if fixed else 'The rollback was not approved, so there is no "after" line.'}</p>
<div class="charts">{charts}</div></section>

<section class="two"><div><h2>Symptoms, in the order they started</h2>
<table><tr><th>Onset</th><th>Metric</th><th>Baseline</th><th>Worst</th><th>Severity</th></tr>{symptoms}</table>
<p class="note">{len(anomalies)} anomalies across {len(cells)} cells on {e(incident['node'])}. Ruled out: {e('; '.join(x['cause'] + ' (' + x['reason'] + ')' for x in incident['excluded']) or 'nothing')}.</p></div>
<div><h2>C call-log analysis, last hour</h2>
<table><tr><th>Cell</th><th>Calls</th><th>Drop %</th><th>Fail %</th><th>Signal dBm</th><th>Loss %</th></tr>{call_rows}</table>
<p class="note">libcallanalyzer {e(calls['library_version'])} parsed {calls['parse']['parsed']:,} calls; highlighted rows are the cells it flagged as outliers.</p></div></section>

<section class="two"><div><h2>AI investigation</h2><p class="note">Investigator: {e(rca['provider'])}. Every fact cites the tool result it came from (hover a chip).</p>
<ul class="facts">{facts}</ul><h3>Other explanations considered</h3><ul class="facts">{alts}</ul></div>
<div><h2>Evidence trail</h2><table><tr><th>Id</th><th>Tool</th><th>Input</th></tr>{trail}</table></div></section>

<section><h2>DevSecOps agent</h2><p class="note">Agent: {e(agent['provider'])}. Risky steps paused for a human.</p>
<table><tr><th>Tool</th><th>Risk</th><th>Human</th><th>Status</th><th>Result</th></tr>{actions}</table>
{f'<h3>Why the agent asked for approval</h3><ul class="facts">{reasons}</ul>' if reasons else ''}
{f'<h3>Code change</h3><pre>{e(agent["diff"])}</pre>' if agent.get('diff') else ''}
<p class="note audit {'ok' if ok else 'broken'}">Audit log: {e(chain)}.</p></section>
<footer>Generated by nexus from simulated data. Nothing here describes a real network.</footer>
</main></body></html>"""


CSS = """
:root{--bg:#0b1020;--panel:#111a33;--line:#22305a;--fg:#e6edf3;--muted:#93a1b8;--accent:#5aa2ff;--good:#34d399;--bad:#f87171;--warn:#fbbf24}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:1180px;margin:0 auto;padding:32px max(16px,env(safe-area-inset-left))}
h1{font-size:30px;margin:6px 0 8px;display:flex;gap:12px;align-items:center;flex-wrap:wrap}h2{font-size:18px;margin:0 0 10px}h3{font-size:15px;margin:18px 0 6px;color:var(--muted)}
.eyebrow{font:12px ui-monospace,Menlo,monospace;letter-spacing:.08em;text-transform:uppercase;color:var(--muted)}
.lede{font-size:17px;max-width:75ch;margin:0}section{margin-top:28px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px}.card .k{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.06em}
.card .v{font-size:24px;font-weight:650;margin:2px 0}.card .s{color:var(--muted);font-size:13px}
.charts{display:grid;grid-template-columns:repeat(auto-fit,minmax(340px,1fr));gap:12px}
.chart{margin:0;background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:10px 10px 4px}
.chart figcaption{font-weight:600}.chart figcaption span{color:var(--muted);font-weight:400;font-size:12px}
svg{width:100%;height:auto;display:block}.grid{stroke:var(--line)}.tick{fill:var(--muted);font-size:10px}
.mark{stroke:var(--warn);stroke-dasharray:3 3}.marklabel{fill:var(--warn);font-size:10px}
path{fill:none;stroke-width:2}.line{stroke:var(--accent)}.bad{stroke:var(--bad);stroke-dasharray:5 3;opacity:.85}.good{stroke:var(--good);stroke-width:2.5}
.key{display:inline-block;width:18px;height:0;border-top:3px solid;vertical-align:middle}.key.bad{border-color:var(--bad);border-top-style:dashed}.key.good{border-color:var(--good)}
.two{display:grid;grid-template-columns:repeat(auto-fit,minmax(420px,1fr));gap:24px}
table{width:100%;border-collapse:collapse;font-size:13px;background:var(--panel);border:1px solid var(--line);border-radius:10px;overflow:hidden}
th,td{text-align:left;padding:7px 10px;border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--muted);font-weight:500;font-size:12px}
tr.flag td{background:rgba(248,113,113,.12)}.mono{font-family:ui-monospace,Menlo,monospace}.small{font-size:11px;color:var(--muted)}
.note{color:var(--muted);font-size:13px}.facts{padding-left:18px}.facts li{margin:5px 0}
.chip{display:inline-block;font:11px ui-monospace,Menlo,monospace;background:#1b2a52;color:var(--accent);border-radius:4px;padding:1px 6px;margin-left:3px;cursor:help}
.sev,.status,.risk,.st{font-size:11px;font-weight:600;padding:2px 8px;border-radius:999px;text-transform:uppercase;letter-spacing:.04em}
.sev.critical{background:#4c1d1d;color:#fca5a5}.sev.high{background:#4a3410;color:#fcd34d}.sev.medium{background:#1e3a5f;color:#93c5fd}
.status.resolved,.st.done{background:#123b2c;color:var(--good)}.status.open,.status.mitigating,.st.denied,.st.failed,.st.blocked{background:#4c1d1d;color:#fca5a5}
.risk.read_only{background:#1e293b;color:var(--muted)}.risk.needs_approval{background:#4a3410;color:#fcd34d}
pre{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:12px;overflow-x:auto;font-size:12px}
.audit.ok::before{content:"✔ ";color:var(--good)}.audit.broken::before{content:"✘ ";color:var(--bad)}
footer{margin-top:36px;color:var(--muted);font-size:12px}
"""

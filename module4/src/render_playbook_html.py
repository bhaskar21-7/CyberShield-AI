"""
render_playbook_html.py
-------------------------
Same job as render_playbook.py (turn a raw JSON playbook into something
readable), but outputs a standalone, styled .html file instead of
Markdown — matches the landing page's dark theme exactly (colors and
glow effects pulled directly from landing/styles.css and animations.css,
not eyeballed) so it feels like part of the same product.

Design choices, and why:
- LLM-generated sections (Threat Summary / Root Cause / Executive Summary)
  and the Evidence/MITRE tables are shown OPEN, front and center — that's
  what a judge or non-technical reader actually needs to see first.
- Verbose technical sections (raw commands, YARA/Snort/Sigma rules, CVE
  candidates, recovery steps, checklist) are collapsed by default using
  native <details>/<summary> — no JS framework, no bugs, works in every
  browser. This fixes the "wall of text" problem without hiding anything;
  one click expands each section.
- Code blocks get a "Copy" button (vanilla JS, no dependencies) — small
  but real usability improvement if someone actually wants to use the
  generated commands/rules.
- A "Print / Save as PDF" button uses the browser's native window.print()
  with dedicated @media print CSS (expands all collapsed sections and
  strips the dark background so it prints on white paper) — gives you a
  physical handout for judges without needing any conversion tool.

This is a STATIC file — no server, no backend, opens by double-clicking
or dragging into any browser. That was deliberate: a live backend was
explicitly ruled out for this project given the timeline.

Usage:
    python render_playbook_html.py                    # most recent event with a playbook
    python render_playbook_html.py --index -2          # a specific one
    python render_playbook_html.py --output report.html
"""

import argparse
import html
import json
import os

EVENT_LOG_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "event_log.jsonl")
DEFAULT_OUTPUT = os.path.join(os.path.dirname(__file__), "..", "data", "incident_report.html")

CSS = """
:root {
    --primary-color: #00D9FF;
    --secondary-color: #0969DA;
    --accent-color: #DA3633;
    --dark-bg: #0D1117;
    --card-bg: #161B22;
    --border-color: #30363D;
    --text-primary: #E6EDF3;
    --text-secondary: #8b949e;
    --success-color: #1a7f37;
    --warning-color: #d29922;
}
* { box-sizing: border-box; }
body {
    background: var(--dark-bg);
    color: var(--text-primary);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    max-width: 900px;
    margin: 0 auto;
    padding: 40px 24px 80px;
    line-height: 1.6;
}
.topbar {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 20px;
}
.print-btn {
    background: var(--card-bg);
    border: 1px solid var(--primary-color);
    color: var(--primary-color);
    padding: 8px 18px;
    border-radius: 20px;
    cursor: pointer;
    font-size: 0.85rem;
    transition: box-shadow 0.2s ease;
}
.print-btn:hover { box-shadow: 0 0 16px rgba(0, 217, 255, 0.4); }
h1 {
    color: var(--primary-color);
    border-bottom: 2px solid var(--border-color);
    padding-bottom: 16px;
    font-size: 1.8rem;
    text-shadow: 0 0 30px rgba(0, 217, 255, 0.3);
}
h2 {
    color: var(--primary-color);
    margin-top: 40px;
    font-size: 1.3rem;
    display: flex;
    align-items: center;
    gap: 8px;
}
h2 .tag {
    font-size: 0.7rem;
    font-weight: normal;
    font-style: italic;
    color: var(--text-secondary);
    background: var(--card-bg);
    border: 1px solid var(--border-color);
    border-radius: 12px;
    padding: 2px 10px;
}
h2 .tag.llm { color: var(--primary-color); border-color: var(--primary-color); }
.meta-box {
    background: var(--card-bg);
    border: 1px solid var(--border-color);
    border-radius: 8px;
    padding: 20px 24px;
    margin: 20px 0;
    box-shadow: 0 20px 40px rgba(0, 217, 255, 0.1);
}
.meta-box div { margin: 6px 0; }
.risk-badge {
    display: inline-block;
    padding: 4px 16px;
    border-radius: 20px;
    font-weight: bold;
    font-size: 0.95rem;
}
.risk-Critical { background: rgba(218, 54, 51, 0.15); color: var(--accent-color); border: 1px solid var(--accent-color); box-shadow: 0 0 16px rgba(218, 54, 51, 0.3); }
.risk-Medium { background: rgba(210, 153, 34, 0.15); color: var(--warning-color); border: 1px solid var(--warning-color); }
.risk-Low { background: rgba(26, 127, 55, 0.15); color: var(--success-color); border: 1px solid var(--success-color); }
.risk-meter-track {
    width: 100%;
    height: 8px;
    background: var(--border-color);
    border-radius: 4px;
    margin-top: 10px;
    overflow: hidden;
}
.risk-meter-fill {
    height: 100%;
    border-radius: 4px;
}
code {
    background: var(--card-bg);
    border: 1px solid var(--border-color);
    border-radius: 4px;
    padding: 2px 6px;
    font-family: "SF Mono", Consolas, monospace;
    font-size: 0.9em;
    color: var(--primary-color);
}
pre {
    background: var(--card-bg);
    border: 1px solid var(--border-color);
    border-radius: 8px;
    padding: 16px;
    overflow-x: auto;
    position: relative;
}
pre code {
    background: none;
    border: none;
    padding: 0;
    color: var(--text-primary);
}
.copy-btn {
    position: absolute;
    top: 10px;
    right: 10px;
    background: var(--dark-bg);
    border: 1px solid var(--border-color);
    color: var(--text-secondary);
    border-radius: 4px;
    padding: 4px 10px;
    font-size: 0.75rem;
    cursor: pointer;
}
.copy-btn:hover { color: var(--primary-color); border-color: var(--primary-color); }
.disclaimer {
    background: rgba(210, 153, 34, 0.1);
    border-left: 3px solid var(--warning-color);
    padding: 14px 18px;
    border-radius: 4px;
    margin: 20px 0;
    color: var(--text-secondary);
}
table { width: 100%; border-collapse: collapse; margin: 16px 0; }
th, td { border: 1px solid var(--border-color); padding: 10px 14px; text-align: left; }
th { background: var(--card-bg); color: var(--primary-color); }
ul.checklist, ul.actions { list-style: none; padding-left: 0; }
ul.checklist li, ul.actions li {
    padding: 8px 0 8px 30px;
    position: relative;
    border-bottom: 1px solid var(--border-color);
}
ul.checklist li::before, ul.actions li::before {
    content: "\\2610";
    position: absolute;
    left: 0;
    color: var(--primary-color);
}
ul.plain { padding-left: 20px; }
details {
    background: var(--card-bg);
    border: 1px solid var(--border-color);
    border-radius: 8px;
    margin: 16px 0;
    padding: 4px 20px;
}
details summary {
    cursor: pointer;
    padding: 14px 0;
    color: var(--primary-color);
    font-weight: 600;
    list-style: none;
    display: flex;
    align-items: center;
    gap: 8px;
}
details summary::-webkit-details-marker { display: none; }
details summary::before { content: "\\25B6"; font-size: 0.7rem; transition: transform 0.15s ease; }
details[open] summary::before { transform: rotate(90deg); }
details[open] summary { border-bottom: 1px solid var(--border-color); }
details .tag { margin-left: auto; }
.footer-note {
    margin-top: 50px;
    padding-top: 20px;
    border-top: 1px solid var(--border-color);
    color: var(--text-secondary);
    font-size: 0.85rem;
    font-style: italic;
}
@media print {
    .print-btn { display: none; }
    body { background: white; color: black; max-width: 100%; }
    .meta-box, pre, details, table, .disclaimer { background: #f5f5f5; color: black; box-shadow: none; }
    details { border: 1px solid #ccc; }
    h1, h2 { color: #000; text-shadow: none; }
    .copy-btn { display: none; }
    code { color: #000; }
}
"""

JS = """
function copyCode(btn) {
    const code = btn.parentElement.querySelector('code').innerText;
    const showCopied = () => {
        const orig = btn.innerText;
        btn.innerText = 'Copied!';
        setTimeout(() => { btn.innerText = orig; }, 1500);
    };
    // navigator.clipboard requires a "secure context" (https/localhost) and
    // is BLOCKED on file:// pages, which is exactly how this report is
    // normally opened (double-clicked from disk). Confirmed directly: it
    // throws "Write permission denied" on file://, not a hypothetical edge
    // case. Fall back to the older execCommand method, which does work
    // there, instead of silently failing with no feedback to the user.
    if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(code).then(showCopied).catch(() => fallbackCopy(code, showCopied));
    } else {
        fallbackCopy(code, showCopied);
    }
}
function fallbackCopy(text, onSuccess) {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.focus();
    ta.select();
    try {
        document.execCommand('copy');
        onSuccess();
    } catch (e) {
        alert('Copy failed - please select and copy the text manually.');
    }
    document.body.removeChild(ta);
}
function printReport() {
    document.querySelectorAll('details').forEach(d => d.setAttribute('open', ''));
    window.print();
}
"""


def load_events_with_playbooks(path: str) -> list:
    events = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            if record.get("playbook"):
                events.append(record)
    return events


def esc(x) -> str:
    return html.escape(str(x))


def code_block(content: str, lang_class: str = "") -> str:
    return f'<pre><button class="copy-btn" onclick="copyCode(this)">Copy</button><code class="{lang_class}">{esc(content)}</code></pre>'


def render_event_html(event: dict) -> str:
    pb = event["playbook"]
    meta = pb.get("_metadata", {})
    risk_level = event.get("risk_level", "?")
    risk_frac = float(event.get("final_risk_probability", 0))
    risk_pct = f"{risk_frac * 100:.1f}%"
    meter_color = {"Critical": "var(--accent-color)", "Medium": "var(--warning-color)", "Low": "var(--success-color)"}.get(risk_level, "var(--primary-color)")

    parts = []
    parts.append(
        '<div class="topbar"><div></div>'
        '<button class="print-btn" onclick="printReport()">🖨️ Print / Save as PDF</button></div>'
    )
    parts.append(f"<h1>Incident Report — {esc(meta.get('threat_category', 'Unclassified'))}</h1>")

    conf = pb.get("confidence_score", {})
    parts.append('<div class="meta-box">')
    parts.append(f"<div><strong>Generated:</strong> {esc(event.get('stored_at', 'unknown'))}</div>")
    parts.append(f"<div><strong>Source → Destination:</strong> <code>{esc(event.get('source_ip', '?'))}</code> → <code>{esc(event.get('destination_ip', '?'))}</code></div>")
    parts.append(f"<div><strong>Channel / Protocol:</strong> {esc(event.get('channel', '?'))} / {esc(event.get('protocol', '?'))}</div>")
    parts.append(f'<div><strong>Risk Level:</strong> <span class="risk-badge risk-{esc(risk_level)}">{esc(risk_level)} — {risk_pct}</span></div>')
    parts.append(f'<div class="risk-meter-track"><div class="risk-meter-fill" style="width:{risk_frac*100:.1f}%; background:{meter_color};"></div></div>')
    if conf:
        parts.append(f"<div style='margin-top:14px'><strong>Confidence:</strong> {esc(conf.get('confidence_percent', '?'))}% — {esc(conf.get('basis', ''))}</div>")
    parts.append("</div>")

    parts.append(
        '<div class="disclaimer">⚠️ <strong>How to read this report:</strong> the Threat Summary, '
        'Root Cause, and Executive Summary sections are written by an LLM (Google Gemini), grounded '
        'in the real detection data below. Every other section — evidence, commands, detection rules, '
        'MITRE mapping, CVE candidates — comes from a fixed, deterministic template, not the LLM. '
        'Section headers are labeled so you always know which is which.</div>'
    )

    for key, title, icon in [("threat_summary", "Threat Summary", "🧠"),
                              ("root_cause", "Root Cause Analysis", "🔍"),
                              ("executive_summary", "Executive Summary", "📋")]:
        text = pb.get(key, "")
        if text:
            parts.append(f'<h2>{icon} {title} <span class="tag llm">LLM-generated</span></h2>')
            parts.append(f"<p>{esc(text)}</p>")

    evidence = pb.get("evidence", {})
    top_features = evidence.get("top_features", [])
    contributions = evidence.get("feature_contributions", {})
    if top_features:
        parts.append('<h2>📊 Evidence <span class="tag">template-derived, real SHAP output</span></h2>')
        parts.append("<table><tr><th>Feature</th><th>SHAP Contribution</th></tr>")
        for f in top_features:
            parts.append(f"<tr><td>{esc(f)}</td><td>{contributions.get(f, 0):+.3f}</td></tr>")
        parts.append("</table>")
        if evidence.get("raw_content_sample"):
            parts.append(f"<p><strong>Raw event content sample:</strong></p>{code_block(evidence['raw_content_sample'])}")

    mitre = pb.get("mitre_attack_mapping", [])
    if mitre:
        parts.append('<h2>🎯 MITRE ATT&CK Mapping <span class="tag">template-derived</span></h2>')
        parts.append("<table><tr><th>Tactic</th><th>Technique ID</th><th>Technique Name</th></tr>")
        for m in mitre:
            parts.append(f"<tr><td>{esc(m.get('tactic',''))}</td><td>{esc(m.get('technique_id',''))}</td><td>{esc(m.get('technique_name',''))}</td></tr>")
        parts.append("</table>")

    actions = pb.get("immediate_actions", [])
    if actions:
        parts.append('<h2>⚡ Immediate Actions <span class="tag">template-derived</span></h2>')
        parts.append('<ul class="actions">' + "".join(f"<li>{esc(a)}</li>" for a in actions) + "</ul>")

    # --- Collapsed-by-default technical sections ---
    cmd_sections = [("linux_commands", "🐧 Linux Commands"), ("windows_commands", "🪟 Windows Commands"), ("firewall_rules", "🔥 Firewall Rules")]
    for key, label in cmd_sections:
        cmds = pb.get(key, [])
        if cmds:
            parts.append(f'<details><summary>{label} <span class="tag">template-derived</span></summary>{code_block(chr(10).join(cmds))}</details>')

    for key, label in [("yara_rule", "🛡️ YARA Rule"), ("snort_rule", "🛡️ Snort Rule"), ("sigma_rule", "🛡️ Sigma Rule")]:
        rule = pb.get(key)
        if rule:
            parts.append(f'<details><summary>{label} <span class="tag">syntax-validated</span></summary>{code_block(rule)}</details>')

    cve = pb.get("cve_suggestions", {})
    candidates = cve.get("candidates", [])
    if candidates:
        rows = "".join(f"<tr><td>{esc(c.get('cve_id',''))}</td><td>{esc(c.get('name',''))}</td><td>{esc(c.get('note',''))}</td></tr>" for c in candidates)
        parts.append(
            f'<details><summary>🗂️ CVE Candidates <span class="tag">illustrative only</span></summary>'
            f'<div class="disclaimer">{esc(cve.get("disclaimer", ""))}</div>'
            f'<table><tr><th>CVE ID</th><th>Name</th><th>Relevance Note</th></tr>{rows}</table></details>'
        )

    recovery = pb.get("recovery_steps", [])
    if recovery:
        parts.append(
            '<details><summary>🔧 Recovery Steps <span class="tag">template-derived</span></summary>'
            + '<ul class="plain">' + "".join(f"<li>{esc(r)}</li>" for r in recovery) + "</ul></details>"
        )

    checklist = pb.get("post_incident_checklist", [])
    if checklist:
        cleaned = [c.replace("[ ]", "").strip() for c in checklist]
        parts.append(
            '<details><summary>✅ Post-Incident Checklist <span class="tag">template-derived</span></summary>'
            + '<ul class="checklist">' + "".join(f"<li>{esc(c)}</li>" for c in cleaned) + "</ul></details>"
        )

    parts.append(
        f'<div class="footer-note">Generated by Bayesian Sentinel Module 4 — generate_response_playbook(). '
        f'LLM sections: {esc(", ".join(meta.get("llm_sections", [])))}. '
        f'Template sections: {esc(", ".join(meta.get("template_sections", [])))}.</div>'
    )

    return "\n".join(parts)


def build_html(body: str, title: str) -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>{esc(title)}</title>
<style>{CSS}</style>
</head>
<body>
{body}
<script>{JS}</script>
</body>
</html>"""


def main():
    parser = argparse.ArgumentParser(description="Render a JSON playbook as a styled, standalone HTML incident report.")
    parser.add_argument("--index", type=int, default=-1, help="Index into playbook-only event list (default -1 = most recent).")
    parser.add_argument("--output", type=str, default=DEFAULT_OUTPUT)
    parser.add_argument("--log-path", type=str, default=EVENT_LOG_PATH)
    args = parser.parse_args()

    events = load_events_with_playbooks(args.log_path)
    if not events:
        print(f"No events with a generated playbook found in {args.log_path}.")
        return

    try:
        event = events[args.index]
    except IndexError:
        print(f"Index {args.index} out of range — only {len(events)} playbook events available.")
        return

    threat_category = event["playbook"].get("_metadata", {}).get("threat_category", "Incident")
    body = render_event_html(event)
    doc = build_html(body, f"Incident Report — {threat_category}")

    with open(args.output, "w", encoding="utf-8") as f:
        f.write(doc)

    print(f"Wrote HTML report to: {args.output}")
    print("Double-click it (or drag into a browser tab) to view.")


if __name__ == "__main__":
    main()

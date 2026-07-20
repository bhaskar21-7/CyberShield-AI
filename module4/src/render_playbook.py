"""
render_playbook.py
--------------------
Turns a raw JSON event/playbook from event_log.jsonl into a clean,
readable Markdown incident report — the thing you actually show a
judge or a non-technical reader, instead of a terminal full of braces.

Raw JSON is correct and complete, but nobody outside the dev team can
tell at a glance whether it's a real finding or "just something typed
out." A formatted report with headers, tables, and clearly-labeled
sections (which parts are LLM-written vs. template-derived) reads as
what it actually is: a structured SOC deliverable.

Usage:
    python render_playbook.py                  # render the most recent event WITH a playbook
    python render_playbook.py --all             # render every event that has a playbook
    python render_playbook.py --index -3         # render a specific event by index into the
                                                   # filtered (playbook-only) list, e.g. -3 for
                                                   # the 3rd-most-recent playbook event
    python render_playbook.py --output report.md # write to a specific file instead of the default

Output is a single .md file — open it in VS Code (Ctrl+Shift+V for
preview), a browser via any markdown viewer, or convert it to PDF with
a tool like pandoc if you want a printable handout for judges.
"""

import argparse
import json
import os

EVENT_LOG_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "event_log.jsonl")
DEFAULT_OUTPUT = os.path.join(os.path.dirname(__file__), "..", "data", "incident_report.md")


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


def _fmt_pct(x) -> str:
    try:
        return f"{float(x) * 100:.1f}%"
    except (TypeError, ValueError):
        return str(x)


def _md_table(headers: list, rows: list) -> str:
    lines = ["| " + " | ".join(headers) + " |", "|" + "|".join(["---"] * len(headers)) + "|"]
    for row in rows:
        lines.append("| " + " | ".join(str(c) for c in row) + " |")
    return "\n".join(lines)


def render_event(event: dict) -> str:
    pb = event["playbook"]
    meta = pb.get("_metadata", {})
    out = []

    out.append(f"# Incident Report — {meta.get('threat_category', 'Unclassified')}")
    out.append("")
    out.append(f"**Generated:** {event.get('stored_at', 'unknown')}  ")
    out.append(f"**Source → Destination:** `{event.get('source_ip', '?')}` → `{event.get('destination_ip', '?')}`  ")
    out.append(f"**Channel / Protocol:** {event.get('channel', '?')} / {event.get('protocol', '?')}  ")
    out.append(f"**Risk Level:** **{event.get('risk_level', '?')}** ({_fmt_pct(event.get('final_risk_probability'))})  ")
    conf = pb.get("confidence_score", {})
    if conf:
        out.append(f"**Confidence:** {conf.get('confidence_percent', '?')}% — {conf.get('basis', '')}  ")
    out.append("")
    out.append("> ⚠️ **How to read this report:** the *Threat Summary*, *Root Cause*, and "
                "*Executive Summary* sections below are written by an LLM (Google Gemini), "
                "grounded in the real detection data. Every other section — evidence, commands, "
                "detection rules, MITRE mapping, CVE candidates — is generated from a fixed, "
                "deterministic template, not the LLM. This split is intentional: prose benefits "
                "from an LLM, detection rules and remediation commands do not. See the section "
                "headers below for which is which.")
    out.append("")
    out.append("---")
    out.append("")

    out.append("## 🧠 Threat Summary  *(LLM-generated, grounded in detection data)*")
    out.append("")
    out.append(pb.get("threat_summary", "_not generated_"))
    out.append("")

    out.append("## 🔍 Root Cause Analysis  *(LLM-generated, grounded in detection data)*")
    out.append("")
    out.append(pb.get("root_cause", "_not generated_"))
    out.append("")

    out.append("## 📋 Executive Summary  *(LLM-generated, for non-technical stakeholders)*")
    out.append("")
    out.append(pb.get("executive_summary", "_not generated_"))
    out.append("")
    out.append("---")
    out.append("")

    evidence = pb.get("evidence", {})
    top_features = evidence.get("top_features", [])
    contributions = evidence.get("feature_contributions", {})
    if top_features:
        out.append("## 📊 Evidence  *(template-derived from real model output — SHAP feature contributions)*")
        out.append("")
        rows = [[f, f"{contributions.get(f, 0):+.3f}"] for f in top_features]
        out.append(_md_table(["Feature", "SHAP Contribution"], rows))
        out.append("")
        if evidence.get("raw_content_sample"):
            out.append("**Raw event content sample:**")
            out.append("```")
            out.append(str(evidence["raw_content_sample"]))
            out.append("```")
            out.append("")

    mitre = pb.get("mitre_attack_mapping", [])
    if mitre:
        out.append("## 🎯 MITRE ATT&CK Mapping  *(template-derived, curated knowledge base)*")
        out.append("")
        rows = [[m.get("tactic", ""), m.get("technique_id", ""), m.get("technique_name", "")] for m in mitre]
        out.append(_md_table(["Tactic", "Technique ID", "Technique Name"], rows))
        out.append("")

    actions = pb.get("immediate_actions", [])
    if actions:
        out.append("## ⚡ Immediate Actions  *(template-derived)*")
        out.append("")
        for a in actions:
            out.append(f"- [ ] {a}")
        out.append("")

    for key, label, lang in [
        ("linux_commands", "🐧 Linux Commands", "bash"),
        ("windows_commands", "🪟 Windows Commands", "powershell"),
        ("firewall_rules", "🔥 Firewall Rules", "bash"),
    ]:
        cmds = pb.get(key, [])
        if cmds:
            out.append(f"## {label}  *(template-derived)*")
            out.append("")
            out.append(f"```{lang}")
            out.append("\n".join(cmds))
            out.append("```")
            out.append("")

    for key, label, lang in [
        ("yara_rule", "🛡️ YARA Rule", "yara"),
        ("snort_rule", "🛡️ Snort Rule", "text"),
        ("sigma_rule", "🛡️ Sigma Rule", "yaml"),
    ]:
        rule = pb.get(key)
        if rule:
            out.append(f"## {label}  *(template-derived — compiled/parsed for validity before shipping)*")
            out.append("")
            out.append(f"```{lang}")
            out.append(rule)
            out.append("```")
            out.append("")

    cve = pb.get("cve_suggestions", {})
    candidates = cve.get("candidates", [])
    if candidates:
        out.append("## 🗂️ CVE Candidates  *(template-derived — illustrative only, see disclaimer)*")
        out.append("")
        out.append(f"> {cve.get('disclaimer', '')}")
        out.append("")
        rows = [[c.get("cve_id", ""), c.get("name", ""), c.get("note", "")] for c in candidates]
        out.append(_md_table(["CVE ID", "Name", "Relevance Note"], rows))
        out.append("")

    recovery = pb.get("recovery_steps", [])
    if recovery:
        out.append("## 🔧 Recovery Steps  *(template-derived)*")
        out.append("")
        for r in recovery:
            out.append(f"- {r}")
        out.append("")

    checklist = pb.get("post_incident_checklist", [])
    if checklist:
        out.append("## ✅ Post-Incident Checklist  *(template-derived)*")
        out.append("")
        for c in checklist:
            out.append(c if c.strip().startswith("[") else f"- {c}")
        out.append("")

    out.append("---")
    out.append(f"*Generated by CyberShield-AI Module 4 — `generate_response_playbook()`. "
                f"LLM sections: {', '.join(meta.get('llm_sections', []))}. "
                f"Template sections: {', '.join(meta.get('template_sections', []))}.*")

    return "\n".join(out)


def main():
    parser = argparse.ArgumentParser(description="Render a JSON playbook as a readable Markdown incident report.")
    parser.add_argument("--all", action="store_true", help="Render every event that has a playbook, not just the latest.")
    parser.add_argument("--index", type=int, default=-1, help="Index into the playbook-only event list (default -1 = most recent).")
    parser.add_argument("--output", type=str, default=DEFAULT_OUTPUT, help="Output .md file path.")
    parser.add_argument("--log-path", type=str, default=EVENT_LOG_PATH, help="Path to event_log.jsonl.")
    args = parser.parse_args()

    events = load_events_with_playbooks(args.log_path)
    if not events:
        print(f"No events with a generated playbook found in {args.log_path}. "
              f"Run main.py with a risk>70 event first (mock or real).")
        return

    if args.all:
        sections = [render_event(e) for e in events]
        content = "\n\n<div style=\"page-break-after: always;\"></div>\n\n".join(sections)
    else:
        try:
            event = events[args.index]
        except IndexError:
            print(f"Index {args.index} out of range — only {len(events)} playbook events available.")
            return
        content = render_event(event)

    with open(args.output, "w", encoding="utf-8") as f:
        f.write(content)

    print(f"Wrote {'all ' + str(len(events)) + ' ' if args.all else '1 '}report(s) to: {args.output}")
    print("Open it in VS Code (Ctrl+Shift+V for preview) or any Markdown viewer.")


if __name__ == "__main__":
    main()

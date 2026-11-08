import csv
import io
import json
import os
import re
from datetime import datetime, timezone

import pandas as pd
import streamlit as st

from trace_parser import parse_text, sha, verify_chain
from rules import analyze, risk_summary

st.set_page_config(page_title="AgentTrace | AI Agent Forensics", page_icon=None,
                   layout="wide", initial_sidebar_state="expanded")

st.markdown("""
<style>
    .block-container {padding-top: 1.6rem; padding-bottom: 2rem;}
    [data-testid="stMetric"] {background: rgba(128,128,128,.08); padding: 14px 16px; border-radius: 12px;}
    .hero {padding: 1.1rem 1.3rem; border: 1px solid rgba(128,128,128,.25); border-radius: 16px; margin-bottom: 1rem;}
    .muted {opacity: .72; font-size: .9rem;}

    .risk-badge {
        display: inline-block;
        padding: 5px 12px;
        border-radius: 8px;
        font-size: 13px;
        font-weight: 700;
        margin-top: 5px;
    }
    .risk-low {
        background-color: #dcfce7;
        color: #166534;
    }
    .risk-medium {
        background-color: #fef3c7;
        color: #92400e;
    }
    .risk-high {
        background-color: #ffedd5;
        color: #c2410c;
    }
    .risk-critical {
        background-color: #7f1d1d;
        color: #ffffff;
    }
</style>
""", unsafe_allow_html=True)

st.markdown(
    """
    <div class="hero">
        <h1>AgentTrace</h1>
        <div class="muted">AI Agent Forensics and Audit Platform</div>
        <div class="muted">Inspect prompts, tool calls, outputs, and suspicious activity.</div>
    </div>
    """,
    unsafe_allow_html=True,
)
st.caption("Rule-based prototype. Findings are investigation leads, not proof of malicious activity.")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SAMPLES_DIR = os.path.join(BASE_DIR, "samples")

with st.sidebar:
    st.header("Session source")
    choice = st.radio("Choose input", ["Upload JSONL", "Suspicious demo", "Benign demo"])
    uploaded = st.file_uploader("Select a JSONL file", type=["jsonl", "txt"]) if choice == "Upload JSONL" else None
    st.warning("Use sanitized logs. The app masks common secrets in the interface and exports, but review data before sharing.")
    st.divider()
    st.caption("Supported input: one JSON object per line (JSONL).")

text, source_name = "", ""
if choice == "Upload JSONL":
    if uploaded:
        text = uploaded.getvalue().decode("utf-8-sig", errors="replace")
        source_name = uploaded.name
else:
    source_name = "suspicious.jsonl" if choice == "Suspicious demo" else "benign.jsonl"
    sample_path = os.path.join(SAMPLES_DIR, source_name)
    if os.path.isfile(sample_path):
        with open(sample_path, encoding="utf-8") as f:
            text = f.read()

if not text.strip():
    st.info("Upload a JSONL file or choose one of the demo sessions in the sidebar.")
    st.stop()

events, errors, session_hash = parse_text(text)
analyze(events)
findings = [(event, flag) for event in events for flag in event["flags"]]
risk_score, risk_level = risk_summary(events)

def redact(value):
    """Mask common credential patterns before display/export."""
    value = str(value)
    patterns = [
        (r'(?i)(password|passwd|secret|api[_-]?key|token)(["\'\s:=]+)([^,\s"\']+)', r'\1\2[REDACTED]'),
        (r'\bAKIA[0-9A-Z]{16}\b', '[REDACTED_AWS_KEY]'),
        (r'\bgh[pousr]_[A-Za-z0-9]{20,}\b', '[REDACTED_GITHUB_TOKEN]'),
        (r'-----BEGIN (?:RSA |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |OPENSSH )?PRIVATE KEY-----', '[REDACTED_PRIVATE_KEY]'),
    ]
    for pattern, replacement in patterns:
        value = re.sub(pattern, replacement, value)
    return value

severity_counts = {s: sum(1 for _, f in findings if f["severity"] == s) for s in ("critical", "high", "medium", "low")}
risk_class = re.sub(r"[^a-z]", "", str(risk_level).lower())

m1, m2, m3, m4 = st.columns(4)
m1.metric("Events", len(events))
m2.metric("Findings", len(findings))
m3.metric("Risk score", f"{risk_score}/100")
m3.markdown(
    f'<span class="risk-badge risk-{risk_class}">{str(risk_level).upper()}</span>',
    unsafe_allow_html=True
)
m4.metric("Invalid lines", len(errors))

left, right = st.columns([3, 2])
with left:
    st.markdown("#### Session integrity")
    st.code(session_hash, language=None)
    trusted_hash = st.text_input(
        "Previously saved trusted session hash (optional)",
        placeholder="Paste a hash saved during an earlier analysis"
    )
    if trusted_hash.strip():
        verification = verify_chain(events, trusted_hash.strip())
        if verification["valid"]:
            st.success(f"Integrity check matched the trusted hash · {verification['events_checked']} events checked")
        else:
            st.error("Integrity check failed: current session does not match the trusted hash.")
    else:
        st.info("A new hash was calculated. To verify later integrity, save it separately and paste it here during a future analysis.")
with right:
    st.markdown("#### Severity overview")
    st.write(f" Critical: **{severity_counts['critical']}**")
    st.write(f" High: **{severity_counts['high']}**")
    st.write(f" Medium: **{severity_counts['medium']}**")
    st.write(f" Low: **{severity_counts['low']}**")

if errors:
    with st.expander(f"Parsing warnings ({len(errors)})"):
        st.dataframe(pd.DataFrame(errors), hide_index=True, use_container_width=True)

tab_timeline, tab_findings, tab_correlations, tab_export = st.tabs(
    ["Timeline", "Findings", "Tool Correlations", "Export"])

with tab_timeline:
    st.subheader("Event timeline")
    col1, col2, col3 = st.columns([2, 2, 1])
    kinds = sorted({e["kind"] for e in events})
    selected_kinds = col1.multiselect("Event types", kinds, default=kinds)
    severity_filter = col2.multiselect("Severity", ["critical", "high", "medium", "low"])
    flagged_only = col3.checkbox("Flagged only")
    query = st.text_input("Search in commands, summaries and outputs", placeholder="e.g. .env, curl, pytest")
    filtered = []
    for e in events:
        event_severities = {f["severity"] for f in e["flags"]}
        searchable = f"{e['summary']} {e['command']} {e['detail']} {e['orig_type']}".lower()
        if e["kind"] not in selected_kinds:
            continue
        if flagged_only and not e["flags"]:
            continue
        if severity_filter and not event_severities.intersection(severity_filter):
            continue
        if query and query.lower() not in searchable:
            continue
        filtered.append(e)

    table_rows = [{
        "Event": e["idx"], "Line": e["line_no"], "Type": e["kind"],
        "Tool": e["tool_name"], "Call ID": e["call_id"],
        "Summary": redact(e["summary"])[:120],
        "Severity": ", ".join(sorted({f["severity"].upper() for f in e["flags"]})) or "—",
        "SHA-256": e["raw_sha256"][:12]
    } for e in filtered]
    st.dataframe(pd.DataFrame(table_rows), hide_index=True, use_container_width=True)
    if filtered:
        selected_idx = st.selectbox("Inspect event", [e["idx"] for e in filtered],
                                    format_func=lambda n: f"Event #{n} · {next(x['kind'] for x in filtered if x['idx']==n)}")
        ev = next(e for e in filtered if e["idx"] == selected_idx)
        st.markdown(f"**Event #{ev['idx']}** · source line {ev['line_no']} · `{ev['orig_type']}`")
        if ev["call_id"]:
            st.caption(f"Call ID: {ev['call_id']} · correlated event: {ev['correlation'] or 'not found'}")
        if ev["flags"]:
            for flag in ev["flags"]:
                st.warning(f"{flag['severity'].upper()} · {flag['rule']} · {flag['title']} — {flag['why']}")
        st.code(redact(ev["raw"]), language="json")
    else:
        st.info("No events match these filters.")

with tab_findings:
    st.subheader("Detection findings")
    if not findings:
        st.success("No detection rule matched this session.")
    else:
        rows = [{"Severity": f["severity"].upper(), "Rule": f["rule"], "Event": e["idx"],
                 "Title": f["title"], "Confidence": f["confidence"], "Explanation": f["why"]}
                for e, f in findings]
        st.dataframe(pd.DataFrame(rows), hide_index=True, use_container_width=True)
        st.caption("Confidence describes the strength of the pattern match, not the probability that an attack occurred.")

with tab_correlations:
    st.subheader("Tool call ↔ output correlation")
    pairs = []
    for e in events:
        if e["kind"] == "tool_call":
            output = next((x for x in events if x["idx"] == e["correlation"]), None)
            pairs.append({"Call event": e["idx"], "Call ID": e["call_id"] or "—",
                          "Tool": e["tool_name"] or "—",
                          "Command": redact(e["command"] or e["summary"]),
                          "Output event": output["idx"] if output else "Unmatched",
                          "Output preview": redact(output["detail"][:180]) if output else "No matching output"})
    if pairs:
        st.dataframe(pd.DataFrame(pairs), hide_index=True, use_container_width=True)
    else:
        st.info("No tool calls were found in this session.")
    unmatched_outputs = [e for e in events if e["kind"] == "tool_output" and not e["correlation"]]
    if unmatched_outputs:
        st.warning(f"{len(unmatched_outputs)} tool output event(s) have no matching call_id.")

with tab_export:
    st.subheader("Evidence and report export")
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    md_lines = [
        f"# AgentTrace report: {source_name}", "",
        f"- Generated (UTC): {now}", f"- Events: {len(events)}",
        f"- Findings: {len(findings)}", f"- Risk score: {risk_score}/100 ({risk_level})",
        f"- SHA-256 chain: `{session_hash}`",
        "- Integrity note: this verifies consistency against the supplied session hash; store that hash separately in a trusted location for later tamper detection.",
        "", "## Findings"
    ]
    if findings:
        for e, f in findings:
            md_lines.append(f"- **{f['severity'].upper()} {f['rule']}** · event #{e['idx']}: {f['title']} — {f['why']}")
    else:
        md_lines.append("- No rules matched.")
    md_lines += ["", "## Timeline"]
    for e in events:
        md_lines.append(f"{e['idx']}. [{e['kind']}] {redact(e['summary'])} · SHA-256 `{e['raw_sha256'][:16]}`")
    st.download_button("Download Markdown Report", "\n".join(md_lines),
                       file_name="agenttrace_report.md", mime="text/markdown")

    include_raw = st.checkbox("Include raw events in JSON evidence (secrets are masked)", value=False)
    export_events = []
    for e in events:
        item = {k: e[k] for k in ("idx", "line_no", "ts", "kind", "orig_type", "role",
                                  "tool_name", "call_id", "command", "summary",
                                  "raw_sha256", "chain_hash", "correlation")}
        item["command"] = redact(item["command"])
        item["summary"] = redact(item["summary"])
        if include_raw:
            item["raw"] = redact(e["raw"])
        export_events.append(item)
    package = {
        "tool": "AgentTrace MVP", "generated_at_utc": now, "source_file": source_name,
        "hash_algorithm": "SHA-256", "session_hash": session_hash,
        "trusted_hash_comparison": ("match" if trusted_hash.strip() and verify_chain(events, trusted_hash.strip())["valid"] else "mismatch" if trusted_hash.strip() else "not_performed"),
        "integrity_note": "For later tamper detection, retain this session hash separately in a trusted location.",
        "risk_score": risk_score, "risk_level": risk_level,
        "parse_errors": errors,
        "findings": [{"event": e["idx"], **f} for e, f in findings],
        "events": export_events
    }
    st.download_button("Download JSON Evidence Package", json.dumps(package, ensure_ascii=False, indent=2),
                       file_name="agenttrace_evidence.json", mime="application/json")

    st.divider()
    st.subheader("Tester feedback")
    st.caption("Use anonymous tester codes. Feedback is stored locally in feedback.csv beside app.py.")
    with st.form("feedback_form"):
        tester = st.text_input("Tester code (e.g. T01)")
        stage = st.selectbox("Test stage", ["alpha", "beta"])
        found = st.radio("Did you find the suspicious action?", ["yes", "partly", "no"], horizontal=True)
        seconds = st.number_input("Time to find it (seconds)", min_value=0, max_value=36000, value=0)
        clarity = st.slider("Timeline clarity", 1, 5, 4)
        would_use = st.slider("Would you use this tool?", 1, 5, 3)
        comment = st.text_area("What should be improved?")
        submitted = st.form_submit_button("Save feedback", type="primary")
    if submitted:
        if not tester.strip():
            st.error("Enter an anonymous tester code.")
        else:
            feedback_path = os.path.join(BASE_DIR, "feedback.csv")
            exists = os.path.exists(feedback_path)
            with open(feedback_path, "a", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                if not exists:
                    writer.writerow(["time_utc", "tester", "stage", "source", "found", "seconds", "clarity", "would_use", "comment"])
                writer.writerow([now, tester.strip(), stage, source_name, found, int(seconds), clarity, would_use, comment])
            st.success("Feedback saved.")

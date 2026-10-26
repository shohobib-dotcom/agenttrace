import csv
import json
import os
from datetime import datetime, timezone

import pandas as pd
import streamlit as st

from trace_parser import parse_text, sha
from rules import analyze

st.set_page_config(page_title="AgentTrace MVP", layout="wide")
st.title("AgentTrace: agent session timeline")
st.caption("Each item shows its raw log line and SHA-256. Flags are hints, not verdicts: verify them manually.")

st.sidebar.warning("Do not upload logs that contain real secrets, account IDs or personal data. "
                   "Use samples or sanitized logs. Uploaded files are processed in memory only.")
choice = st.sidebar.radio("Log", ["Upload", "Sample: suspicious", "Sample: benign"])
text, name = None, ""
base_dir = os.path.dirname(os.path.abspath(__file__))

if choice == "Upload":
    up = st.sidebar.file_uploader("JSONL log", type=["jsonl", "txt", "json"])
    if up:
        text, name = up.getvalue().decode("utf-8", errors="replace"), up.name
elif choice == "Sample: suspicious":
    # Используем os.path.join для правильного пути
    file_path = os.path.join(base_dir, "samples", "suspicious.jsonl")
    text, name = open(file_path, encoding="utf-8").read(), "suspicious.jsonl"
else:
    file_path = os.path.join(base_dir, "samples", "benign.jsonl")
    text, name = open(file_path, encoding="utf-8").read(), "benign.jsonl"

if not text:
    st.info("Upload a log or choose a sample in the sidebar.")
    st.stop()

events, errors, session_hash = parse_text(text)
analyze(events)
findings = [(e, f) for e in events for f in e["flags"]]

c1, c2, c3 = st.columns(3)
c1.metric("Events", len(events))
c2.metric("Findings", len(findings))
c3.metric("Unparsable lines", len(errors))
st.code("session hash (SHA-256 chain): " + session_hash)
st.caption("Demonstration integrity mechanism. A hash alone does not prove the log was not altered: "
           "the session hash must be stored separately and trusted (for example, signed) "
           "and compared later with the 'verify' step.")

tab1, tab2, tab3 = st.tabs(["Timeline", "Findings", "Export and feedback"])

with tab1:
    kinds = sorted({e["kind"] for e in events})
    f1, f2 = st.columns([3, 1])
    chosen = f1.multiselect("Event types", kinds, default=kinds)
    only = f2.checkbox("Only flagged events")

    rows = [{"#": e["idx"], "line": e["line_no"], "time": e["ts"], "type": e["kind"],
             "original type": e["orig_type"], "summary": e["summary"],
             "flags": ", ".join(f["rule"] for f in e["flags"]),
             "sha256": e["raw_sha256"][:12]}
            for e in events if e["kind"] in chosen and (e["flags"] or not only)]

    st.caption("Click a row to open its raw event.")
    table = st.dataframe(pd.DataFrame(rows), hide_index=True,
                         on_select="rerun", selection_mode="single-row")
    picked = table.selection.rows
    default_n = rows[picked[0]]["#"] if picked and picked[0] < len(rows) else 1

    st.subheader("Source event")
    n = st.number_input("Event number (or click a row above)", min_value=1,
                        max_value=max(1, len(events)), value=int(default_n), step=1)
    ev = next((x for x in events if x["idx"] == n), None)
    if ev:
        st.write(f"Event #{ev['idx']}, file line {ev['line_no']}, original type: {ev['orig_type']}")
        st.write("Raw SHA-256: " + ev["raw_sha256"])
        st.write("Chain hash: " + ev["chain_hash"])
        for f in ev["flags"]:
            st.warning(f"{f['severity'].upper()} {f['rule']} (confidence: {f['confidence']}): "
                       f"{f['title']}. {f['why']}")
        st.code(ev["raw"], language="json")

with tab2:
    if not findings:
        st.success("No rule matched.")
    else:
        df = pd.DataFrame([{"severity": f["severity"], "confidence": f["confidence"], "rule": f["rule"],
                            "event": e["idx"], "line": e["line_no"], "title": f["title"], "why": f["why"]}
                           for e, f in findings])
        st.dataframe(df, hide_index=True)

with tab3:
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    md = (f"# AgentTrace report: {name}\n\n"
          f"Generated (UTC): {now}\n\nHash algorithm: SHA-256\n\n"
          f"Session hash: `{session_hash}`\n\n"
          "> Demonstration integrity mechanism, not proof that the log is unaltered. "
          "Flags are hints: verify manually.\n\n## Findings\n")
    for e, f in findings:
        md += (f"- {f['severity']} {f['rule']} (confidence {f['confidence']}) event #{e['idx']} "
               f"(line {e['line_no']}): {f['title']} - {f['why']}\n")
    md += "\n## Timeline\n"
    for e in events:
        md += f"{e['idx']}. [{e['kind']}] {e['summary']} (sha256 {e['raw_sha256'][:12]})\n"
    st.download_button("Download Markdown report", md, file_name="agenttrace_report.md")

    package = {
        "tool": "AgentTrace MVP (demonstration)",
        "generated_at_utc": now,
        "source_file": name,
        "hash_algorithm": "SHA-256",
        "chain_method": "chain_i = SHA256(chain_(i-1) + SHA256(raw_line_i)); chain_0 = 64 zeros",
        "file_sha256": sha(text),
        "session_hash": session_hash,
        "integrity_note": "Demonstration mechanism only. Store the session hash separately and sign it "
                          "to make later alteration detectable.",
        "unparsable_lines": errors,
        "findings": [{"event": e["idx"], "line": e["line_no"], **f} for e, f in findings],
        "events": [{k: e[k] for k in ("idx", "line_no", "ts", "kind", "orig_type", "raw",
                                      "raw_sha256", "chain_hash")} for e in events],
    }
    st.download_button("Download JSON evidence package (with raw events and hashes)",
                       json.dumps(package, ensure_ascii=False, indent=2),
                       file_name="agenttrace_evidence.json")

    st.subheader("Tester feedback")
    st.caption("Feedback is saved locally to feedback.csv on this computer. Use tester codes, not real names.")
    with st.form("fb"):
        who = st.text_input("Tester code (A1, B1...)")
        stage = st.selectbox("Stage", ["alpha", "beta"])
        found = st.radio("Found the suspicious action?", ["yes", "partly", "no"])
        secs = st.number_input("Seconds to find it", min_value=0, value=0)
        opened = st.radio("Opened the raw line?", ["yes", "no"])
        clarity = st.slider("Timeline clarity (1-5)", 1, 5, 4)
        use = st.slider("Would you use it? (1-5)", 1, 5, 3)
        comment = st.text_area("What was confusing or missing?")
        ok = st.form_submit_button("Save")
    if ok:
        new = not os.path.exists("feedback.csv")
        with open("feedback.csv", "a", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            if new:
                w.writerow(["time", "tester", "stage", "log", "found", "seconds",
                            "opened_raw", "clarity", "would_use", "comment"])
            w.writerow([datetime.now().isoformat(timespec="seconds"), who, stage, name,
                        found, secs, opened, clarity, use, comment])
        st.success("Saved to feedback.csv")

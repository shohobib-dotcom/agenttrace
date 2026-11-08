"""Transparent, explainable heuristic detections. Findings are not verdicts."""
import re

RULES = [
    ("R01", "high", "Sensitive file access",
     r"(\.env\b|id_rsa|\.ssh/|\.aws/credentials|/etc/shadow|\.pem\b|credentials\.json)", "tool_call"),
    ("R02", "medium", "Outbound network command",
     r"\b(curl|wget|nc|ncat|scp|Invoke-WebRequest|iwr|Invoke-RestMethod)\b.*(https?://|\d{1,3}(?:\.\d{1,3}){3})", "tool_call"),
    ("R03", "high", "Possible local data upload",
     r"\b(curl|wget)\b.*(-d\s+@|--data(?:-binary)?\s+@|-F\s+\S*=@)", "tool_call"),
    ("R04", "high", "Destructive command",
     r"(rm\s+-rf|git\s+push\s+--force|chmod\s+777|git\s+reset\s+--hard|Remove-Item\s+.*-Recurse|format\s+[a-z]:)", "tool_call"),
    ("R05", "high", "Possible secret in tool output",
     r"(AKIA[0-9A-Z]{16}|BEGIN (?:RSA |OPENSSH )?PRIVATE KEY|gh[pousr]_[A-Za-z0-9]{20,}|(?:password|api[_-]?key|secret)\s*[:=]\s*\S+)", "tool_output"),
    ("R06", "medium", "Possible prompt injection in retrieved content",
     r"(ignore (?:all )?previous instructions|disregard (?:all )?prior instructions|reveal (?:the )?system prompt)", "tool_output"),
    ("R08", "high", "Suspicious PowerShell execution",
     r"\b(powershell|pwsh)\b.*(-enc(?:odedcommand)?\b|frombase64string|downloadstring|iex\s*\()", "tool_call"),
    ("R09", "medium", "Execution of a downloaded or temporary binary",
     r"(?:/tmp/|\\temp\\|%temp%|Downloads[/\\])[^ \n]+\.(?:exe|dll|sh|bin)\b", "tool_call"),
    ("R10", "high", "Permission or system configuration change",
     r"(?:\bchmod\b|\bchown\b|\breg\s+add\b|\bsc\s+(?:create|config)\b|\bSet-ExecutionPolicy\b)", "tool_call"),
    ("R11", "high", "Encoded command or payload",
     r"(?:base64\s+-d|frombase64string|(?:-enc(?:odedcommand)?)\s+[A-Za-z0-9+/]{20,}={0,2})", "tool_call"),
    ("R12", "medium", "Repeated sensitive-file access",
     r"(\.env\b|id_rsa|\.aws/credentials|/etc/shadow)", "tool_call"),
]
SEVERITY_WEIGHT = {"critical": 10, "high": 7, "medium": 4, "low": 1}

def analyze(events):
    for ev in events:
        ev["flags"] = []
        text = ev.get("command") or ev.get("detail", "")
        for rid, severity, title, pattern, kind in RULES:
            if ev["kind"] != kind:
                continue
            match = re.search(pattern, text, re.I | re.S)
            if match:
                confidence = "medium"
                # A command that only prints a suspicious-looking string is weaker evidence.
                if kind == "tool_call" and re.match(r"^\s*(echo|printf|Write-Output|Write-Host)\b", text, re.I):
                    confidence = "low"
                ev["flags"].append({
                    "rule": rid, "severity": severity, "title": title,
                    "confidence": confidence,
                    "why": f"Matched pattern: {match.group(0)[:90]}. Review the full event and context."
                })

    # R07: a sensitive read followed shortly by a network/upload command.
    for a in events:
        if a["kind"] != "tool_call" or not any(f["rule"] == "R01" for f in a["flags"]):
            continue
        for b in events:
            distance = b["idx"] - a["idx"]
            if 0 < distance <= 8 and b["kind"] == "tool_call":
                rules = {f["rule"] for f in b["flags"]}
                if rules.intersection({"R02", "R03"}):
                    if not any(f["rule"] == "R07" for f in b["flags"]):
                        b["flags"].append({
                            "rule": "R07", "severity": "critical",
                            "title": "Possible exfiltration sequence",
                            "confidence": "medium",
                            "why": f"Network/upload activity at event #{b['idx']} follows sensitive-file access at event #{a['idx']}."
                        })
                    break

    # R12 is contextual: flag repeated sensitive paths after the first occurrence.
    seen = set()
    for ev in events:
        if ev["kind"] != "tool_call":
            continue
        match = re.search(r"(\.env\b|id_rsa|\.aws/credentials|/etc/shadow)", ev.get("command", ""), re.I)
        if match:
            key = match.group(0).lower()
            if key in seen and not any(f["rule"] == "R12" for f in ev["flags"]):
                ev["flags"].append({
                    "rule": "R12", "severity": "medium",
                    "title": "Repeated sensitive-file access",
                    "confidence": "medium",
                    "why": f"The sensitive path pattern {key} appears more than once in this session."
                })
            seen.add(key)
    return events

def risk_summary(events):
    weights = []
    for ev in events:
        for flag in ev["flags"]:
            weights.append(SEVERITY_WEIGHT.get(flag["severity"], 1))
    score = min(100, sum(weights) * 3)
    level = "Critical" if score >= 70 else "High" if score >= 40 else "Medium" if score >= 15 else "Low"
    return score, level

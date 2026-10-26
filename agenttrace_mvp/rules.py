import re

RULES = [
    ("R01", "high", "Sensitive file access",
     r"(\.env\b|id_rsa|\.ssh/|\.aws/credentials|/etc/shadow|\.pem\b)", "tool_call"),
    ("R02", "medium", "Outbound network command",
     r"\b(curl|wget|nc|scp|Invoke-WebRequest|iwr|Invoke-RestMethod)\b.*(https?://|\d+\.\d+\.\d+\.\d+)",
     "tool_call"),
    ("R03", "high", "Uploads local data",
     r"curl\b.*(-d\s+@|--data(-binary)?\s+@|-F\s+\S*=@)", "tool_call"),
    ("R04", "high", "Destructive command",
     r"(rm\s+-rf|git\s+push\s+--force|chmod\s+777|git\s+reset\s+--hard|Remove-Item\s+.*-Recurse)",
     "tool_call"),
    ("R05", "high", "Secret in output",
     r"(AKIA[0-9A-Z]{16}|BEGIN (RSA |OPENSSH )?PRIVATE KEY|ghp_[A-Za-z0-9]{20,})", "tool_output"),
    ("R06", "medium", "Possible prompt injection",
     r"ignore (all )?previous instructions", "tool_output"),
]

PRINT_ONLY = re.compile(r"^\s*(echo|printf|Write-Output|Write-Host)\b", re.I)


def analyze(events):
    for ev in events:
        ev["flags"] = []
        for rid, sev, title, pattern, kind in RULES:
            if ev["kind"] == kind:
                m = re.search(pattern, ev["detail"], re.I | re.S)
                if m:
                    low = kind == "tool_call" and PRINT_ONLY.match(ev["detail"])
                    ev["flags"].append({
                        "rule": rid, "severity": sev, "title": title,
                        "confidence": "low" if low else "medium",
                        "why": "Pattern matched - verify manually: " + m.group(0)[:60],
                    })

    # R07: чтение секрета, а вскоре сетевая команда = возможная утечка
    def has(ev, rules):
        return any(f["rule"] in rules and f["confidence"] != "low" for f in ev["flags"])

    for a in events:
        if has(a, ("R01",)):
            for b in events:
                if 0 < b["idx"] - a["idx"] <= 8 and has(b, ("R02", "R03")):
                    b["flags"].append({
                        "rule": "R07", "severity": "critical", "title": "Possible exfiltration chain",
                        "confidence": "medium",
                        "why": f"Pattern matched - verify manually: network command at #{b['idx']} follows sensitive access at #{a['idx']}",
                    })
                    break
    return events
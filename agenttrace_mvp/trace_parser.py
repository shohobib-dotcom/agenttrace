import json
import hashlib
import re


def sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def text_of(content): 
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(str(p.get("text", "")) for p in content if isinstance(p, dict))
    return ""


def command_of(args):
    if isinstance(args, str):
        try:
            args = json.loads(args)
        except ValueError:
            return args
    if not isinstance(args, dict):
        return ""
    cmd = args.get("command") or args.get("cmd") or ""
    if isinstance(cmd, list):
        if len(cmd) >= 3 and cmd[1] in ("-c", "-lc"):   # ["bash","-lc","cat .env"]
            return str(cmd[2])
        return " ".join(map(str, cmd))
    return str(cmd)


def command_from_js(src):
    src = str(src)
    m = re.search(r'"cmd"\s*:\s*"((?:[^"\\]|\\.)*)"', src)
    if m:
        try:
            return json.loads('"' + m.group(1) + '"')
        except ValueError:
            return m.group(1)
    return src

KIND_MAP = {
    "task_started": "lifecycle", "task_complete": "lifecycle", "item_completed": "lifecycle",
    "thread_settings_applied": "state", "turn_context": "state", "world_state": "state",
    "additional_tools": "state", "token_count": "usage", "token_usage_record": "usage",
    "reasoning": "reasoning",
}

def parse_text(text):
    events, errors = [], []
    chain = "0" * 64
    for line_no, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            errors.append(line_no) 
            continue
        if not isinstance(obj, dict):
            errors.append(line_no)
            continue

        p = obj.get("payload") if isinstance(obj.get("payload"), dict) else obj
        t = p.get("type") or obj.get("type", "")
        kind, detail, command = "other", "", ""

        if t == "session_meta":
            kind, detail = "session", "Session started"

        elif t == "message":
            role = p.get("role", "")
            detail = text_of(p.get("content"))
            if role == "user":
                kind = "user_prompt"
                if detail.lstrip().startswith("<environment_context>"):
                    kind = "context"
            elif role in ("developer", "system"):
                kind = "system_prompt"
            else:
                kind = "assistant_message"

        elif t in ("function_call", "local_shell_call", "custom_tool_call"):
            kind = "tool_call"
            if t == "custom_tool_call":
                command = command_from_js(p.get("input", ""))
            else:
                command = command_of(p.get("arguments", p.get("action", {})))
            detail = command

        elif t in ("function_call_output", "custom_tool_call_output"):
            kind = "tool_output"
            out = p.get("output", "")
            if isinstance(out, list):
                out = text_of(out)
            elif isinstance(out, dict):
                out = json.dumps(out, ensure_ascii=False)
            else:
                try:
                    j = json.loads(out)
                    if isinstance(j, dict) and "output" in j:
                        out = j["output"]
                except (ValueError, TypeError):
                    pass
            detail = str(out)
        if kind == "other":
            kind = KIND_MAP.get(t, "other")
        raw_hash = sha(line)
        chain = sha(chain + raw_hash)
        events.append({
            "idx": len(events) + 1,
            "line_no": line_no,
            "ts": str(obj.get("timestamp", "")),
            "kind": kind,
            "orig_type": t or obj.get("type", ""),
            "summary": (" ".join(detail.split())[:100]) or (t or "event"),
            "detail": detail,
            "raw": line,
            "raw_sha256": raw_hash,
            "chain_hash": chain,
            "flags": [],
        })
    return events, errors, chain
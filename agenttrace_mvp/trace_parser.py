"""JSONL parser and integrity helpers for AgentTrace."""
import hashlib
import json
from typing import Any

ZERO_HASH = "0" * 64

def sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()

def text_of(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for item in content:
            if isinstance(item, dict):
                value = item.get("text", item.get("content", ""))
                if isinstance(value, str):
                    parts.append(value)
                elif value:
                    parts.append(json.dumps(value, ensure_ascii=False))
            elif isinstance(item, str):
                parts.append(item)
        return "\n".join(parts)
    if isinstance(content, dict):
        return json.dumps(content, ensure_ascii=False)
    return ""

def _decode_jsonish(value: Any) -> Any:
    if isinstance(value, str):
        try:
            return json.loads(value)
        except (ValueError, TypeError):
            return value
    return value

def command_of(args: Any) -> str:
    args = _decode_jsonish(args)
    if isinstance(args, dict):
        cmd = args.get("command") or args.get("cmd") or args.get("script") or ""
        if isinstance(cmd, list):
            if len(cmd) >= 3 and str(cmd[1]) in ("-c", "-lc", "/c", "-Command"):
                return str(cmd[2])
            return " ".join(map(str, cmd))
        return str(cmd)
    return str(args) if args is not None else ""

def _payload(obj: dict) -> dict:
    payload = obj.get("payload")
    return payload if isinstance(payload, dict) else obj

def parse_text(text: str):
    events, errors = [], []
    chain = ZERO_HASH
    for line_no, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except (ValueError, TypeError):
            errors.append({"line": line_no, "error": "Invalid JSON"})
            continue
        if not isinstance(obj, dict):
            errors.append({"line": line_no, "error": "JSON value must be an object"})
            continue

        p = _payload(obj)
        event_type = str(p.get("type") or obj.get("type") or "")
        kind, detail, command, role = "other", "", "", ""
        call_id = p.get("call_id") or p.get("tool_call_id") or p.get("id")
        tool_name = p.get("name") or p.get("tool_name") or ""

        if event_type == "session_meta":
            kind, detail = "session", "Session started"
        elif event_type == "message":
            role = str(p.get("role", ""))
            detail = text_of(p.get("content"))
            kind = {"user": "user_prompt", "developer": "system_prompt",
                    "system": "system_prompt"}.get(role, "assistant_message")
            if role == "user" and detail.lstrip().startswith("<environment_context>"):
                kind = "context"
        elif event_type in ("function_call", "local_shell_call", "custom_tool_call",
                            "tool_call", "computer_call"):
            kind = "tool_call"
            if event_type == "custom_tool_call":
                detail = text_of(p.get("input", ""))
                command = detail
            else:
                command = command_of(p.get("arguments", p.get("action", p.get("input", {}))))
                detail = command or text_of(p.get("input", ""))
        elif event_type in ("function_call_output", "custom_tool_call_output",
                            "tool_output", "computer_call_output"):
            kind = "tool_output"
            output = p.get("output", p.get("content", ""))
            output = _decode_jsonish(output)
            if isinstance(output, dict) and "output" in output:
                output = output["output"]
            detail = text_of(output) if isinstance(output, (dict, list)) else str(output)
        elif event_type in ("reasoning", "token_count", "token_usage_record"):
            kind = "reasoning" if event_type == "reasoning" else "usage"
            detail = text_of(p.get("text", ""))

        raw_hash = sha(line)
        chain = sha(chain + raw_hash)
        event = {
            "idx": len(events) + 1, "line_no": line_no,
            "ts": str(obj.get("timestamp") or p.get("timestamp") or ""),
            "kind": kind, "orig_type": event_type, "role": role,
            "tool_name": str(tool_name), "call_id": str(call_id) if call_id is not None else "",
            "command": command, "detail": detail,
            "summary": " ".join((detail or event_type or "event").split())[:140],
            "raw": line, "raw_sha256": raw_hash, "chain_hash": chain,
            "flags": [], "correlation": None,
        }
        events.append(event)

    # Correlate calls and outputs using call_id; unmatched events remain visible.
    calls = {}
    for event in events:
        if event["kind"] == "tool_call" and event["call_id"]:
            calls[event["call_id"]] = event
        elif event["kind"] == "tool_output" and event["call_id"]:
            call = calls.get(event["call_id"])
            if call:
                event["correlation"] = call["idx"]
                call["correlation"] = event["idx"]
    return events, errors, chain

def calculate_chain(raw_lines):
    chain = ZERO_HASH
    for line in raw_lines:
        chain = sha(chain + sha(line))
    return chain

def verify_chain(events, expected_hash: str):
    actual = calculate_chain([e["raw"] for e in events])
    return {"valid": actual == expected_hash, "expected": expected_hash,
            "actual": actual, "events_checked": len(events)}

"""W3C Trace Context propagation and redacted OTLP JSON for incident runs."""
from __future__ import annotations

import os
import re
import time
from typing import Any

from fastapi import Request

def nonzero_hex(nbytes: int) -> str:
    while True:
        value = os.urandom(nbytes).hex()
        if int(value, 16) != 0:
            return value


def attr(key: str, value: Any) -> dict[str, Any]:
    if isinstance(value, bool):
        return {"key": key, "value": {"boolValue": value}}
    if isinstance(value, int):
        # OTLP JSON encodes int64 AnyValue values as decimal strings.
        return {"key": key, "value": {"intValue": str(value)}}
    return {"key": key, "value": {"stringValue": str(value)}}


def set_attr(span: dict[str, Any], key: str, value: Any) -> None:
    span["attributes"] = [item for item in span.get("attributes", []) if item.get("key") != key]
    span.setdefault("attributes", []).append(attr(key, value))


def make_span(
    state: dict[str, Any],
    name: str,
    kind: int,
    parent_span_id: str | None,
    attributes: list[dict[str, Any]] | None = None,
    start_ns: int | None = None,
    end_ns: int | None = None,
    links: list[dict[str, Any]] | None = None,
    status_code: int | None = None,
    status_message: str | None = None,
) -> dict[str, Any]:
    now = time.time_ns()
    existing_ids = {span["spanId"] for span in state.get("spans", [])}
    span_id = nonzero_hex(8)
    while span_id in existing_ids or span_id == parent_span_id:
        span_id = nonzero_hex(8)
    span: dict[str, Any] = {
        "traceId": state["traceId"],
        "spanId": span_id,
        "name": name,
        "kind": kind,
        "startTimeUnixNano": str(start_ns if start_ns is not None else now),
        "endTimeUnixNano": str(end_ns if end_ns is not None else now),
        "attributes": [
            attr("ga5.run.id", state["runId"]),
            attr("ga5.public.marker", state["publicMarker"]),
        ] + (attributes or []),
        "flags": state.get("traceFlags", 1),
    }
    if parent_span_id:
        span["parentSpanId"] = parent_span_id
    if state.get("tracestate"):
        span["traceState"] = state["tracestate"]
    if links is not None:
        span["links"] = links
    if status_code is not None:
        status: dict[str, Any] = {"code": status_code}
        if status_message:
            status["message"] = status_message
        span["status"] = status
    return span


def make_otlp(state: dict[str, Any]) -> dict[str, Any]:
    return {
        "resourceSpans": [
            {
                "resource": {
                    "attributes": [
                        attr("service.name", "observable-incident-agent"),
                        attr("service.version", "2"),
                    ]
                },
                "scopeSpans": [
                    {
                        "scope": {"name": "observable-incident-agent", "version": "2"},
                        "spans": state.get("spans", []),
                    }
                ],
            }
        ]
    }


def valid_tracestate(value: str | None) -> str | None:
    if value is None:
        return None
    if len(value) > 16447:
        return None
    members = [part.strip(" \t") for part in value.split(",")]
    if len(members) > 32:
        return None
    seen: set[str] = set()
    key_re = re.compile(r"(?:[a-z][_0-9a-z*/-]{0,255}|[a-z0-9][_0-9a-z*/-]{0,240}@[a-z][_0-9a-z*/-]{0,13})")
    for member in members:
        if not member:  # W3C allows empty list members and HTTP optional whitespace.
            continue
        key, separator, item_value = member.partition("=")
        if not separator or len(key) > 256 or not key_re.fullmatch(key):
            return None
        if key in seen or not 1 <= len(item_value) <= 256:
            return None
        if any(ord(ch) < 32 or ord(ch) > 126 or ch in ",=" for ch in item_value):
            return None
        seen.add(key)
    return value


def trace_context(request: Request) -> dict[str, Any]:
    parents = request.headers.getlist("traceparent")
    incoming = parents[0] if len(parents) == 1 else ""
    match = re.fullmatch(r"([0-9a-f]{2})-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})(.*)", incoming)
    if match:
        version, trace_id, parent_id, flags, extra = match.groups()
        valid_version = version != "ff" and ((version == "00" and not extra) or (version != "00" and (not extra or extra.startswith("-"))))
    else:
        valid_version = False
    if match and valid_version and int(trace_id, 16) and int(parent_id, 16):
        state_headers = request.headers.getlist("tracestate")
        state = valid_tracestate(",".join(state_headers)) if state_headers else None
        sampled = int(flags, 16) & 1
        return {
            "traceId": trace_id,
            "upstreamParentSpanId": parent_id,
            "traceFlags": sampled,
            "traceFlagsHex": f"{sampled:02x}",
            "tracestate": state,
        }
    return new_context()


def new_context() -> dict[str, Any]:
    return {
        "traceId": nonzero_hex(16),
        "upstreamParentSpanId": "",
        "traceFlags": 1,
        "traceFlagsHex": "01",
        "tracestate": None,
    }


def add_logical_action(state: dict[str, Any], tool_name: str, phase: str, action_id: str, call_id: str, approval_id: str | None = None) -> str:
    attributes = [
        attr("ga5.action.id", action_id),
        attr("gen_ai.tool.name", tool_name),
        attr("gen_ai.tool.call.id", call_id),
        attr("gen_ai.operation.name", "execute_tool"),
    ]
    if approval_id:
        attributes.append(attr("ga5.approval.id", approval_id))
    span = make_span(state, f"execute_tool {tool_name}", 1, state["agentSpanId"], attributes, status_code=0)
    state["spans"].append(span)
    state["actionSpanIds"][action_id] = span["spanId"]
    state["actionMeta"][action_id] = {
        "toolName": tool_name,
        "phase": phase,
        "callId": call_id,
        "spanId": span["spanId"],
        "completed": False,
    }
    return span["spanId"]


def add_client_attempt(
    state: dict[str, Any],
    tool_name: str,
    action_id: str,
    call_id: str,
    attempt: int,
) -> tuple[dict[str, Any], str]:
    span = make_span(
        state,
        f"POST tool/{tool_name}",
        3,
        state["actionSpanIds"][action_id],
        [
            attr("ga5.action.id", action_id),
            attr("ga5.attempt", attempt),
            attr("http.request.method", "POST"),
            attr("http.request.resend_count", attempt - 1),
            attr("gen_ai.tool.name", tool_name),
            attr("gen_ai.tool.call.id", call_id),
        ],
        status_code=0,
    )
    state["spans"].append(span)
    state["clientSpanIds"][f"{action_id}:{attempt}"] = span["spanId"]
    return span, span["spanId"]


def update_client_receipt(state: dict[str, Any], action_id: str, attempt: int, receipt_id: str, outcome: dict[str, Any]) -> None:
    span_id = state["clientSpanIds"].get(f"{action_id}:{attempt}")
    span = next((item for item in state["spans"] if item["spanId"] == span_id), None)
    if span is None:
        raise ValueError("missing client span for receipt")
    status_code = outcome.get("status")
    span["endTimeUnixNano"] = str(time.time_ns())
    error_type = None
    if status_code == 503:
        error_type = "503"
    elif status_code == 0:
        error_type = "timeout"
    elif status_code != 200:
        error_type = str(status_code)
    set_attr(span, "ga5.receipt.id", receipt_id)
    set_attr(span, "ga5.receipt.nonce", outcome.get("nonce", ""))
    if status_code != 0:
        set_attr(span, "http.response.status_code", status_code)
    if error_type:
        set_attr(span, "error.type", str(error_type))
        span["status"] = {"code": 2, "message": str(error_type)}
    else:
        span["attributes"] = [item for item in span.get("attributes", []) if item.get("key") != "error.type"]
        span["status"] = {"code": 1}


def end_action_span(state: dict[str, Any], action_id: str, status_code: int) -> None:
    meta = state["actionMeta"].get(action_id)
    if not meta or meta["completed"]:
        return
    span = next((item for item in state["spans"] if item["spanId"] == meta["spanId"]), None)
    if span:
        span["endTimeUnixNano"] = str(time.time_ns())
        span["status"] = {"code": 1 if status_code == 200 else 2}
    meta["completed"] = True


def add_join_span(state: dict[str, Any], diagnostic_action_ids: list[str]) -> None:
    if len(diagnostic_action_ids) <= 1:
        return
    links = [
        {
            "traceId": state["traceId"],
            "spanId": state["actionSpanIds"][action_id],
            "attributes": [],
            "flags": state.get("traceFlags", 1),
            **({"traceState": state["tracestate"]} if state.get("tracestate") else {}),
        }
        for action_id in diagnostic_action_ids
    ]
    span = make_span(state, "incident.join", 1, state["agentSpanId"], links=links, status_code=0)
    state["spans"].append(span)
    state["joinSpanId"] = span["spanId"]


def end_join_span(state: dict[str, Any], status_code: int) -> None:
    span_id = state.get("joinSpanId")
    if not span_id:
        return
    span = next((item for item in state["spans"] if item["spanId"] == span_id), None)
    if span:
        span["endTimeUnixNano"] = str(time.time_ns())
        span["status"] = {"code": 1 if status_code == 200 else 2}


def start_trace_state(
    run_id: str,
    agent_name: str,
    public_marker: str,
    context: dict[str, Any],
) -> dict[str, Any]:
    now = time.time_ns()
    base = {"traceId": context["traceId"], "runId": run_id, "publicMarker": public_marker,
            "traceFlags": context["traceFlags"], "tracestate": context["tracestate"]}
    server_span = make_span(
        base,
        "POST /v2/incidents",
        2,
        context["upstreamParentSpanId"],
        [
            attr("http.request.method", "POST"),
            attr("url.path", "/v2/incidents"),
        ],
        start_ns=now,
        status_code=0,
    )
    server_id = server_span["spanId"]

    agent_span = make_span(
        base,
        f"invoke_agent {agent_name}",
        1,
        server_id,
        [attr("gen_ai.operation.name", "invoke_agent")],
        start_ns=now,
        status_code=0,
    )
    return {
        "traceId": context["traceId"],
        "traceFlags": context["traceFlags"],
        "traceFlagsHex": context["traceFlagsHex"],
        "tracestate": context["tracestate"],
        "upstreamParentSpanId": context["upstreamParentSpanId"],
        "serverSpanId": server_id,
        "agentSpanId": agent_span["spanId"],
        "spans": [server_span, agent_span],
        "actionSpanIds": {},
        "actionMeta": {},
        "clientSpanIds": {},
        "joinSpanId": None,
        "runId": run_id,
        "publicMarker": public_marker,
        "agentName": agent_name,
    }


def close_initial_spans(state: dict[str, Any]) -> None:
    server = next(span for span in state["spans"] if span["spanId"] == state["serverSpanId"])
    server["endTimeUnixNano"] = str(time.time_ns())
    server["status"] = {"code": 1}
    set_attr(server, "http.response.status_code", 200)


def finish_trace(state: dict[str, Any]) -> None:
    """Close the durable agent operation after every observed child has finished."""
    agent = next(span for span in state["spans"] if span["spanId"] == state["agentSpanId"])
    if state.get("traceFinished"):
        return
    agent["endTimeUnixNano"] = str(time.time_ns())
    agent["status"] = {"code": 1 if state["status"] == "completed" else 2}
    state["traceFinished"] = True


def close_model_span(state: dict[str, Any], span_id: str, success: bool, error_type: str | None = None) -> None:
    span = next((item for item in state["spans"] if item["spanId"] == span_id), None)
    if not span:
        return
    span["endTimeUnixNano"] = str(time.time_ns())
    if success:
        span["status"] = {"code": 1}
    else:
        span["status"] = {"code": 2}
        if error_type:
            set_attr(span, "error.type", error_type)


def add_approval_gate(state: dict[str, Any], approval_id: str, nonce: str, decision: str) -> None:
    start = state.get("approvalSpanStartNs") or time.time_ns()
    span = make_span(
        state,
        "approval_gate",
        1,
        state["agentSpanId"],
        [
            attr("ga5.approval.id", approval_id),
            attr("ga5.approval.receipt.nonce", nonce),
            attr("ga5.approval.decision", decision),
        ],
        start_ns=int(start),
        end_ns=time.time_ns(),
        status_code=1 if decision == "approved" else 2,
    )
    state["spans"].append(span)

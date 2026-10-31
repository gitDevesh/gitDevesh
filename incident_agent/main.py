from __future__ import annotations

import asyncio
import copy
import hashlib
import json
import logging
import os
import re
import sqlite3
import time
import uuid
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from jsonschema import ValidationError, validate
from jsonschema.validators import validator_for

from planner import MODEL_NAME, call_planner
from telemetry import (
    add_approval_gate, add_client_attempt, add_join_span, add_logical_action, attr,
    close_initial_spans, close_model_span, end_action_span, end_join_span, finish_trace, make_otlp,
    make_span, set_attr, start_trace_state, trace_context, update_client_receipt,
)


PROFILE = "ga5-incident-agent/v2"
MAX_BODY_BYTES = 2 * 1024 * 1024
MAX_RESPONSE_BYTES = 768 * 1024
DB_PATH = os.getenv("INCIDENT_DB_PATH", "/tmp/incident-agent.sqlite3")
DESTRUCTIVE_TOOLS = {"rollback_deployment", "disable_feature"}

app = FastAPI(title="Observable Incident Triage Agent", version="2.0")
log = logging.getLogger("incident-agent")
_run_locks: dict[str, asyncio.Lock] = {}
_run_locks_guard = asyncio.Lock()


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


def new_id() -> str:
    return uuid.uuid4().hex


def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=1, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=1000")
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=FULL")
    return conn


def init_db() -> None:
    conn = get_db()
    try:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS incident_runs (
                run_id TEXT PRIMARY KEY,
                request_hash TEXT NOT NULL,
                state_json TEXT NOT NULL,
                initial_response TEXT NOT NULL,
                latest_response TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS incident_receipts (
                run_id TEXT NOT NULL,
                receipt_id TEXT NOT NULL,
                content_hash TEXT NOT NULL,
                response_json TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (run_id, receipt_id)
            );
            """
        )
    finally:
        conn.close()


init_db()


async def lock_for_run(run_id: str) -> asyncio.Lock:
    async with _run_locks_guard:
        lock = _run_locks.get(run_id)
        if lock is None:
            lock = asyncio.Lock()
            _run_locks[run_id] = lock
        return lock


def get_run(run_id: str) -> sqlite3.Row | None:
    conn = get_db()
    try:
        return conn.execute(
            "SELECT run_id,request_hash,state_json,initial_response,latest_response FROM incident_runs WHERE run_id=?",
            (run_id,),
        ).fetchone()
    finally:
        conn.close()


def save_initial(run_id: str, request_hash: str, state: dict[str, Any], response: dict[str, Any]) -> None:
    conn = get_db()
    try:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute(
            "INSERT INTO incident_runs(run_id,request_hash,state_json,initial_response,latest_response) VALUES(?,?,?,?,?)",
            (run_id, request_hash, canonical(state), canonical(response), canonical(response)),
        )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def save_transition(
    run_id: str,
    state: dict[str, Any],
    receipt_id: str,
    receipt_hash: str,
    response: dict[str, Any],
) -> None:
    conn = get_db()
    try:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute(
            "INSERT INTO incident_receipts(run_id,receipt_id,content_hash,response_json) VALUES(?,?,?,?)",
            (run_id, receipt_id, receipt_hash, canonical(response)),
        )
        updated = conn.execute(
            "UPDATE incident_runs SET state_json=?,latest_response=?,updated_at=CURRENT_TIMESTAMP WHERE run_id=?",
            (canonical(state), canonical(response), run_id),
        )
        if updated.rowcount != 1:
            raise ValueError("run disappeared")
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def get_receipt(run_id: str, receipt_id: str) -> sqlite3.Row | None:
    conn = get_db()
    try:
        return conn.execute(
            "SELECT content_hash,response_json FROM incident_receipts WHERE run_id=? AND receipt_id=?",
            (run_id, receipt_id),
        ).fetchone()
    finally:
        conn.close()


def error(status: int, message: str) -> JSONResponse:
    return JSONResponse({"error": message}, status_code=status)


def parse_evidence_ids(transcript: str) -> list[str]:
    found: list[str] = []
    for line in transcript.splitlines():
        match = re.match(r"^\s*\[([^\]\r\n]+)\]", line)
        if match:
            evidence_id = match.group(1).strip()
            if evidence_id and evidence_id not in found:
                found.append(evidence_id)
    return found


def validate_request(body: Any) -> tuple[str, str, str, dict[str, Any], list[str], dict[str, Any]]:
    if not isinstance(body, dict) or body.get("profile") != PROFILE:
        raise ValueError("unsupported request profile")
    run_id = body.get("runId")
    if not isinstance(run_id, str) or not run_id.strip() or len(run_id) > 256:
        raise ValueError("invalid runId")
    agent_name = body.get("agentName")
    if not isinstance(agent_name, str) or not agent_name.strip():
        raise ValueError("invalid agentName")
    public_marker = body.get("publicMarker")
    if not isinstance(public_marker, str) or not public_marker.strip() or len(public_marker) > 256:
        raise ValueError("invalid publicMarker")
    incident = body.get("incident")
    catalog = body.get("toolCatalog")
    policy = body.get("policy")
    if not isinstance(incident, dict) or not isinstance(catalog, list) or not isinstance(policy, dict):
        raise ValueError("incident, toolCatalog, and policy are required")
    if not isinstance(incident.get("incidentId"), str) or not incident["incidentId"]:
        raise ValueError("incidentId is required")
    if not isinstance(incident.get("transcript"), str) or not incident["transcript"]:
        raise ValueError("transcript is required")
    roots = incident.get("allowedRootCauses")
    if not isinstance(roots, list) or not roots or any(not isinstance(x, str) or not x for x in roots):
        raise ValueError("allowedRootCauses is required")
    if not catalog:
        raise ValueError("toolCatalog is required")
    names: set[str] = set()
    for tool in catalog:
        if not isinstance(tool, dict) or not isinstance(tool.get("name"), str) or not tool["name"]:
            raise ValueError("invalid tool catalog")
        if tool["name"] in names:
            raise ValueError("duplicate tool name")
        names.add(tool["name"])
        if not isinstance(tool.get("inputSchema", {}), dict):
            raise ValueError("invalid tool input schema")
        validator_for(tool.get("inputSchema", {})).check_schema(tool.get("inputSchema", {}))
    maximum = policy.get("maximumDiagnostics")
    if not isinstance(maximum, int) or isinstance(maximum, bool) or maximum < 1:
        raise ValueError("maximumDiagnostics must be a positive integer")
    effects = policy.get("effectTools", [])
    approvals = policy.get("approvalRequiredFor", [])
    if not isinstance(effects, list) or not effects or any(not isinstance(x, str) for x in effects):
        raise ValueError("invalid effectTools")
    if not isinstance(approvals, list) or any(not isinstance(x, str) for x in approvals):
        raise ValueError("invalid approvalRequiredFor")
    if any(name not in names for name in effects + approvals):
        raise ValueError("policy references an unknown tool")
    if not names - set(effects) - set(approvals) - DESTRUCTIVE_TOOLS:
        raise ValueError("at least one diagnostic tool is required")
    if "doNotExport" in policy and (not isinstance(policy["doNotExport"], list) or any(not isinstance(x, str) for x in policy["doNotExport"])):
        raise ValueError("invalid doNotExport")
    blocked = sensitive_values(body)
    public_fields = [run_id, agent_name, public_marker, *roots, *names]
    if any(secret and (secret == value or (len(secret) >= 4 and secret in value)) for secret in blocked for value in public_fields):
        raise ValueError("protected values cannot be public identifiers")
    evidence_ids = parse_evidence_ids(incident["transcript"])
    if len(evidence_ids) < 2:
        raise ValueError("transcript must contain at least two evidence-tagged lines")
    return run_id, agent_name, public_marker, incident, evidence_ids, {
        "catalog": catalog,
        "policy": policy,
        "roots": roots,
        "evidenceIds": evidence_ids,
    }


def sensitive_values(body: dict[str, Any]) -> list[str]:
    values: list[str] = []
    def collect(value: Any) -> None:
        if isinstance(value, str) and value and value not in values:
            values.append(value)
        elif isinstance(value, dict):
            for item in value.values():
                collect(item)
        elif isinstance(value, list):
            for item in value:
                collect(item)
    collect(body.get("sensitive", {}))
    do_not_export = (body.get("policy") or {}).get("doNotExport", [])
    if isinstance(do_not_export, list):
        for value in do_not_export:
            if isinstance(value, str) and len(value) >= 8 and value not in values:
                values.append(value)
    return values


def redact_planner_input(value: Any, blocked: list[str]) -> Any:
    if isinstance(value, str):
        for secret in sorted(blocked, key=len, reverse=True):
            if len(secret) >= 4:
                value = value.replace(secret, "[REDACTED]")
            elif value == secret:
                value = "[REDACTED]"
        return value
    if isinstance(value, dict):
        return {key: redact_planner_input(item, blocked) for key, item in value.items()}
    if isinstance(value, list):
        return [redact_planner_input(item, blocked) for item in value]
    return value


def has_protected_value(value: Any, blocked: list[str]) -> bool:
    if isinstance(value, str):
        return any(secret == value or (len(secret) >= 4 and secret in value) for secret in blocked if secret)
    if isinstance(value, dict):
        return any(has_protected_value(key, blocked) or has_protected_value(item, blocked) for key, item in value.items())
    if isinstance(value, list):
        return any(has_protected_value(item, blocked) for item in value)
    return False


def validate_schema_args(tool: dict[str, Any], arguments: Any) -> dict[str, Any]:
    if not isinstance(arguments, dict):
        raise ValueError("tool arguments must be an object")
    schema = tool.get("inputSchema") or {"type": "object"}
    try:
        validate(instance=arguments, schema=schema)
    except ValidationError as exc:
        path = ".".join(str(part) for part in exc.absolute_path) or "$"
        reason = str(exc.validator or "schema")
        name = str(tool.get("name") or "tool")
        raise ValueError(f"tool arguments do not match schema for {name} ({reason} at {path})") from None
    return arguments


def validate_plan(
    plan: dict[str, Any],
    incident: dict[str, Any],
    catalog: list[dict[str, Any]],
    policy: dict[str, Any],
    roots: list[str],
    evidence_ids: list[str],
    blocked_values: list[str],
) -> dict[str, Any]:
    root = plan.get("rootCause")
    if root not in roots:
        raise ValueError("rootCause is not allowed")
    evidence = plan.get("evidence")
    if not isinstance(evidence, list) or not 2 <= len(evidence) <= 4:
        raise ValueError("diagnosis requires two to four evidence IDs")
    if len(set(evidence)) != len(evidence) or any(item not in evidence_ids for item in evidence):
        raise ValueError("diagnosis evidence must reference unique transcript IDs")

    tools = {tool["name"]: tool for tool in catalog}
    effects = list(dict.fromkeys(policy.get("effectTools", [])))
    effect_set = set(effects)
    diagnostic_names = [name for name in tools if name not in effect_set | set(policy.get("approvalRequiredFor", [])) | DESTRUCTIVE_TOOLS]
    diagnostics = plan.get("diagnostics")
    maximum = min(3, policy.get("maximumDiagnostics", 3))
    if not isinstance(diagnostics, list) or not 1 <= len(diagnostics) <= maximum:
        raise ValueError("one to three necessary diagnostics are required")
    normalized_diagnostics: list[dict[str, Any]] = []
    seen_diagnostics: set[str] = set()
    for item in diagnostics:
        if not isinstance(item, dict):
            raise ValueError("invalid diagnostic proposal")
        name = item.get("toolName")
        if name not in tools or name not in diagnostic_names:
            raise ValueError("diagnostic tool is not permitted")
        arguments = validate_schema_args(tools[name], item.get("arguments"))
        signature = canonical([name, arguments])
        if signature in seen_diagnostics:
            raise ValueError("duplicate diagnostic proposal")
        seen_diagnostics.add(signature)
        cited = item.get("evidence")
        if not isinstance(cited, list) or not cited or len(set(cited)) != len(cited):
            raise ValueError("diagnostic dispatch requires unique evidence IDs")
        if any(value not in evidence for value in cited):
            raise ValueError("diagnostic evidence must come from diagnosis evidence")
        normalized_diagnostics.append({"toolName": name, "arguments": arguments, "evidence": cited})

    effect = plan.get("effect")
    if not isinstance(effect, dict):
        raise ValueError("one effect proposal is required")
    effect_name = effect.get("toolName")
    if effect_name not in tools or effect_name not in effect_set:
        raise ValueError("effect tool is not permitted")
    effect_arguments = validate_schema_args(tools[effect_name], effect.get("arguments"))
    effect_evidence = effect.get("evidence")
    if not isinstance(effect_evidence, list) or not effect_evidence or len(set(effect_evidence)) != len(effect_evidence):
        raise ValueError("effect dispatch requires evidence")
    if any(value not in evidence for value in effect_evidence):
        raise ValueError("effect evidence must come from diagnosis evidence")

    safe_plan = {
        "rootCause": root,
        "evidence": evidence,
        "diagnostics": normalized_diagnostics,
        "effect": {
            "toolName": effect_name,
            "arguments": effect_arguments,
            "evidence": effect_evidence,
        },
    }
    if has_protected_value(safe_plan, blocked_values):
        raise ValueError("plan contains a protected value")
    return safe_plan


def make_dispatch(
    state: dict[str, Any],
    tool_name: str,
    arguments: dict[str, Any],
    phase: str,
    evidence: list[str],
    action_id: str | None = None,
    call_id: str | None = None,
    attempt: int = 1,
    approval_id: str | None = None,
    approval_nonce: str | None = None,
) -> dict[str, Any]:
    action_id = action_id or new_id()
    call_id = call_id or new_id()
    if action_id not in state["actionSpanIds"]:
        add_logical_action(state, tool_name, phase, action_id, call_id, approval_id)
    client_span, span_id = add_client_attempt(state, tool_name, action_id, call_id, attempt)
    traceparent = f"00-{state['traceId']}-{span_id}-{state['traceFlagsHex']}"
    dispatch: dict[str, Any] = {
        "actionId": action_id,
        "callId": call_id,
        "phase": phase,
        "toolName": tool_name,
        "arguments": arguments,
        "evidence": evidence,
        "attempt": attempt,
        "traceparent": traceparent,
    }
    if state.get("tracestate"):
        dispatch["tracestate"] = state["tracestate"]
    if approval_id:
        dispatch["approvalId"] = approval_id
    if approval_nonce:
        dispatch["approvalNonce"] = approval_nonce
        set_attr(client_span, "ga5.approval.id", approval_id)
        set_attr(client_span, "ga5.approval.nonce", approval_nonce)
    state["actionLog"].append(dispatch)
    state["pending"][call_id] = {
        "actionId": action_id,
        "callId": call_id,
        "phase": phase,
        "toolName": tool_name,
        "attempt": attempt,
        "approvalId": approval_id,
        "approvalNonce": approval_nonce,
        "arguments": arguments,
        "evidence": evidence,
    }
    return dispatch


def build_waiting_response(
    state: dict[str, Any],
    dispatches: list[dict[str, Any]],
    approvals: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "runId": state["runId"],
        "status": "waiting",
        "diagnosis": state["diagnosis"],
        "dispatches": dispatches,
        "approvals": approvals,
    }


def final_response(state: dict[str, Any]) -> dict[str, Any]:
    finish_trace(state)
    result: dict[str, Any] = {
        "runId": state["runId"],
        "status": state["status"],
        "diagnosis": state["diagnosis"],
        "chosenEffect": state.get("chosenEffect"),
        "suppressed": state.get("suppressed", []),
        "actionLog": state.get("actionLog", []),
        "receiptLog": state.get("receiptLog", []),
        "otlp": make_otlp(state),
    }
    if len(canonical(result).encode("utf-8")) > MAX_RESPONSE_BYTES:
        raise ValueError("response is too large")
    return result


def set_terminal(state: dict[str, Any], status: str) -> dict[str, Any]:
    state["status"] = status
    state["pending"] = {}
    state["latestResponse"] = final_response(state)
    return state["latestResponse"]


def diagnostic_completion(state: dict[str, Any]) -> tuple[bool, bool]:
    values = list(state["diagnosticStatus"].values())
    all_finished = all(value != "pending" for value in values)
    any_failed = any(value == "failed" for value in values)
    return all_finished, any_failed


def make_approval_request(state: dict[str, Any]) -> dict[str, Any]:
    effect = state["plannedEffect"]
    approval_id = new_id()
    action_id = state["effectActionId"]
    approval = {
        "approvalId": approval_id,
        "actionId": action_id,
        "toolName": effect["toolName"],
        "argumentsDigest": digest(effect["arguments"]),
    }
    state["approvalPending"] = {
        **approval,
        "callId": state["effectCallId"],
        "arguments": effect["arguments"],
        "evidence": effect["evidence"],
    }
    state["approvalSpanStartNs"] = time.time_ns()
    return approval


def create_effect_dispatch(state: dict[str, Any], approval_id: str | None = None, nonce: str | None = None) -> dict[str, Any]:
    effect = state["plannedEffect"]
    return make_dispatch(
        state=state,
        tool_name=effect["toolName"],
        arguments=effect["arguments"],
        phase="effect",
        evidence=effect["evidence"],
        action_id=state["effectActionId"],
        call_id=state["effectCallId"],
        attempt=1,
        approval_id=approval_id,
        approval_nonce=nonce,
    )


def schedule_after_diagnostics(state: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    all_finished, any_failed = diagnostic_completion(state)
    if not all_finished:
        return [], []
    if state.get("effectScheduled") or state.get("approvalPending"):
        return [], []
    if state.get("joinSpanId"):
        end_join_span(state, 200 if not any_failed else 2)
    if any_failed:
        effect = state["plannedEffect"]
        state["chosenEffect"] = effect["toolName"]
        state["suppressed"] = [{
            "toolName": effect["toolName"],
            "reason": "a required diagnostic failed or timed out",
        }]
        set_terminal(state, "failed")
        return [], []
    effect_name = state["plannedEffect"]["toolName"]
    if effect_name in state["approvalRequiredFor"]:
        approval = make_approval_request(state)
        state["effectScheduled"] = True
        state["latestResponse"] = build_waiting_response(state, [], [approval])
        return [], [approval]
    dispatch = create_effect_dispatch(state)
    state["effectScheduled"] = True
    state["latestResponse"] = build_waiting_response(state, [dispatch], [])
    return [dispatch], []


def valid_receipt_id(value: Any) -> bool:
    return isinstance(value, str) and len(value) >= 8 and len(value) <= 256


def valid_nonce(value: Any) -> bool:
    if not isinstance(value, str) or len(value) > 128:
        return False
    try:
        uuid.UUID(value)
        return True
    except (ValueError, AttributeError):
        return False


def outcome_receipt_entry(receipt_id: str, outcome: dict[str, Any]) -> dict[str, Any]:
    entry = {
        "receiptId": receipt_id,
        "actionId": outcome["actionId"],
        "callId": outcome["callId"],
        "attempt": outcome["attempt"],
        "status": outcome["status"],
        "nonce": outcome["nonce"],
    }
    if "resultClass" in outcome:
        entry["resultClass"] = outcome["resultClass"]
    if outcome.get("errorType"):
        entry["errorType"] = outcome["errorType"]
    return entry


def approval_receipt_entry(receipt_id: str, approval: dict[str, Any]) -> dict[str, Any]:
    return {
        "receiptId": receipt_id,
        "approvalId": approval["approvalId"],
        "decision": approval["decision"],
        "nonce": approval["nonce"],
    }


def apply_outcomes(state: dict[str, Any], receipt_id: str, outcomes: list[Any]) -> tuple[list[dict[str, Any]], bool]:
    if not isinstance(outcomes, list) or not outcomes:
        raise ValueError("outcomes must be a nonempty array")
    seen: set[str] = set()
    new_dispatches: list[dict[str, Any]] = []
    for outcome in outcomes:
        if not isinstance(outcome, dict):
            raise ValueError("each outcome must be an object")
        call_id = outcome.get("callId")
        if not isinstance(call_id, str) or call_id in seen:
            raise ValueError("outcome callIds must be unique")
        seen.add(call_id)
        pending = state["pending"].get(call_id)
        if not pending:
            raise ValueError("outcome does not match a pending call")
        for key in ("actionId", "callId", "attempt"):
            if outcome.get(key) != pending.get(key):
                raise ValueError("outcome does not match the pending attempt")
        if not isinstance(outcome.get("attempt"), int) or isinstance(outcome.get("attempt"), bool):
            raise ValueError("outcome attempt must be an integer")
        if not isinstance(outcome.get("status"), int) or isinstance(outcome.get("status"), bool):
            raise ValueError("outcome status must be an integer")
        if not valid_nonce(outcome.get("nonce")):
            raise ValueError("outcome nonce must be a UUID")
        if outcome["status"] == 0 and outcome.get("errorType") != "timeout":
            raise ValueError("status 0 is only valid for a timeout")
        if outcome["status"] != 0 and not 100 <= outcome["status"] <= 599:
            raise ValueError("outcome status is invalid")
        if "resultClass" in outcome and (not isinstance(outcome["resultClass"], str) or not outcome["resultClass"]):
            raise ValueError("resultClass must be a nonempty string")
        if "errorType" in outcome and (not isinstance(outcome["errorType"], str) or not outcome["errorType"] or outcome["status"] == 200):
            raise ValueError("errorType is invalid for the observed status")

    # All entries are validated before state changes, so malformed receipts are atomic.
    for outcome in outcomes:
        call_id = outcome["callId"]
        pending = state["pending"][call_id]
        action_id = pending["actionId"]
        attempt = pending["attempt"]
        status_code = outcome["status"]
        phase = pending["phase"]
        update_client_receipt(state, action_id, attempt, receipt_id, outcome)
        state["receiptLog"].append(outcome_receipt_entry(receipt_id, outcome))

        if status_code == 503 and attempt == 1:
            del state["pending"][call_id]
            issued = next(item for item in reversed(state["actionLog"]) if item["callId"] == call_id and item["attempt"] == attempt)
            retry = make_dispatch(
                state=state, tool_name=pending["toolName"],
                arguments=issued["arguments"], phase=phase, evidence=issued["evidence"],
                action_id=action_id, call_id=call_id, attempt=2,
                approval_id=issued.get("approvalId"), approval_nonce=issued.get("approvalNonce"),
            )
            new_dispatches.append(retry)
            continue
        if phase == "diagnostic":
            if status_code == 200:
                state["diagnosticStatus"][action_id] = "success"
                end_action_span(state, action_id, 200)
            else:
                state["diagnosticStatus"][action_id] = "failed"
                end_action_span(state, action_id, status_code)
                state["failedDiagnostics"].append(action_id)
            del state["pending"][call_id]
        else:
            end_action_span(state, action_id, status_code)
            del state["pending"][call_id]
            if status_code == 200:
                state["status"] = "completed"
                state["chosenEffect"] = pending["toolName"]
                state["latestResponse"] = final_response(state)
            else:
                state["status"] = "failed"
                state["chosenEffect"] = pending["toolName"]
                state["suppressed"].append({"toolName": pending["toolName"], "reason": "effect failed"})
                state["latestResponse"] = final_response(state)

    return new_dispatches, any(item["phase"] == "diagnostic" for item in state["pending"].values())


def validate_receipt_body(body: Any) -> tuple[str, list[Any], list[Any]]:
    if not isinstance(body, dict):
        raise ValueError("receipt body must be an object")
    receipt_id = body.get("receiptId")
    if not valid_receipt_id(receipt_id):
        raise ValueError("receiptId is invalid")
    outcomes = body.get("outcomes", [])
    approvals = body.get("approvals", [])
    if not isinstance(outcomes, list) or not isinstance(approvals, list):
        raise ValueError("outcomes and approvals must be arrays")
    if bool(outcomes) == bool(approvals):
        raise ValueError("receipt must contain outcomes or approvals")
    return receipt_id, outcomes, approvals


def process_approval(state: dict[str, Any], receipt_id: str, approvals: list[Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    pending = state.get("approvalPending")
    if not pending or len(approvals) != 1 or not isinstance(approvals[0], dict):
        raise ValueError("approval does not match a pending approval")
    approval = approvals[0]
    if approval.get("approvalId") != pending["approvalId"]:
        raise ValueError("approvalId does not match")
    decision = approval.get("decision")
    nonce = approval.get("nonce")
    if decision not in ("approved", "rejected") or not valid_nonce(nonce):
        raise ValueError("approval decision or nonce is invalid")
    state["receiptLog"].append(approval_receipt_entry(receipt_id, approval))
    add_approval_gate(state, pending["approvalId"], nonce, decision)
    state["approvalPending"] = None
    if decision == "approved":
        dispatch = create_effect_dispatch(state, pending["approvalId"], nonce)
        state["latestResponse"] = build_waiting_response(state, [dispatch], [])
        return [dispatch], []
    state["status"] = "failed"
    state["chosenEffect"] = pending["toolName"]
    state["suppressed"] = [{"toolName": pending["toolName"], "reason": "approval rejected"}]
    state["latestResponse"] = final_response(state)
    return [], []


@app.api_route("/", methods=["GET", "HEAD"])
async def root() -> JSONResponse:
    return JSONResponse({"status": "ok", "service": "observable-incident-agent", "profile": PROFILE, "health": "/health", "createIncident": "POST /v2/incidents", "receipt": "POST /v2/incidents/{run_id}/receipts", "getIncident": "GET /v2/incidents/{run_id}"})


@app.get("/health")
async def health() -> JSONResponse:
    return JSONResponse({"status": "ok", "profile": PROFILE})


@app.post("/v2/incidents")
async def create_incident(request: Request) -> JSONResponse:
    content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if content_type != "application/json":
        return error(415, "Content-Type application/json is required")
    raw = await request.body()
    if len(raw) > MAX_BODY_BYTES:
        return error(413, "request body is too large")
    try:
        body = json.loads(raw)
    except Exception:
        return error(400, "request body must be valid JSON")
    try:
        run_id, agent_name, public_marker, incident, evidence_ids, validated = validate_request(body)
        request_hash = digest(body)
    except Exception:
        return error(422, "request does not match the incident-agent contract")

    lock = await lock_for_run(run_id)
    async with lock:
        existing = get_run(run_id)
        if existing:
            if existing["request_hash"] != request_hash:
                return error(409, "runId is already used with different content")
            return JSONResponse(json.loads(existing["initial_response"]))

        context = trace_context(request)
        state = start_trace_state(run_id, agent_name, public_marker, context)
        state.update({
            "status": "waiting",
            "diagnosis": None,
            "plannedEffect": None,
            "effectActionId": new_id(),
            "effectCallId": new_id(),
            "effectScheduled": False,
            "approvalRequiredFor": list(set(validated["policy"].get("approvalRequiredFor", [])) | DESTRUCTIVE_TOOLS),
            "diagnosticStatus": {},
            "diagnosticArguments": {},
            "diagnosticEvidence": {},
            "failedDiagnostics": [],
            "pending": {},
            "actionLog": [],
            "receiptLog": [],
            "chosenEffect": None,
            "suppressed": [],
            "approvalPending": None,
            "approvalSpanStartNs": None,
            "latestResponse": None,
        })
        planner_span = make_span(
            state,
            "chat incident-plan",
            3,
            state["agentSpanId"],
            [
                attr("gen_ai.operation.name", "chat"),
                attr("gen_ai.request.model", MODEL_NAME),
            ],
            status_code=0,
        )
        state["spans"].append(planner_span)

        try:
            blocked = sensitive_values(body)
            plan_raw = await asyncio.wait_for(asyncio.to_thread(
                call_planner, agent_name,
                redact_planner_input(incident, blocked),
                redact_planner_input(validated["catalog"], blocked),
                validated["policy"], validated["roots"], evidence_ids,
            ), timeout=16.5)
            plan = validate_plan(
                plan_raw,
                incident,
                validated["catalog"],
                validated["policy"],
                validated["roots"],
                evidence_ids,
                sensitive_values(body),
            )
        except Exception as exc:
            close_model_span(state, planner_span["spanId"], False, type(exc).__name__)
            log.warning("incident planning failed: %s: %s", type(exc).__name__, str(exc) if isinstance(exc, RuntimeError) else "invalid_or_unavailable_plan")
            return error(503, "incident planning is temporarily unavailable")
        close_model_span(state, planner_span["spanId"], True)

        state["diagnosis"] = {"rootCause": plan["rootCause"], "evidence": plan["evidence"]}
        state["plannedEffect"] = plan["effect"]
        state["diagnosticActionIds"] = []
        dispatches: list[dict[str, Any]] = []
        for diagnostic in plan["diagnostics"]:
            action_id = new_id()
            call_id = new_id()
            state["diagnosticActionIds"].append(action_id)
            state["diagnosticStatus"][action_id] = "pending"
            state["diagnosticArguments"][action_id] = diagnostic["arguments"]
            state["diagnosticEvidence"][action_id] = diagnostic["evidence"]
            dispatches.append(
                make_dispatch(
                    state,
                    diagnostic["toolName"],
                    diagnostic["arguments"],
                    "diagnostic",
                    diagnostic["evidence"],
                    action_id,
                    call_id,
                    1,
                )
            )
        add_join_span(state, state["diagnosticActionIds"])
        state["latestResponse"] = build_waiting_response(state, dispatches, [])
        close_initial_spans(state)
        try:
            if len(canonical(state["latestResponse"]).encode("utf-8")) > MAX_RESPONSE_BYTES:
                return error(413, "response is too large")
            save_initial(run_id, request_hash, state, state["latestResponse"])
        except Exception:
            log.exception("failed to persist initial incident state")
            return error(503, "incident state could not be saved")
        return JSONResponse(state["latestResponse"])


@app.post("/v2/incidents/{run_id}/receipts")
async def receive_receipts(run_id: str, request: Request) -> JSONResponse:
    content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if content_type != "application/json":
        return error(415, "Content-Type application/json is required")
    raw = await request.body()
    if len(raw) > MAX_BODY_BYTES:
        return error(413, "receipt body is too large")
    try:
        body = json.loads(raw)
        receipt_id, outcomes, approvals = validate_receipt_body(body)
        receipt_hash = digest(body)
    except Exception:
        return error(422, "receipt body is invalid")

    lock = await lock_for_run(run_id)
    async with lock:
        existing_receipt = get_receipt(run_id, receipt_id)
        if existing_receipt:
            if existing_receipt["content_hash"] != receipt_hash:
                return error(409, "receiptId is already used with different content")
            return JSONResponse(json.loads(existing_receipt["response_json"]))

        row = get_run(run_id)
        if not row:
            return error(404, "runId was not found")
        state = json.loads(row["state_json"])
        if state["status"] != "waiting":
            return error(409, "run is already terminal")

        updated = copy.deepcopy(state)
        try:
            if outcomes:
                if updated.get("approvalPending") is not None:
                    raise ValueError("outcomes cannot replace a pending approval")
                new_dispatches, diagnostic_pending = apply_outcomes(updated, receipt_id, outcomes)
                new_approvals: list[dict[str, Any]] = []
                if diagnostic_pending:
                    response = build_waiting_response(updated, new_dispatches, [])
                else:
                    if not updated["pending"]:
                        scheduled, approvals_now = schedule_after_diagnostics(updated)
                        new_dispatches.extend(scheduled)
                        new_approvals.extend(approvals_now)
                    if updated["status"] in ("completed", "failed"):
                        response = final_response(updated)
                    else:
                        response = build_waiting_response(updated, new_dispatches, new_approvals)
            else:
                new_dispatches, new_approvals = process_approval(updated, receipt_id, approvals)
                if updated["status"] in ("completed", "failed"):
                    response = final_response(updated)
                else:
                    response = build_waiting_response(updated, new_dispatches, new_approvals)
        except Exception:
            return error(422, "receipt does not match the current pending state")

        if len(canonical(response).encode("utf-8")) > MAX_RESPONSE_BYTES:
            return error(413, "response is too large")
        updated["latestResponse"] = response
        try:
            save_transition(run_id, updated, receipt_id, receipt_hash, response)
        except sqlite3.IntegrityError:
            # The per-run lock should prevent this in one instance; this protects
            # against duplicate writers if the service is scaled later.
            duplicate = get_receipt(run_id, receipt_id)
            if duplicate and duplicate["content_hash"] == receipt_hash:
                return JSONResponse(json.loads(duplicate["response_json"]))
            return error(409, "receiptId conflicts with an existing receipt")
        except Exception:
            log.exception("failed to persist receipt transition")
            return error(503, "receipt state could not be saved")
        return JSONResponse(response)


@app.get("/v2/incidents/{run_id}")
async def get_incident(run_id: str) -> JSONResponse:
    row = get_run(run_id)
    if not row:
        return error(404, "runId was not found")
    return JSONResponse(json.loads(row["latest_response"]))

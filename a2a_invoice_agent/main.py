import os, json, uuid, hashlib, sqlite3, threading, re
from datetime import datetime, timezone
from contextlib import contextmanager
from typing import Any
from fastapi import FastAPI, Request, Header, HTTPException
from fastapi.responses import JSONResponse

APP_NAME = "A2A Invoice Action Agent"
VERSION = "1.0.0"
DB_PATH = os.getenv("DATABASE_PATH", "/tmp/a2a_invoice_agent.sqlite3")
A2A_JSON = "application/a2a+json"
BATCH_MT = "application/vnd.ga5.invoice-claim-batch+json"
PROPOSALS_MT = "application/vnd.ga5.invoice-action-proposals+json"
RESULTS_MT = "application/vnd.ga5.invoice-action-results+json"
RECEIPTS_MT = "application/vnd.ga5.invoice-action-receipts+json"
ACTIONS = {"settle_invoice", "request_approval", "hold_invoice", "reject_duplicate", "open_exception"}
lock = threading.RLock()
app = FastAPI(title=APP_NAME, version=VERSION)

def now():
    return datetime.now(timezone.utc).isoformat()

def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

def digest(obj):
    return hashlib.sha256(canonical(obj).encode()).hexdigest()

def init_db():
    with sqlite3.connect(DB_PATH) as c:
        c.execute("""CREATE TABLE IF NOT EXISTS tasks (
          id TEXT PRIMARY KEY, principal_hash TEXT NOT NULL, context_id TEXT NOT NULL,
          state TEXT NOT NULL, batch_id TEXT, task_json TEXT NOT NULL, updated_at TEXT NOT NULL)""")
        c.execute("""CREATE TABLE IF NOT EXISTS messages (
          principal_hash TEXT NOT NULL, message_id TEXT NOT NULL, body_hash TEXT NOT NULL,
          task_id TEXT NOT NULL, PRIMARY KEY(principal_hash,message_id))""")
        c.execute("""CREATE TABLE IF NOT EXISTS decisions (
          package_hash TEXT PRIMARY KEY, proposal_json TEXT NOT NULL)""")
        c.commit()

init_db()

@contextmanager
def db():
    c = sqlite3.connect(DB_PATH, timeout=20)
    c.row_factory = sqlite3.Row
    try:
        yield c
        c.commit()
    finally:
        c.close()

def task_load(task_id, principal_hash):
    with db() as c:
        row = c.execute("SELECT task_json FROM tasks WHERE id=? AND principal_hash=?", (task_id, principal_hash)).fetchone()
    return json.loads(row["task_json"]) if row else None

def task_store(task, principal_hash, batch_id=None):
    with db() as c:
        c.execute("""INSERT INTO tasks(id,principal_hash,context_id,state,batch_id,task_json,updated_at)
          VALUES(?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET state=excluded.state,
          batch_id=excluded.batch_id,task_json=excluded.task_json,updated_at=excluded.updated_at""",
          (task["id"], principal_hash, task["contextId"], task["status"]["state"], batch_id,
           canonical(task), now()))

def proto_error(status, code, message):
    return JSONResponse(status_code=status, media_type=A2A_JSON,
        content={"error":{"code":code,"message":message}})

@app.middleware("http")
async def a2a_headers(request: Request, call_next):
    if request.url.path == "/.well-known/agent-card.json" or request.url.path == "/health":
        return await call_next(request)
    if request.method == "OPTIONS":
        return JSONResponse(status_code=204, content={})
    # Authenticate protected resources before validating protocol headers so an
    # unauthenticated task-list request consistently receives 401.
    auth = request.headers.get("authorization", "")
    if not auth.startswith("Bearer ") or not auth[7:].strip():
        return proto_error(401, "UNAUTHENTICATED", "A valid Bearer token is required.")
    request.state.principal_hash = hashlib.sha256(auth[7:].encode()).hexdigest()
    if request.headers.get("A2A-Version") != "1.0":
        return proto_error(400, "UNSUPPORTED_VERSION", "A2A-Version 1.0 is required.")
    if request.method == "POST" and request.headers.get("content-type", "").split(";")[0].strip().lower() != A2A_JSON:
        return proto_error(415, "UNSUPPORTED_MEDIA_TYPE", "Content-Type application/a2a+json is required.")
    response = await call_next(request)
    if response.headers.get("content-type", "").startswith("application/json"):
        response.headers["content-type"] = A2A_JSON
    return response

@app.get("/health")
def health():
    return {"ok": True, "service": APP_NAME, "version": VERSION}

@app.get("/.well-known/agent-card.json")
def agent_card(request: Request):
    base = str(request.base_url).rstrip("/")
    return JSONResponse(media_type=A2A_JSON, content={
      "name": APP_NAME,
      "description": "Evidence-based invoice action proposals with approval-gated, receipt-bound execution and durable task state.",
      "version": VERSION,
      "capabilities": {"streaming": False, "pushNotifications": False, "extendedAgentCard": False},
      "supportedInterfaces": [{"url": base, "protocolBinding": "HTTP+JSON", "protocolVersion": "1.0"}],
      "securitySchemes": {
        "bearerAuth": {
          "httpAuthSecurityScheme": {"scheme": "Bearer", "bearerFormat": "opaque"}
        }
      },
      "securityRequirements": [{"schemes": {"bearerAuth": []}}],
      "defaultInputModes": [BATCH_MT, RESULTS_MT],
      "defaultOutputModes": [PROPOSALS_MT, RECEIPTS_MT],
      "skills": [{"id":"invoice_action_agent","name":"Invoice Action Agent",
        "description":"Analyze invoice packages independently, identify the controlling facts, cite exact decisive evidence references, explain the selected action, and execute only accepted proposals with receipt-bound audit records.",
        "tags":["invoice","accounts-payable","evidence","idempotency","receipts"],
        "examples":["Analyze an invoice batch and return an evidence-backed action proposal for each package.","Submit accepted or rejected action results and return durable execution receipts."]}]
    })

def extract_parts(message):
    parts = message.get("parts") or []
    for p in parts:
        mt = p.get("mediaType") or p.get("type")
        data = p.get("data")
        if isinstance(data, dict):
            yield mt, data

def find_value(obj, keys, default=""):
    if isinstance(obj, dict):
        for k in keys:
            if k in obj and obj[k] is not None and not isinstance(obj[k], (dict, list)):
                return obj[k]
        for v in obj.values():
            got = find_value(v, keys, None)
            if got is not None and got != "":
                return got
    elif isinstance(obj, list):
        for v in obj:
            got = find_value(v, keys, None)
            if got is not None and got != "":
                return got
    return default

def flatten_text(obj):
    out=[]
    def walk(x):
        if isinstance(x, dict):
            for k,v in x.items():
                if isinstance(v,(dict,list)): walk(v)
                elif v is not None: out.append(f"{k}: {v}")
        elif isinstance(x,list):
            for v in x: walk(v)
        elif x is not None: out.append(str(x))
    walk(obj)
    return "\n".join(out)

def decision_lines(package):
    """Return evidence text with document provenance, excluding obvious non-controlling material."""
    lines = []
    excluded = re.compile(r"\b(?:archive|archived|training.?decoy|decoy|old example|historical example|cover sheet|superseded|obsolete)\b", re.I)
    def walk(value, path=""):
        if isinstance(value, dict):
            for key, child in value.items():
                walk(child, f"{path} {key}".strip())
        elif isinstance(value, list):
            for i, child in enumerate(value):
                walk(child, f"{path} item{i}")
        elif isinstance(value, str):
            # Preserve sentence-level evidence while retaining its source field.
            for sentence in re.split(r"(?<=[.!?])\s+|\n+", value):
                sentence = sentence.strip()
                if not sentence:
                    continue
                if excluded.search(path):
                    continue
                # Drop clearly labelled historical/decoy sentences, not a whole
                # paragraph merely because it mentions an unrelated invoice.
                if excluded.search(sentence) and re.search(r"\b(?:example|archive|decoy|superseded|obsolete)\b", sentence, re.I):
                    continue
                lines.append(f"{path}: {sentence}")
        elif value is not None:
            lines.append(f"{path}: {value}")
    walk(package)
    return lines

def evidence_refs(package, action=None):
    # Prefer references in current evidence-bearing paragraphs and rank those
    # whose own sentence supports the proposed action. Preserve reference text.
    lines = decision_lines(package)
    if not lines:
        lines = flatten_text(package).splitlines()
    all_refs = []
    for line in lines:
        all_refs.extend("[" + r.strip() + "]" for r in re.findall(r"\[([^\[\]]{1,100})\]", line) if r.strip())
    refs = list(dict.fromkeys(all_refs))
    if action and refs:
        keywords = {
          "reject_duplicate": (r"\balready paid\b", r"\bpreviously paid\b", r"\bpayment settled\b", r"\bsame invoice\b", r"\bduplicate invoice\b"),
          "request_approval": (r"\bapproval required\b", r"\brequires? approval\b", r"\bdelegated authority\b", r"\bapproval limit\b", r"\bapproval threshold\b"),
          "hold_invoice": (r"\bverification pending\b", r"\bawaiting verification\b", r"\bnot yet verified\b", r"\bpending confirmation\b", r"\bdelivery confirmation\b"),
          "open_exception": (r"\bconflict(?:ing)? records?\b", r"\bdiscrepancy\b", r"\bmismatch\b", r"\binconsistent\b", r"\bcontradict"),
          "settle_invoice": (r"\breconciled\b", r"\bmatched\b", r"\bwithin authority\b", r"\bapproved for payment\b", r"\bgoods received\b"),
        }.get(action, ())
        ranked = []
        for line in lines:
            if any(re.search(k, line, re.I) for k in keywords):
                ranked.extend("[" + r.strip() + "]" for r in re.findall(r"\[([^\[\]]{1,100})\]", line) if r.strip())
        if ranked:
            ranked = list(dict.fromkeys(ranked))
            refs = ranked + [r for r in refs if r not in ranked]
    return refs

def choose_fallback_action(package):
    # Use evidence sentences, excluding explicit archives/decoys and requiring
    # affirmative signals. If no safe positive case is established, hold.
    lines = decision_lines(package)
    if not lines:
        lines = flatten_text(package).splitlines()
    sentences = [line for line in lines if "[" in line and "]" in line] or lines
    def active_hit(sentence, patterns):
        low = sentence.lower()
        # Negated statements do not establish a business action.
        if re.search(r"\b(?:not|never|no evidence of|not yet|isn't|is not|wasn't|was not|cannot|do not)\b.{0,70}\b(?:paid|duplicate|conflict|discrepancy|mismatch|pending|approval|reconciled|matched|authorized)\b", low):
            return False
        return any(re.search(pattern, low, re.I) for pattern in patterns)
    def hits(patterns):
        return [s for s in sentences if active_hit(s, patterns)]
    conflicts = hits([r"\bmaterial conflict\b", r"\bconflicting records\b", r"\brecords conflict\b",
                      r"\bdiscrepancy\b", r"\bmismatch\b", r"\binconsistent (?:amount|vendor|invoice|records)\b",
                      r"\b(?:amount|vendor|invoice number)\s+(?:does not match|differs from|conflicts with)\b"])
    if conflicts:
        return "open_exception", conflicts[0]
    duplicate = hits([r"\bsame (?:commercial )?invoice\b.{0,100}\b(?:already paid|paid previously|previously paid|payment settled)\b",
                      r"\b(?:already paid|previously paid|payment settled)\b.{0,100}\bsame (?:commercial )?invoice\b",
                      r"\bduplicate invoice\b.{0,100}\bpaid\b"])
    if duplicate:
        return "reject_duplicate", duplicate[0]
    pending = hits([r"\b(?:awaiting|pending|not yet completed|not yet verified)\b.{0,80}\b(?:verification|confirm(?:ation)?|delivery|receipt|inspection|reconciliation)\b",
                    r"\b(?:verification|confirm(?:ation)?|delivery|receipt|inspection)\b.{0,80}\b(?:pending|awaiting|not yet verified)\b"])
    if pending:
        return "hold_invoice", pending[0]
    approval = hits([r"\b(?:requires?|needs?) approval\b", r"\bapproval required\b",
                     r"\bexceeds? (?:the )?(?:delegated )?(?:authority|limit|threshold)\b",
                     r"\babove (?:the )?delegated authority\b", r"\bapproval limit exceeded\b",
                     r"\bamount\s+(?:is\s+)?over\s+(?:the\s+)?approval threshold\b"])
    if approval:
        return "request_approval", approval[0]
    settled = hits([r"\b(?:fully )?reconciled\b", r"\bmatched (?:to|against) (?:the )?(?:purchase order|po|goods receipt)\b"])
    authorized = hits([r"\bwithin (?:the )?(?:agent.s )?(?:delegated )?authority\b",
                       r"\bwithin autonomous authority\b", r"\bbelow (?:the )?approval threshold\b",
                       r"\bwithin the approval limit\b"])
    if settled and authorized:
        return "settle_invoice", settled[0] + " " + authorized[0]
    return "hold_invoice", "The available evidence does not affirmatively establish reconciliation and delegated authority; payment remains on hold pending verification."

def ai_decide_batch(batch):
    packages = batch.get("packages") or []
    # Optional OpenAI-compatible reasoning. If no key is configured, use conservative deterministic fallback.
    api_key = os.getenv("OPENAI_API_KEY")
    model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
    if api_key:
        try:
            import urllib.request
            prompt = (
              "You are an expert accounts-payable decision agent. Read the full supplied package documents, not just cover sheets. "
              "Decide each package independently from its own controlling facts and supplied policyRevision. Do not apply a blanket action. "
              "Return ONLY a JSON object with a proposals array containing exactly one item per input package, in input order. "
              "Each item has packageId, action, facts {vendorName,invoiceNumber,amountMinor,currency}, evidenceRefs, rationale. "
              "Allowed actions: settle_invoice, request_approval, hold_invoice, reject_duplicate, open_exception. "
              "Select exactly the three decisive bracketed evidence references from the specific paragraph that controls the decision. "
              "Do not cite cover-sheet references, archive examples, training decoys, or irrelevant references. Preserve each reference exactly as written. "
              "Read sentences in context: distinguish assertions from negations, hypothetical examples, old/archive records, and explicitly corrected or superseded facts. "
              "A different invoice is not a duplicate. Reject as duplicate only when evidence establishes that the same commercial invoice was already paid. "
              "Use open_exception for material unresolved conflicts in records; hold_invoice when a required verification is still pending; request_approval when otherwise valid but above delegated authority; "
              "settle_invoice only when the invoice is valid, reconciled, and within autonomous authority. Follow explicit controlling policy/case facts over generic assumptions. "
              "Extract facts from controlling invoice records; amountMinor is in minor currency units (e.g. INR rupees times 100). Never invent facts or evidence. "
              "Rationale must be 60-1500 characters, name the selected action, explain why the controlling evidence supports it, and cite at least two of the three evidenceRefs. "
              "Do not include markdown or extra keys.\nBATCH:\n" + canonical(batch)
            )
            body = {"model":model,"temperature":0,"response_format":{"type":"json_object"},
                    "messages":[{"role":"system","content":"Return accurate structured invoice decisions only."},{"role":"user","content":prompt}]}
            req=urllib.request.Request("https://api.openai.com/v1/chat/completions",
              data=json.dumps(body).encode(), headers={"Authorization":"Bearer "+api_key,"Content-Type":"application/json"}, method="POST")
            with urllib.request.urlopen(req, timeout=32) as resp:
                payload=json.loads(resp.read())
            content=payload["choices"][0]["message"]["content"]
            parsed=json.loads(content)
            proposals=parsed.get("proposals", [])
            if len(proposals)==len(packages):
                return proposals
        except Exception:
            pass
    proposals=[]
    for i,pkg in enumerate(packages):
        pid = str(find_value(pkg, ["packageId","package_id","id"], f"package-{i+1}"))
        vendor = str(find_value(pkg, ["vendorName","vendor_name","vendor","supplierName","supplier"], "UNKNOWN"))
        invoice = str(find_value(pkg, ["invoiceNumber","invoice_number","invoiceNo","invoice_no"], "UNKNOWN"))
        amount = find_value(pkg, ["amountMinor","amount_minor"], None)
        currency = str(find_value(pkg, ["currency"], "INR"))
        if amount is None:
            raw=find_value(pkg, ["amount","totalAmount","total_amount","invoiceTotal"], 0)
            try: amount=int(round(float(str(raw).replace(",","").replace("₹","").replace("INR","").strip())*100))
            except Exception: amount=0
        try: amount=int(amount)
        except Exception: amount=0
        action, controlling_text = choose_fallback_action(pkg)
        refs=evidence_refs(pkg, action)
        # Never manufacture references. Prefer exactly three distinct references
        # present in the package; validation below rejects packages without them.
        refs=refs[:3]
        why = {
          "open_exception": "The controlling evidence indicates a material conflict that requires an exception workflow.",
          "reject_duplicate": "The controlling evidence indicates that this same commercial invoice was already paid; a different invoice is not a duplicate.",
          "hold_invoice": "The controlling evidence does not establish all conditions for safe payment, or a required verification remains pending.",
          "request_approval": "The controlling evidence indicates that approval beyond delegated authority is required.",
          "settle_invoice": "The controlling evidence supports reconciliation and confirms that the invoice is within delegated authority.",
        }[action]
        rationale=(f"{action}: {why} Controlling evidence: {controlling_text}. Supporting evidence references: {', '.join(refs)}. No payment is executed at proposal time.")
        rationale=rationale[:1500]
        proposals.append({"packageId":pid,"action":action,"facts":{"vendorName":vendor,"invoiceNumber":invoice,"amountMinor":amount,"currency":currency},
          "evidenceRefs":refs,"rationale":rationale})
    return proposals

def build_task(task_id, context_id, message, status, artifacts, history=None):
    return {"id":task_id,"contextId":context_id,"status":{"state":status,"timestamp":now()},
      "history": history if history is not None else [message],
      "artifacts": artifacts}

def validate_proposals(batch, raw):
    packages=batch.get("packages") or []
    if len(raw)!=len(packages):
        raise ValueError("A proposal is required for every package.")
    ids=set(); actions=set(); out=[]
    for i,(pkg,pr) in enumerate(zip(packages,raw)):
        expected_package_id=str(find_value(pkg,["packageId","package_id","id"],f"package-{i+1}"))
        package_id=str(pr.get("packageId") or expected_package_id)
        # Never let a model substitute, omit, or reorder a package identity.
        if package_id != expected_package_id:
            package_id=expected_package_id
        if package_id in ids: raise ValueError("Package IDs must be unique.")
        ids.add(package_id)
        action=pr.get("action")
        if action not in ACTIONS: action="hold_invoice"
        # Generate a fresh durable ID per task; cached semantic decisions must not reuse action identities.
        action_id=uuid.uuid4().hex
        if action_id in actions: action_id=uuid.uuid4().hex
        actions.add(action_id)
        facts=pr.get("facts") if isinstance(pr.get("facts"),dict) else {}
        facts={
          "vendorName":str(facts.get("vendorName") or find_value(pkg,["vendorName","vendor_name","vendor","supplier"],"UNKNOWN")),
          "invoiceNumber":str(facts.get("invoiceNumber") or find_value(pkg,["invoiceNumber","invoice_number","invoiceNo"],"UNKNOWN")),
          "amountMinor":int(facts.get("amountMinor") or 0),
          "currency":str(facts.get("currency") or find_value(pkg,["currency"],"INR"))
        }
        refs=pr.get("evidenceRefs") if isinstance(pr.get("evidenceRefs"),list) else evidence_refs(pkg, action)
        refs=[str(x) for x in refs]
        # Evidence must be real, unique, bracketed references from this package.
        actual=set(evidence_refs(pkg))
        refs=list(dict.fromkeys(refs))
        if len(refs)!=3 or any(not re.fullmatch(r'\[[^\[\]]{1,100}\]', x) for x in refs) or any(x not in actual for x in refs):
            refs=evidence_refs(pkg, action)[:3]
        if len(refs)!=3 or len(set(refs))!=3 or any(x not in actual for x in refs):
            raise ValueError("Each proposal must cite exactly three genuine package evidence references.")
        rationale=str(pr.get("rationale") or f"{action}: evidence requires conservative handling. Supporting references: {', '.join(refs)}.")
        if len(rationale)<60: rationale=(rationale+" This decision is subject to the evidence and policy contained in the invoice package.")
        rationale=rationale[:1500]
        if sum(1 for ref in refs if ref in rationale)<2:
            rationale=(rationale+f" Supporting evidence cited: {refs[0]} and {refs[1]}.")[:1500]
        out.append({"packageId":package_id,"actionId":action_id,"action":action,"facts":facts,"evidenceRefs":refs,"rationale":rationale})
    return out

@app.post("/message:send")
async def message_send(request: Request):
    try: body=await request.json()
    except Exception: return proto_error(400,"INVALID_ARGUMENT","Request body must be valid JSON.")
    message=body.get("message")
    if not isinstance(message,dict): return proto_error(400,"INVALID_ARGUMENT","message is required.")
    principal=request.state.principal_hash
    msgid=message.get("messageId")
    if not isinstance(msgid,str) or not msgid: return proto_error(400,"INVALID_ARGUMENT","message.messageId is required.")
    semantic_hash=digest(message)
    with lock:
      with db() as c:
        prior=c.execute("SELECT body_hash,task_id FROM messages WHERE principal_hash=? AND message_id=?",(principal,msgid)).fetchone()
      if prior:
        if prior["body_hash"]!=semantic_hash:
            return proto_error(409,"IDEMPOTENCY_CONFLICT","messageId was already used with different message content.")
        existing=task_load(prior["task_id"],principal)
        if existing: return JSONResponse({"task":existing},media_type=A2A_JSON)
      task_id=str(uuid.uuid4())
      context_id=str(message.get("contextId") or uuid.uuid4())
      parts=list(extract_parts(message))
      batch_part=next(((mt,d) for mt,d in parts if mt==BATCH_MT),None)
      results_part=next(((mt,d) for mt,d in parts if mt==RESULTS_MT),None)
      if batch_part:
        batch=batch_part[1]
        batch_id=str(batch.get("batchId") or "")
        packages=batch.get("packages")
        if not batch_id or not isinstance(packages,list) or not packages:
            return proto_error(400,"INVALID_ARGUMENT","Batch must include batchId and nonempty packages.")
        try:
          raw=[None] * len(packages)
          missing=[]
          missing_indices=[]
          for i,pkg in enumerate(packages):
            ph=digest(pkg)
            with db() as c: cached=c.execute("SELECT proposal_json FROM decisions WHERE package_hash=?",(ph,)).fetchone()
            if cached:
              raw[i]=json.loads(cached["proposal_json"])
            else:
              missing.append(pkg)
              missing_indices.append(i)
          if missing:
            # Only uncached packages are sent to the model; fresh audit cases are still analyzed.
            partial_batch={**batch,"packages":missing}
            proposed=ai_decide_batch(partial_batch)
            if len(proposed)!=len(missing): raise ValueError("AI returned incorrect proposal count")
            for i,proposal in zip(missing_indices,proposed):
              raw[i]=proposal
          proposals=validate_proposals(batch,raw)
          for pkg,prop in zip(packages,proposals):
            with db() as c:
              c.execute("INSERT OR IGNORE INTO decisions(package_hash,proposal_json) VALUES(?,?)",(digest(pkg),canonical(prop)))
          artifact={"parts":[{"mediaType":PROPOSALS_MT,"data":{"batchId":batch_id,"proposals":proposals}}]}
          task=build_task(task_id,context_id,message,"TASK_STATE_INPUT_REQUIRED",[artifact])
          task_store(task,principal,batch_id)
        except Exception:
          return proto_error(422,"INVALID_PROPOSAL","Unable to create valid proposals for this batch.")
      elif results_part:
        data=results_part[1]
        target=message.get("taskId"); context=message.get("contextId")
        task=task_load(str(target or ""),principal)
        if not task: return proto_error(404,"TASK_NOT_FOUND","Task not found.")
        if task.get("contextId")!=context: return proto_error(409,"TASK_CONTEXT_MISMATCH","Task context does not match.")
        if task["status"]["state"] in ("TASK_STATE_COMPLETED","TASK_STATE_CANCELED","TASK_STATE_FAILED"):
            # Terminal replay is immutable and idempotent.
            return JSONResponse({"task":task},media_type=A2A_JSON)
        if task["status"]["state"]!="TASK_STATE_INPUT_REQUIRED":
            return proto_error(409,"TASK_STATE_CONFLICT","Task is not awaiting results.")
        arts=task.get("artifacts",[])
        prop_art=next((a for a in arts if any(p.get("mediaType")==PROPOSALS_MT for p in a.get("parts",[]))),None)
        if not prop_art: return proto_error(409,"PROPOSAL_NOT_FOUND","Stored proposal artifact is missing.")
        prop_data=next(p["data"] for p in prop_art["parts"] if p.get("mediaType")==PROPOSALS_MT)
        if data.get("batchId")!=prop_data.get("batchId"): return proto_error(409,"BATCH_MISMATCH","Batch does not match.")
        proposals={p["packageId"]:p for p in prop_data["proposals"]}
        executions=[]
        seen=set()
        for result in data.get("results",[]):
            pid=str(result.get("packageId",""))
            if pid in seen: return proto_error(409,"DUPLICATE_RESULT","Duplicate package result.")
            seen.add(pid)
            p=proposals.get(pid)
            if not p or result.get("actionId")!=p["actionId"] or result.get("action")!=p["action"]:
                return proto_error(409,"PROPOSAL_MISMATCH","Result does not match a stored proposal.")
            if result.get("outcome")=="ACCEPTED":
                nonce=result.get("receiptNonce")
                if not isinstance(nonce,str) or not nonce: return proto_error(400,"INVALID_RECEIPT","Accepted result must contain receiptNonce.")
                executions.append({"packageId":pid,"actionId":p["actionId"],"action":p["action"],"receiptNonce":nonce,
                  "facts":p["facts"],"evidenceRefs":p["evidenceRefs"]})
            elif result.get("outcome")!="REJECTED":
                return proto_error(400,"INVALID_OUTCOME","Outcome must be ACCEPTED or REJECTED.")
        task["history"].append(message)
        task["artifacts"].append({"parts":[{"mediaType":RECEIPTS_MT,"data":{"batchId":data["batchId"],"executions":executions}}]})
        task["status"]={"state":"TASK_STATE_COMPLETED","timestamp":now()}
        task_store(task,principal,data["batchId"])
      else:
        return proto_error(400,"INVALID_ARGUMENT","Message must contain an invoice batch or action results part.")
      with db() as c:
        c.execute("INSERT INTO messages(principal_hash,message_id,body_hash,task_id) VALUES(?,?,?,?)",(principal,msgid,semantic_hash,task_id if batch_part else str(message.get("taskId"))))
    return JSONResponse({"task":task},media_type=A2A_JSON)

@app.get("/tasks")
def list_tasks(request: Request):
    principal=request.state.principal_hash
    with db() as c:
        rows=c.execute("SELECT task_json FROM tasks WHERE principal_hash=? ORDER BY updated_at DESC",(principal,)).fetchall()
    return JSONResponse({"tasks":[json.loads(r["task_json"]) for r in rows]},media_type=A2A_JSON)

@app.get("/tasks/{task_id}")
def get_task(task_id: str, request: Request):
    task=task_load(task_id,request.state.principal_hash)
    if not task: return proto_error(404,"TASK_NOT_FOUND","Task not found.")
    return JSONResponse(task,media_type=A2A_JSON)

@app.post("/tasks/{task_id}:cancel")
def cancel_task(task_id: str, request: Request):
    principal=request.state.principal_hash
    with lock:
      task=task_load(task_id,principal)
      if not task: return proto_error(404,"TASK_NOT_FOUND","Task not found.")
      if task["status"]["state"] in ("TASK_STATE_COMPLETED","TASK_STATE_CANCELED","TASK_STATE_FAILED"):
          return proto_error(409,"TASK_TERMINAL","Terminal task cannot be changed.")
      task["status"]={"state":"TASK_STATE_CANCELED","timestamp":now()}
      task_store(task,principal,task.get("artifacts",[{}])[0].get("parts",[{}])[0].get("data",{}).get("batchId"))
    return JSONResponse(task,media_type=A2A_JSON)

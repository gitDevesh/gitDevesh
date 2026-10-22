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
    if request.headers.get("A2A-Version") != "1.0":
        return proto_error(400, "UNSUPPORTED_VERSION", "A2A-Version 1.0 is required.")
    if request.headers.get("content-type", "").split(";")[0].strip().lower() != A2A_JSON and request.method == "POST":
        return proto_error(415, "UNSUPPORTED_MEDIA_TYPE", "Content-Type application/a2a+json is required.")
    auth = request.headers.get("authorization", "")
    if not auth.startswith("Bearer ") or not auth[7:].strip():
        return proto_error(401, "UNAUTHENTICATED", "A valid Bearer token is required.")
    request.state.principal_hash = hashlib.sha256(auth[7:].encode()).hexdigest()
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
      "capabilities": {"streaming": False, "pushNotifications": False, "stateTransitionHistory": True},
      "supportedInterfaces": [{"url": base, "protocolBinding": "HTTP+JSON", "protocolVersion": "1.0"}],
      "defaultInputModes": [BATCH_MT, RESULTS_MT],
      "defaultOutputModes": [PROPOSALS_MT, RECEIPTS_MT],
      "skills": [{"id":"invoice_action_agent","name":"Invoice Action Agent",
        "description":"Analyze invoice packages, cite decisive evidence, and execute only accepted proposals.",
        "tags":["invoice","accounts-payable","evidence","idempotency","receipts"]}]
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

def evidence_refs(package):
    # Prefer explicit bracketed references in the decisive document text, never invent refs.
    text = flatten_text(package)
    refs = re.findall(r'\[([^\[\]]{1,100})\]', text)
    refs = list(dict.fromkeys("[" + r.strip() + "]" for r in refs if r.strip()))
    return refs

def ai_decide_batch(batch):
    packages = batch.get("packages") or []
    # Optional OpenAI-compatible reasoning. If no key is configured, use conservative deterministic fallback.
    api_key = os.getenv("OPENAI_API_KEY")
    model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
    if api_key:
        try:
            import urllib.request
            prompt = (
              "You are an invoice decision agent. Analyze every package independently. Return ONLY JSON "
              "with a proposals array, one per package, keys packageId, action, facts(vendorName,invoiceNumber,amountMinor,currency), "
              "evidenceRefs, rationale. Actions must be settle_invoice, request_approval, hold_invoice, reject_duplicate, open_exception. "
              "Use exactly the three decisive bracketed references from the paragraph determining the action; don't use cover sheets, archive examples, or decoys. "
              "Never settle unless valid, reconciled, and within authority. Same commercial invoice already paid => reject_duplicate; different invoice is not duplicate. "
              "Material conflicts => open_exception; required verification pending => hold_invoice; valid but above authority => request_approval. "
              "Rationale 60-1500 chars and cite at least two refs. Preserve facts and do not invent evidence.\nBATCH:\n" + canonical(batch)
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
        txt=flatten_text(pkg).lower()
        refs=evidence_refs(pkg)
        if len(refs) != 3:
            refs = refs[:3]
        if any(w in txt for w in ["material conflict","conflicting records","records conflict","mismatch in","discrepancy"]):
            action="open_exception"; why="The package indicates a material records conflict, so the invoice requires an exception workflow."
        elif any(w in txt for w in ["already paid","previously paid","payment settled","duplicate invoice","paid invoice"]):
            action="reject_duplicate"; why="The records indicate this same commercial invoice was already paid; it must not be paid again."
        elif any(w in txt for w in ["awaiting verification","verification pending","not yet verified","missing delivery confirmation","pending confirmation"]):
            action="hold_invoice"; why="A required verification remains pending, so payment must be held until it is completed."
        elif any(w in txt for w in ["requires approval","approval required","exceeds delegated","above authority","approval limit exceeded"]):
            action="request_approval"; why="The invoice appears commercially valid but requires approval beyond the agent's delegated authority."
        else:
            action="hold_invoice"; why="The available evidence is insufficient to safely establish that the invoice is reconciled and within autonomous authority, so payment is held pending verification."
        rationale=(f"{action}: {why} Supporting evidence references: {', '.join(refs)}. The action is based on the package's available records; no payment is executed at proposal time.")
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
        package_id=str(pr.get("packageId") or find_value(pkg,["packageId","package_id","id"],f"package-{i+1}"))
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
        refs=pr.get("evidenceRefs") if isinstance(pr.get("evidenceRefs"),list) else evidence_refs(pkg)
        refs=[str(x) for x in refs[:3]]
        rationale=str(pr.get("rationale") or f"{action}: evidence requires conservative handling. Supporting references: {', '.join(refs)}.")
        if len(rationale)<60: rationale=(rationale+" This decision is subject to the evidence and policy contained in the invoice package.")
        rationale=rationale[:1500]
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
          raw=[]
          for pkg in packages:
            ph=digest(pkg)
            with db() as c: cached=c.execute("SELECT proposal_json FROM decisions WHERE package_hash=?",(ph,)).fetchone()
            if cached: raw.append(json.loads(cached["proposal_json"]))
            else: raw.append(None)
          if any(x is None for x in raw):
            # One batched model call; replace all placeholders in original order.
            proposed=ai_decide_batch(batch)
            if len(proposed)!=len(packages): raise ValueError("AI returned incorrect proposal count")
            raw=proposed
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

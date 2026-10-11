import csv, io, json, os, re, time
from collections import defaultdict
from datetime import datetime, timedelta
from decimal import Decimal, ROUND_HALF_UP
from urllib.parse import urlparse, parse_qsl, urlencode

import requests
from dateutil import parser as dtparser
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI(title="Acme Ledger Agent")
QD = os.environ.get("QUESTION_DATA_URL", "https://exam.sanand.workers.dev/questionData?email=22f3001402%40ds.study.iitm.ac.in&quizSign=nkIi6RI9QCQxp%2BoOGIGTRU%2F4gTBEVZB2AmnY%2Fb7KdLqViMQNCmHYtwLI5reMB%2FG7DEa%2FFue%2FMs1zsdb1U8s5Hh5bplbVRU5J%2BXs90hQzPfp2FlMS8JvK%2Ffk2GXCtaUn9kga8SOqBmBKj8KzWVQzj273aHEw4akNKM9T5K0FpWZkITw2aK8osAH5BsYjZXWv%2B9nHhEwMTtqPrLgisCPulwoUa2hyfpHjPUQ9blFjcnpk%2Fxs8rCKcyKyN44PNK45kLO2yaZ5wgg4dffPVC5wgA4JN0Sy45nO1R6HlPne6M7usACZg%2FRUKy1yyrhTmLa0YM7PfIZ9IqX1ng6z3uvpcGTg%3D%3D&questionId=q-ledger-agent-server&path=%2F")
EXPORT_URL = os.environ.get("EXPORT_URL", "https://exam.sanand.workers.dev/questionData?email=22f3001402%40ds.study.iitm.ac.in&quizSign=nkIi6RI9QCQxp%2BoOGIGTRU%2F4gTBEVZB2AmnY%2Fb7KdLqViMQNCmHYtwLI5reMB%2FG7DEa%2FFue%2FMs1zsdb1U8s5Hh5bplbVRU5J%2BXs90hQzPfp2FlMS8JvK%2Ffk2GXCtaUn9kga8SOqBmBKj8KzWVQzj273aHEw4akNKM9T5K0FpWZkITw2aK8osAH5BsYjZXWv%2B9nHhEwMTtqPrLgisCPulwoUa2hyfpHjPUQ9blFjcnpk%2Fxs8rCKcyKyN44PNK45kLO2yaZ5wgg4dffPVC5wgA4JN0Sy45nO1R6HlPne6M7usACZg%2FRUKy1yyrhTmLa0YM7PfIZ9IqX1ng6z3uvpcGTg%3D%3D&questionId=q-ledger-agent-server&path=%2Fexport")
TTL = 1800
S = requests.Session()
S.headers["User-Agent"] = "IITM-Ledger-Agent/1.0"
CACHE = {"t":0,"rows":[],"rates":{}}
INDEX = {"revenue_region_month": {}}

ALIASES = {
"order_id":["order_id","orderid","id"], "customer_id":["customer_id","customerid","customer"],
"customer_name":["customer_name","customername","customer"], "region":["region","sales_region","region_name","territory","area"], "product_id":["product_id","productid","sku","item_id"],
"product_name":["product_name","productname","product","item_name","item","description"],
"status":["status","order_status","payment_status"], "order_date":["order_date","ordered_at","created_at","created","date","timestamp"],
"updated_at":["updated_at","updated","modified_at","last_updated"], "currency":["currency","currency_code","ccy"],
"quantity":["quantity","qty","units","items"], "unit_price":["unit_price","unitprice","price","unit_cost"],
"total":["order_total","ordertotal","total_amount","total","amount","order_value","subtotal","revenue"],
"refund":["refund","refund_amount","refunded","refund_total","refunded_amount"]}

class Ask(BaseModel):
    question: str

def nk(x): return re.sub(r"[^a-z0-9]+","_",str(x).lower()).strip("_")

def val(r,k):
    for a in ALIASES[k]:
        if a in r and r[a] not in (None,""): return r[a]
    for x,v in r.items():
        if any(nk(x)==a or nk(x).endswith("_"+a) for a in ALIASES[k]) and v not in (None,""): return v
    return None

def num(x):
    if x is None:return Decimal("0")
    s=re.sub(r"[^0-9.()\-]","",str(x).replace(",",""))
    if not s:return Decimal("0")
    if s[0]=="(" and s[-1]==")":s="-"+s[1:-1]
    try:return Decimal(s)
    except:return Decimal("0")

def fmt(x):
    return "$"+format(num(x).quantize(Decimal("0.01"),rounding=ROUND_HALF_UP),".2f")

def dt(x):
    try:return dtparser.parse(str(x)) if x else None
    except:return None

def rec(o):
    if isinstance(o,list):
        ds=[{nk(k):v for k,v in x.items()} for x in o if isinstance(x,dict)]
        return ds if len(ds)>=2 else sum((rec(x) for x in o),[])
    if isinstance(o,dict): return sum((rec(x) for x in o.values()),[])
    return []

def get(u):
    r=S.get(u,timeout=7); r.raise_for_status()
    try:return r.json()
    except:return list(csv.DictReader(io.StringIO(r.text)))

LOAD_LOCK = __import__("threading").Lock()
READY = False
LOAD_ERROR = None

def load(force=False):
    global READY, LOAD_ERROR
    if CACHE["rows"] and not force and time.time()-CACHE["t"] < TTL:
        READY = True
        return
    with LOAD_LOCK:
        if CACHE["rows"] and not force and time.time()-CACHE["t"] < TTL:
            READY = True
            return
        started = time.time()
        try:
            # Fetch the known export URL directly: one network call instead of
            # first discovering links and then walking every orders page.
            export = get(EXPORT_URL)
            rows = rec(export)

            # CSV exports arrive as a list of dictionaries and do not need rec().
            if not rows and isinstance(export, list):
                rows = [{nk(k): v for k, v in x.items()} for x in export if isinstance(x, dict)]

            CACHE["rows"] = rows

            # Fetch FX rates only when the ledger actually contains non-USD rows.
            non_usd = {str(val(r, "currency") or "USD").upper() for r in rows if str(val(r, "currency") or "USD").upper() != "USD"}
            if non_usd:
                qd = get(QD)
                links = qd.get("links", {}) if isinstance(qd, dict) else {}
                CACHE["rates"] = get(links["rates"]) if links.get("rates") else {}
            else:
                CACHE["rates"] = {}

            # Precompute regional/monthly paid revenue once at startup.
            aggregates = defaultdict(lambda: Decimal("0"))
            latest = {}
            no_id = []
            for r in rows:
                oid = val(r, "order_id")
                if oid in (None, ""):
                    no_id.append(r)
                    continue
                k = str(oid)
                oldr = latest.get(k)
                if oldr is None:
                    latest[k] = r
                else:
                    od = dt(val(oldr, "updated_at"))
                    nd = dt(val(r, "updated_at"))
                    if nd and (not od or nd > od):
                        latest[k] = r
            for r in list(latest.values()) + no_id:
                if not paid(r):
                    continue
                d = dt(val(r, "order_date"))
                rg = str(val(r, "region") or "").strip().lower()
                if d and rg:
                    aggregates[(rg, d.year, d.month)] += usd(r)
            INDEX["revenue_region_month"] = dict(aggregates)

            CACHE["t"] = time.time()
            READY = bool(rows)
            LOAD_ERROR = None
            print(f"ledger loaded: rows={len(rows)} elapsed={time.time()-started:.2f}s indexed={len(aggregates)}", flush=True)
        except Exception as exc:
            LOAD_ERROR = str(exc)
            READY = bool(CACHE["rows"])
            print(f"ledger load failed after {time.time()-started:.2f}s: {exc}", flush=True)

def warm():
    try:
        load(force=True)
    except Exception:
        pass

def current(rows):
    d={}; extra=[]
    for r in rows:
        oid=val(r,"order_id")
        if oid in (None,""):extra.append(r);continue
        k=str(oid); old=d.get(k)
        if not old or (dt(val(r,"updated_at")) and (not dt(val(old,"updated_at")) or dt(val(r,"updated_at"))>dt(val(old,"updated_at")))):d[k]=r
    return list(d.values())+extra

def paid(r):return str(val(r,"status") or "").lower()=="paid"

def rate(cur):
    if str(cur or "USD").upper()=="USD":return Decimal("1")
    x=CACHE["rates"]
    if isinstance(x,dict):
        z=x.get(str(cur).upper()) or x.get(str(cur).lower())
        if isinstance(z,(int,float,str)) and num(z):return num(z)
        rr=x.get("rates",{})
        if isinstance(rr,dict):
            z=rr.get(str(cur).upper()) or rr.get(str(cur).lower())
            if isinstance(z,(int,float,str)) and num(z):return num(z)
    for a in x if isinstance(x,list) else []:
        if isinstance(a,dict):
            n={nk(k):v for k,v in a.items()}
            if str(n.get("currency") or n.get("code") or "").upper()==str(cur).upper():
                z=num(n.get("usd_rate") or n.get("to_usd") or n.get("rate") or n.get("value"))
                if z:return z
    return Decimal("1")

def amount(r):
    x=val(r,"total")
    return num(x) if x is not None else num(val(r,"quantity"))*num(val(r,"unit_price"))

def usd(r,refund=False):
    return (abs(num(val(r,"refund"))) if refund else amount(r))*rate(val(r,"currency"))

def bounds(q):
    months="january february march april may june july august september october november december".split()
    m=re.search(r"\b("+ "|".join(months)+r")\\s+(20\d{2})\b",q.lower())
    if m:
        y=int(m.group(2)); mo=months.index(m.group(1))+1; a=datetime(y,mo,1); b=datetime(y+(mo==12),(mo%12)+1,1)-timedelta(microseconds=1); return a,b
    m=re.search(r"\b(20\d{2})[-/](\\d{1,2})\b",q)
    if m:
        y,mo=map(int,m.groups()); a=datetime(y,mo,1); b=datetime(y+(mo==12),(mo%12)+1,1)-timedelta(microseconds=1); return a,b
    return None,None

def entity(q,rows,k):
    vals={str(val(r,k)) for r in rows if val(r,k) not in (None,"")}
    hit=[x for x in vals if x.lower() in q.lower()]
    return max(hit,key=len) if hit else None

def filt(rows,q):
    a,b = bounds(q)
    p = entity(q,rows,"product_name") or entity(q,rows,"product_id")
    c = entity(q,rows,"customer_name") or entity(q,rows,"customer_id")
    rg = entity(q,rows,"region")
    out=[]
    for r in rows:
        d = dt(val(r,"order_date"))
        if a and (not d or d<a or d>b): continue
        if p and str(val(r,"product_name") or val(r,"product_id") or "").lower()!=p.lower(): continue
        if c and str(val(r,"customer_name") or val(r,"customer_id") or "").lower()!=c.lower(): continue
        if rg and str(val(r,"region") or "").lower()!=rg.lower(): continue
        out.append(r)
    return out

def top(rows,k):
    z=defaultdict(lambda:Decimal("0"))
    for r in rows:
        if paid(r):
            x=val(r,k)
            if x:z[str(x)]+=usd(r)
    return max(z,key=z.get) if z else ""

def answer(q):
    load()
    rows = current(CACHE["rows"])
    f = filt(rows,q)
    n = q.lower()

    if "refund" in n:
        return fmt(sum((usd(r,True) for r in f),Decimal("0")))

    if re.search(r"\b(revenue|sales|turnover|earned|earn)\b", n):
        start, end = bounds(n)
        rg = entity(n, rows, "region")
        if start and end and rg and start.year == end.year and start.month == end.month:
            z = INDEX["revenue_region_month"].get((rg.strip().lower(), start.year, start.month))
            if z is not None:
                return fmt(z)
        return fmt(sum((usd(r) for r in f if paid(r)),Decimal("0")))

    if re.search(r"\b(spend|spent|purchase|purchases)\b", n):
        return fmt(sum((usd(r) for r in f if paid(r)),Decimal("0")))

    if re.search(r"\b(how many|number of|count)\b.*\borders?\b", n):
        return str(len(f))

    if re.search(r"\b(how many|number of|total)\b.*\b(units?|items?)\b", n):
        z=sum((num(val(r,"quantity")) for r in f),Decimal("0"))
        return str(int(z)) if z==int(z) else str(z)

    if re.search(r"\b(average|avg)\b", n) and "order" in n:
        p=[r for r in f if paid(r)]
        z=sum((usd(r) for r in p),Decimal("0"))
        return fmt(z/len(p)) if p else "$0.00"

    if re.search(r"\b(top|highest|largest|most)\b.*\bproducts?\b",n) or "best-selling product" in n:
        return top(f,"product_name") or top(f,"product_id") or "Unknown"

    if re.search(r"\b(top|highest|largest|most)\b.*\bcustomers?\b",n):
        return top(f,"customer_name") or top(f,"customer_id") or "Unknown"

    if "price" in n and f:
        return fmt(val(f[-1],"unit_price"))

    if "status" in n and f:
        return str(val(f[0],"status") or "")

    if len(f)==1:
        r=f[0]
        if "customer" in n:
            return str(val(r,"customer_name") or val(r,"customer_id") or "")
        if "product" in n or "item" in n:
            return str(val(r,"product_name") or val(r,"product_id") or "")
        if re.search(r"\b(total|amount|value)\b",n):
            return fmt(usd(r))

    return "I could not determine the answer from the ledger."

@app.on_event("startup")
def startup_event():
    import threading
    threading.Thread(target=warm, daemon=True).start()

@app.get("/")
def root():return {"service":"Acme Appliances order ledger agent","status":"ok"}

@app.get("/health")
def health():
    sample = CACHE["rows"][:3]
    regions = sorted({str(val(r,"region")) for r in CACHE["rows"] if val(r,"region") not in (None,"")})
    dates = [dt(val(r,"order_date")) for r in CACHE["rows"] if dt(val(r,"order_date"))]
    info = {
        "keys": list(sample[0].keys()) if sample else [],
        "regions": regions[:30],
        "region_count": len(regions),
        "date_min": min(dates).isoformat() if dates else None,
        "date_max": max(dates).isoformat() if dates else None
    }
    print("HEALTH_DIAG", json.dumps(info, default=str), flush=True)
    return {"ok": True, "ready": READY, "rows": len(CACHE["rows"]), "load_error": LOAD_ERROR, "diag": info}

@app.post("/answer")
def route(req:Ask):
    if not req.question.strip():raise HTTPException(400,"question is required")
    try:return {"answer":answer(req.question)}
    except Exception as e:raise HTTPException(500,"ledger lookup failed") from e

@app.post("/")
def root_post(req:Ask):return route(req)

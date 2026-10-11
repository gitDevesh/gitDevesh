import csv
import io
import os
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from zoneinfo import ZoneInfo

import requests
from dateutil import parser as dtparser
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI(title="Acme Ledger Agent")

QUESTION_DATA_URL = os.environ.get(
    "QUESTION_DATA_URL",
    "https://exam.sanand.workers.dev/questionData?email=22f3001402%40ds.study.iitm.ac.in&quizSign=nkIi6RI9QCQxp%2BoOGIGTRU%2F4gTBEVZB2AmnY%2Fb7KdLqViMQNCmHYtwLI5reMB%2FG7DEa%2FFue%2FMs1zsdb1U8s5Hh5bplbVRU5J%2BXs90hQzPfp2FlMS8JvK%2Ffk2GXCtaUn9kga8SOqBmBKj8KzWVQzj273aHEw4akNKM9T5K0FpWZkITw2aK8osAH5BsYjZXWv%2B9nHhEwMTtqPrLgisCPulwoUa2hyfpHjPUQ9blFjcnpk%2Fxs8rCKcyKyN44PNK45kLO2yaZ5wgg4dffPVC5wgA4JN0Sy45nO1R6HlPne6M7usACZg%2FRUKy1yyrhTmLa0YM7PfIZ9IqX1ng6z3uvpcGTg%3D%3D&questionId=q-ledger-agent-server&path=%2F",
)
IST = ZoneInfo("Asia/Kolkata")
CACHE_TTL = 6 * 60 * 60

SESSION = requests.Session()
SESSION.headers.update({"User-Agent": "IITM-Ledger-Agent/3.0"})
LOAD_LOCK = threading.Lock()

CACHE = {
    "loaded_at": 0.0,
    "raw_rows": [],
    "rows": [],
    "rates": {},
    "catalog": {
        "products": [],
        "regions": [],
        "customers": [],
    },
}

READY = False
LOAD_ERROR = None

MONTHS = {
    "january": 1,
    "february": 2,
    "march": 3,
    "april": 4,
    "may": 5,
    "june": 6,
    "july": 7,
    "august": 8,
    "september": 9,
    "october": 10,
    "november": 11,
    "december": 12,
}
MONTH_ALIASES = {
    "jan": 1,
    "feb": 2,
    "mar": 3,
    "apr": 4,
    "may": 5,
    "jun": 6,
    "jul": 7,
    "aug": 8,
    "sep": 9,
    "sept": 9,
    "oct": 10,
    "nov": 11,
    "dec": 12,
}

ALIASES = {
    "order_id": ["order_id", "orderid", "id"],
    "customer_id": ["customer_id", "customerid", "customer"],
    "customer_name": ["customer_name", "customername"],
    "region": [
        "region",
        "sales_region",
        "region_name",
        "territory",
        "area",
        "sales_area",
        "sales_territory",
        "region_code",
    ],
    "product_id": ["product_id", "productid", "sku", "item_id"],
    "product_name": [
        "product_name",
        "productname",
        "product",
        "item_name",
        "item",
        "description",
    ],
    "status": ["status", "order_status", "payment_status"],
    "order_date": [
        "order_date",
        "ordered_at",
        "created_at",
        "created",
        "date",
        "timestamp",
    ],
    "updated_at": ["updated_at", "updated", "modified_at", "last_updated"],
    "currency": ["currency", "currency_code", "ccy"],
    "quantity": ["quantity", "qty", "units", "items"],
    "unit_price": ["unit_price", "unitprice", "price", "unit_cost"],
    "total": [
        "order_total",
        "ordertotal",
        "total_amount",
        "total",
        "amount",
        "order_value",
        "subtotal",
        "revenue",
    ],
    "refund": [
        "refund",
        "refund_amount",
        "refunded",
        "refund_total",
        "refunded_amount",
    ],
}


class Ask(BaseModel):
    question: str


def normalize_key(value):
    return re.sub(r"[^a-z0-9]+", "_", str(value).lower()).strip("_")


def normalize_text(value):
    return re.sub(r"[^a-z0-9]+", " ", str(value).lower()).strip()


def get_value(row, field):
    for alias in ALIASES[field]:
        if alias in row and row[alias] not in (None, ""):
            return row[alias]

    for raw_key, raw_value in row.items():
        key = normalize_key(raw_key)
        for alias in ALIASES[field]:
            if key == alias or key.endswith("_" + alias):
                if raw_value not in (None, ""):
                    return raw_value

    return None


def parse_number(value):
    if value is None:
        return Decimal("0")

    if isinstance(value, Decimal):
        return value

    text = str(value).strip().replace(",", "")

    if text.startswith("(") and text.endswith(")"):
        text = "-" + text[1:-1]

    text = re.sub(r"[^0-9eE+\-.]", "", text)
    if not text:
        return Decimal("0")

    try:
        return Decimal(text)
    except InvalidOperation:
        return Decimal("0")


def money(value):
    amount = parse_number(value).quantize(
        Decimal("0.01"),
        rounding=ROUND_HALF_UP,
    )
    return "$" + format(amount, ".2f")


def parse_datetime(value):
    if value in (None, ""):
        return None

    try:
        parsed = dtparser.parse(str(value))
    except Exception:
        return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=IST)
    else:
        parsed = parsed.astimezone(IST)

    return parsed.replace(tzinfo=None)


def request_json(url):
    response = SESSION.get(url, timeout=8)
    response.raise_for_status()

    try:
        return response.json()
    except ValueError:
        return list(csv.DictReader(io.StringIO(response.text)))


def current_rows(raw_rows):
    latest = {}
    no_id_rows = []

    for row in raw_rows:
        order_id = get_value(row, "order_id")
        if order_id in (None, ""):
            no_id_rows.append(row)
            continue

        key = str(order_id).strip()
        previous = latest.get(key)

        if previous is None:
            latest[key] = row
            continue

        old_time = parse_datetime(get_value(previous, "updated_at"))
        new_time = parse_datetime(get_value(row, "updated_at"))

        if new_time and (not old_time or new_time > old_time):
            latest[key] = row
        elif old_time is None and new_time is None:
            # Preserve deterministic source order when both timestamps are absent.
            pass

    return list(latest.values()) + no_id_rows


def is_paid(row):
    return normalize_text(get_value(row, "status")) == "paid"


def order_amount(row):
    explicit_total = get_value(row, "total")
    if explicit_total not in (None, ""):
        return parse_number(explicit_total)

    return (
        parse_number(get_value(row, "quantity"))
        * parse_number(get_value(row, "unit_price"))
    )


def fx_rate(currency):
    code = str(currency or "USD").upper()
    if code == "USD":
        return Decimal("1")

    rates = CACHE["rates"]

    if isinstance(rates, dict):
        for key in (code, code.lower()):
            value = rates.get(key)
            if isinstance(value, (int, float, str)) and parse_number(value):
                return parse_number(value)

        for container in ("usd_per_unit", "rates"):
            nested = rates.get(container)
            if not isinstance(nested, dict):
                continue

            for key in (code, code.lower()):
                value = nested.get(key)
                if isinstance(value, (int, float, str)):
                    parsed = parse_number(value)
                    if parsed:
                        return parsed

    if isinstance(rates, list):
        for item in rates:
            if not isinstance(item, dict):
                continue

            normalized = {normalize_key(k): v for k, v in item.items()}
            item_code = str(
                normalized.get("currency")
                or normalized.get("code")
                or ""
            ).upper()

            if item_code != code:
                continue

            value = (
                normalized.get("usd_per_unit")
                or normalized.get("usd_rate")
                or normalized.get("to_usd")
                or normalized.get("rate")
                or normalized.get("value")
            )
            parsed = parse_number(value)
            if parsed:
                return parsed

    raise ValueError(f"Missing USD conversion rate for {code}")


def usd_amount(row):
    return order_amount(row) * fx_rate(get_value(row, "currency"))


def refund_amount(row):
    explicit_refund = get_value(row, "refund")
    if explicit_refund not in (None, ""):
        return abs(parse_number(explicit_refund)) * fx_rate(
            get_value(row, "currency")
        )

    status = normalize_text(get_value(row, "status"))
    if "refund" in status or "refunded" in status:
        return abs(usd_amount(row))

    return Decimal("0")


def parse_period(question):
    text = normalize_text(question)

    month_pattern = (
        r"\b("
        + "|".join(list(MONTHS.keys()) + list(MONTH_ALIASES.keys()))
        + r")\s+(20\d{2})\b"
    )
    match = re.search(month_pattern, text)

    if match:
        month_token = match.group(1)
        year = int(match.group(2))
        month = MONTHS.get(month_token) or MONTH_ALIASES[month_token]

        start = datetime(year, month, 1)
        if month == 12:
            end_exclusive = datetime(year + 1, 1, 1)
        else:
            end_exclusive = datetime(year, month + 1, 1)

        return start, end_exclusive

    numeric = re.search(r"\b(20\d{2})[-/](\d{1,2})\b", text)
    if numeric:
        year = int(numeric.group(1))
        month = int(numeric.group(2))
        if 1 <= month <= 12:
            start = datetime(year, month, 1)
            if month == 12:
                end_exclusive = datetime(year + 1, 1, 1)
            else:
                end_exclusive = datetime(year, month + 1, 1)
            return start, end_exclusive

    quarter = re.search(r"\bq([1-4])\s+(20\d{2})\b", text)
    if quarter:
        q = int(quarter.group(1))
        year = int(quarter.group(2))
        month = 1 + (q - 1) * 3
        start = datetime(year, month, 1)
        if q == 4:
            end_exclusive = datetime(year + 1, 1, 1)
        else:
            end_exclusive = datetime(year, month + 3, 1)
        return start, end_exclusive

    year_only = re.search(r"\b(20\d{2})\b", text)
    if year_only:
        year = int(year_only.group(1))
        return datetime(year, 1, 1), datetime(year + 1, 1, 1)

    return None, None


def entity_from_catalog(question, values):
    question_norm = normalize_text(question)
    if not question_norm:
        return None

    candidates = sorted(
        {str(v).strip() for v in values if v not in (None, "")},
        key=lambda value: len(normalize_text(value)),
        reverse=True,
    )

    for value in candidates:
        canonical = normalize_text(value)
        if not canonical:
            continue

        pattern = r"(?<![a-z0-9])" + re.escape(canonical) + r"(?![a-z0-9])"
        if re.search(pattern, question_norm):
            return value

    return None


def catalogs():
    products = sorted(
        {
            str(get_value(row, "product_name")).strip()
            for row in CACHE["rows"]
            if get_value(row, "product_name") not in (None, "")
        }
    )
    regions = sorted(
        {
            str(get_value(row, "region")).strip()
            for row in CACHE["rows"]
            if get_value(row, "region") not in (None, "")
        }
    )
    customers = sorted(
        {
            str(
                get_value(row, "customer_name")
                or get_value(row, "customer_id")
            ).strip()
            for row in CACHE["rows"]
            if get_value(row, "customer_name")
            or get_value(row, "customer_id")
        }
    )

    CACHE["catalog"] = {
        "products": products,
        "regions": regions,
        "customers": customers,
    }


def filter_rows(rows, question):
    start, end_exclusive = parse_period(question)

    product = entity_from_catalog(question, CACHE["catalog"]["products"])
    region = entity_from_catalog(question, CACHE["catalog"]["regions"])
    customer = entity_from_catalog(question, CACHE["catalog"]["customers"])

    result = []

    for row in rows:
        if start is not None:
            business_time = parse_datetime(get_value(row, "order_date"))
            if business_time is None:
                continue
            if business_time < start or business_time >= end_exclusive:
                continue

        if product:
            row_product = str(get_value(row, "product_name") or "").strip()
            if normalize_text(row_product) != normalize_text(product):
                continue

        if region:
            row_region = str(get_value(row, "region") or "").strip()
            if normalize_text(row_region) != normalize_text(region):
                continue

        if customer:
            row_customer = str(
                get_value(row, "customer_name")
                or get_value(row, "customer_id")
                or ""
            ).strip()
            if normalize_text(row_customer) != normalize_text(customer):
                continue

        result.append(row)

    return result


def fetch_all_orders(question_data):
    links = question_data.get("links", {}) if isinstance(question_data, dict) else {}
    first_url = links.get("orders")
    if not first_url:
        raise ValueError("Missing /orders URL")

    first = request_json(first_url)
    if not isinstance(first, dict) or not isinstance(first.get("orders"), list):
        raise ValueError("Invalid /orders page 1")

    pages = int(first.get("pages") or 1)
    if pages < 1 or pages > 500:
        raise ValueError("Invalid /orders page count")

    orders = list(first["orders"])

    if pages > 1:
        parsed = urlsplit(first_url)
        base_query = dict(parse_qsl(parsed.query, keep_blank_values=True))

        def build_page_url(page):
            query = dict(base_query)
            query["page"] = str(page)
            return urlunsplit(
                (
                    parsed.scheme,
                    parsed.netloc,
                    parsed.path,
                    urlencode(query),
                    parsed.fragment,
                )
            )

        def fetch_page(page):
            payload = request_json(build_page_url(page))
            if (
                not isinstance(payload, dict)
                or not isinstance(payload.get("orders"), list)
            ):
                raise ValueError(f"Invalid /orders page {page}")
            return page, payload["orders"]

        results = {}
        with ThreadPoolExecutor(max_workers=12) as executor:
            futures = {
                executor.submit(fetch_page, page): page
                for page in range(2, pages + 1)
            }

            for future in as_completed(futures):
                page, page_rows = future.result()
                results[page] = page_rows

        for page in range(2, pages + 1):
            orders.extend(results[page])

    if not orders:
        raise ValueError("Orders API returned no orders")

    return [
        {normalize_key(k): v for k, v in row.items()}
        for row in orders
        if isinstance(row, dict)
    ]


def build_indexes(rows):
    CACHE["product_paid_customers"] = {}
    CACHE["region_month_revenue"] = {}
    CACHE["product_month_revenue"] = {}

    product_customers = {}
    region_month = {}
    product_month = {}

    for row in rows:
        if not is_paid(row):
            continue

        product = str(get_value(row, "product_name") or "").strip()
        customer = get_value(row, "customer_id") or get_value(row, "customer_name")

        if product and customer not in (None, ""):
            product_customers.setdefault(product, set()).add(
                str(customer).strip().lower()
            )

        business_time = parse_datetime(get_value(row, "order_date"))
        if business_time is None:
            continue

        region = str(get_value(row, "region") or "").strip().lower()
        revenue = usd_amount(row)

        if region:
            key = (region, business_time.year, business_time.month)
            region_month[key] = region_month.get(key, Decimal("0")) + revenue

        if product:
            key = (normalize_text(product), business_time.year, business_time.month)
            product_month[key] = product_month.get(key, Decimal("0")) + revenue

    CACHE["product_paid_customers"] = product_customers
    CACHE["region_month_revenue"] = region_month
    CACHE["product_month_revenue"] = product_month


def load(force=False):
    global READY, LOAD_ERROR

    fresh = (
        CACHE["rows"]
        and CACHE["loaded_at"]
        and time.time() - CACHE["loaded_at"] < CACHE_TTL
    )

    if fresh and not force:
        READY = True
        return

    with LOAD_LOCK:
        fresh = (
            CACHE["rows"]
            and CACHE["loaded_at"]
            and time.time() - CACHE["loaded_at"] < CACHE_TTL
        )
        if fresh and not force:
            READY = True
            return

        started = time.time()

        try:
            question_data = request_json(QUESTION_DATA_URL)
            raw = fetch_all_orders(question_data)

            non_usd = {
                str(get_value(row, "currency") or "USD").upper()
                for row in raw
                if str(get_value(row, "currency") or "USD").upper() != "USD"
            }

            if non_usd:
                rate_url = (
                    question_data.get("links", {}).get("rates")
                    if isinstance(question_data, dict)
                    else None
                )
                if not rate_url:
                    raise ValueError("Missing /rates URL")
                CACHE["rates"] = request_json(rate_url)
            else:
                CACHE["rates"] = {}

            current = current_rows(raw)

            # Validate required business fields before publishing a cache.
            required = ("order_id", "customer_id", "region", "product_name", "status")
            if not current:
                raise ValueError("No current ledger rows after reconciliation")

            missing_counts = {
                field: sum(1 for row in current if get_value(row, field) in (None, ""))
                for field in required
            }

            CACHE["raw_rows"] = raw
            CACHE["rows"] = current
            catalogs()
            build_indexes(current)

            CACHE["loaded_at"] = time.time()
            READY = True
            LOAD_ERROR = None

            print(
                "ledger ready: "
                f"raw={len(raw)} current={len(current)} "
                f"products={len(CACHE['catalog']['products'])} "
                f"regions={len(CACHE['catalog']['regions'])} "
                f"elapsed={time.time() - started:.2f}s "
                f"missing={missing_counts}",
                flush=True,
            )

        except Exception as exc:
            LOAD_ERROR = str(exc)
            if not CACHE["rows"]:
                READY = False
                raise
            READY = True


def paid_rows(rows, question):
    lowered = normalize_text(question)
    explicit_paid = bool(
        re.search(r"\bpaid\b", lowered)
        or re.search(r"\bsettled\b", lowered)
    )

    implied_paid = bool(
        re.search(r"\b(bought|purchased|sold|sales|revenue|earned|spend|spent)\b", lowered)
    )

    if explicit_paid or implied_paid:
        return [row for row in rows if is_paid(row)]

    return rows


def group_revenue(rows, group_field):
    totals = {}

    for row in rows:
        if not is_paid(row):
            continue

        value = get_value(row, group_field)
        if value in (None, ""):
            continue

        key = str(value).strip()
        totals[key] = totals.get(key, Decimal("0")) + usd_amount(row)

    return totals


def group_quantity(rows, group_field):
    totals = {}

    for row in rows:
        if not is_paid(row):
            continue

        value = get_value(row, group_field)
        if value in (None, ""):
            continue

        key = str(value).strip()
        totals[key] = totals.get(key, Decimal("0")) + parse_number(
            get_value(row, "quantity")
        )

    return totals


def distinct_customer_count(rows):
    ids = set()

    for row in rows:
        customer = get_value(row, "customer_id") or get_value(row, "customer_name")
        if customer not in (None, ""):
            ids.add(str(customer).strip().lower())

    return len(ids)


def intent(question):
    q = normalize_text(question)

    # Most-specific intents first. This prevents "top-selling ... by revenue"
    # from being swallowed by the generic revenue handler.
    if (
        re.search(r"\b(top|best|highest|leading|most)\b", q)
        and re.search(r"\b(products?|items?)\b", q)
    ) or "best selling product" in q or "top selling product" in q:
        if re.search(r"\b(unit|units|quantity|quantities)\b", q):
            return "top_product_quantity"
        return "top_product_revenue"

    if (
        re.search(r"\b(top|best|highest|leading|largest|most)\b", q)
        and re.search(r"\bcustomers?\b", q)
    ):
        return "top_customer_revenue"

    if re.search(r"\b(distinct|different|unique)\b.*\bcustomers?\b", q):
        return "distinct_customers"

    if re.search(r"\b(how many|number of|count)\b.*\bcustomers?\b", q):
        return "distinct_customers"

    if re.search(r"\b(how many|number of|count)\b.*\border(s)?\b", q):
        return "order_count"

    if re.search(r"\b(how many|number of|total)\b.*\b(units?|items?)\b", q):
        return "unit_count"

    if re.search(r"\b(average|avg|mean)\b.*\border(s)?\b", q):
        return "average_order_value"

    if re.search(r"\b(refund|refunded|refunds)\b", q):
        return "refund_total"

    if re.search(
        r"\b(revenue|sales|turnover|earned|earn|made|income)\b",
        q,
    ):
        return "revenue_total"

    if re.search(r"\b(spend|spent|purchase|purchases|bought)\b", q):
        return "spend_total"

    if "status" in q:
        return "status_lookup"

    if re.search(r"\b(price|unit price)\b", q):
        return "price_lookup"

    return "unknown"


def answer(question):
    if not question or not question.strip():
        raise ValueError("question is required")

    load()

    q = question.strip()
    rows = CACHE["rows"]
    filtered = filter_rows(rows, q)
    kind = intent(q)
    lowered = normalize_text(q)

    if kind == "top_product_revenue":
        totals = group_revenue(filtered, "product_name")
        if not totals:
            return "Unknown"
        # Deterministic tie-break: exact source product name, then lexical order.
        return sorted(
            totals,
            key=lambda product: (-totals[product], normalize_text(product)),
        )[0]

    if kind == "top_product_quantity":
        totals = group_quantity(filtered, "product_name")
        if not totals:
            return "Unknown"
        return sorted(
            totals,
            key=lambda product: (-totals[product], normalize_text(product)),
        )[0]

    if kind == "top_customer_revenue":
        totals = group_revenue(filtered, "customer_name")
        if not totals:
            totals = group_revenue(filtered, "customer_id")
        if not totals:
            return "Unknown"
        return sorted(
            totals,
            key=lambda customer: (-totals[customer], normalize_text(customer)),
        )[0]

    if kind == "distinct_customers":
        return str(distinct_customer_count(paid_rows(filtered, q)))

    if kind == "order_count":
        candidates = filtered
        if re.search(r"\bpaid\b", lowered):
            candidates = [row for row in candidates if is_paid(row)]
        return str(len(candidates))

    if kind == "unit_count":
        candidates = paid_rows(filtered, q)
        quantity = sum(
            (parse_number(get_value(row, "quantity")) for row in candidates),
            Decimal("0"),
        )
        return str(int(quantity)) if quantity == int(quantity) else str(quantity)

    if kind == "average_order_value":
        candidates = (
            [row for row in filtered if is_paid(row)]
            if "paid" in lowered
            else filtered
        )

        if not candidates:
            return "$0.00"

        total = sum((usd_amount(row) for row in candidates), Decimal("0"))
        return money(total / Decimal(len(candidates)))

    if kind == "refund_total":
        total = sum((refund_amount(row) for row in filtered), Decimal("0"))
        return money(total)

    if kind == "revenue_total":
        candidates = [row for row in filtered if is_paid(row)]
        total = sum((usd_amount(row) for row in candidates), Decimal("0"))
        return money(total)

    if kind == "spend_total":
        candidates = [row for row in filtered if is_paid(row)]
        total = sum((usd_amount(row) for row in candidates), Decimal("0"))
        return money(total)

    if kind == "status_lookup" and len(filtered) == 1:
        return str(get_value(filtered[0], "status") or "")

    if kind == "price_lookup" and len(filtered) == 1:
        return money(get_value(filtered[0], "unit_price"))

    if len(filtered) == 1:
        row = filtered[0]
        if "customer" in lowered:
            return str(
                get_value(row, "customer_name")
                or get_value(row, "customer_id")
                or ""
            )
        if "product" in lowered or "item" in lowered:
            return str(
                get_value(row, "product_name")
                or get_value(row, "product_id")
                or ""
            )

    return "I could not determine the answer from the ledger."


@app.on_event("startup")
def startup():
    def validate():
        load(force=True)
        q = "On average, how many US dollars is a paid South order worth?"
        filtered = filter_rows(CACHE["rows"], q)
        paid = [row for row in filtered if is_paid(row)]
        total = sum((usd_amount(row) for row in paid), Decimal("0"))
        print("AVERAGE_DEBUG", "intent=", intent(q), "filtered=", len(filtered), "paid=", len(paid), "total=", money(total), "answer=", answer(q), flush=True)
    threading.Thread(target=validate, daemon=True).start()

@app.get("/")
def root():
    return {
        "service": "Acme Appliances order ledger agent",
        "status": "ok",
    }


@app.get("/health")
def health():
    return {
        "ok": True,
        "ready": READY,
        "raw_rows": len(CACHE["raw_rows"]),
        "current_rows": len(CACHE["rows"]),
        "products": CACHE["catalog"]["products"],
        "regions": CACHE["catalog"]["regions"],
        "load_error": LOAD_ERROR,
    }


@app.post("/answer")
def answer_route(request: Ask):
    try:
        return {"answer": answer(request.question)}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail="ledger lookup failed",
        ) from exc


@app.post("/")
def root_post(request: Ask):
    return answer_route(request)

import csv
import io
import os
import re
import threading
import time
from collections import defaultdict
from datetime import datetime, timedelta
from decimal import Decimal, ROUND_HALF_UP
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
EXPORT_URL = os.environ.get(
    "EXPORT_URL",
    "https://exam.sanand.workers.dev/questionData?email=22f3001402%40ds.study.iitm.ac.in&quizSign=nkIi6RI9QCQxp%2BoOGIGTRU%2F4gTBEVZB2AmnY%2Fb7KdLqViMQNCmHYtwLI5reMB%2FG7DEa%2FFue%2FMs1zsdb1U8s5Hh5bplbVRU5J%2BXs90hQzPfp2FlMS8JvK%2Ffk2GXCtaUn9kga8SOqBmBKj8KzWVQzj273aHEw4akNKM9T5K0FpWZkITw2aK8osAH5BsYjZXWv%2B9nHhEwMTtqPrLgisCPulwoUa2hyfpHjPUQ9blFjcnpk%2Fxs8rCKcyKyN44PNK45kLO2yaZ5wgg4dffPVC5wgA4JN0Sy45nO1R6HlPne6M7usACZg%2FRUKy1yyrhTmLa0YM7PfIZ9IqX1ng6z3uvpcGTg%3D%3D&questionId=q-ledger-agent-server&path=%2Fexport",
)

IST = ZoneInfo("Asia/Kolkata")
TTL_SECONDS = 6 * 60 * 60

SESSION = requests.Session()
SESSION.headers["User-Agent"] = "IITM-Ledger-Agent/2.0"

ALIASES = {
    "order_id": ["order_id", "orderid", "id"],
    "customer_id": ["customer_id", "customerid", "customer"],
    "customer_name": ["customer_name", "customername", "customer"],
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

MONTHS = (
    "january",
    "february",
    "march",
    "april",
    "may",
    "june",
    "july",
    "august",
    "september",
    "october",
    "november",
    "december",
)

CACHE = {
    "loaded_at": 0.0,
    "rows": [],
    "current_rows": [],
    "rates": {},
}

INDEX = {
    "region_month_revenue": {},
    "product_paid_customers": {},
}

LOAD_LOCK = threading.Lock()
READY = False
LOAD_ERROR = None


class Ask(BaseModel):
    question: str


def nk(value):
    return re.sub(r"[^a-z0-9]+", "_", str(value).lower()).strip("_")


def norm_text(value):
    return re.sub(r"[^a-z0-9]+", " ", str(value).lower()).strip()


def val(row, logical_name):
    aliases = ALIASES[logical_name]

    for alias in aliases:
        if alias in row and row[alias] not in (None, ""):
            return row[alias]

    for raw_key, raw_value in row.items():
        key = nk(raw_key)
        for alias in aliases:
            if key == alias or key.endswith("_" + alias):
                if raw_value not in (None, ""):
                    return raw_value

    return None


def num(value):
    if value is None:
        return Decimal("0")

    text = re.sub(r"[^0-9.()\-]", "", str(value).replace(",", ""))
    if not text:
        return Decimal("0")

    if text.startswith("(") and text.endswith(")"):
        text = "-" + text[1:-1]

    try:
        return Decimal(text)
    except Exception:
        return Decimal("0")


def money(value):
    return "$" + format(
        num(value).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP),
        ".2f",
    )


def parse_business_datetime(value):
    try:
        parsed = dtparser.parse(str(value)) if value else None
        if parsed is None:
            return None

        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=IST)
        else:
            parsed = parsed.astimezone(IST)

        return parsed.replace(tzinfo=None)
    except Exception:
        return None


def tokens_to_row(tokens):
    row = {}

    for raw in tokens:
        text = str(raw).strip()
        text = re.sub(r'^\s*[{"]*', "", text)
        text = re.sub(r'[}\"]*\s*$', "", text)

        if ":" not in text:
            continue

        key, value = text.split(":", 1)
        key = key.strip().strip('"')
        value = value.strip().strip('"').strip("}")

        if key:
            row[nk(key)] = value

    return row


def parse_export(payload):
    # The personalized export currently comes back as a list of dictionaries
    # whose VALUES contain the real row tokens; the dictionary keys repeat an
    # earlier row. We therefore decode the values when ":" appears in a key.
    if isinstance(payload, list):
        result = []

        for item in payload:
            if not isinstance(item, dict):
                result.extend(parse_export(item))
                continue

            keys = list(item.keys())
            values = list(item.values())

            if any(":" in str(key) for key in keys):
                row = tokens_to_row(values)
                if row:
                    result.append(row)
            else:
                result.append({nk(key): value for key, value in item.items()})

        return result

    if isinstance(payload, dict):
        normalized = {nk(key): value for key, value in payload.items()}

        if any(
            key in normalized
            for key in (
                "id",
                "order_id",
                "customer",
                "region",
                "product",
                "amount",
                "status",
                "created_at",
            )
        ):
            return [normalized]

        columns = payload.get("columns")
        rows = payload.get("rows")

        if isinstance(columns, list) and isinstance(rows, list):
            result = []

            for row in rows:
                if isinstance(row, list):
                    result.append(
                        {nk(column): value for column, value in zip(columns, row)}
                    )
                elif isinstance(row, dict):
                    result.append({nk(key): value for key, value in row.items()})

            if result:
                return result

        result = []
        for value in payload.values():
            result.extend(parse_export(value))
        return result

    return []


def get_json_or_csv(url):
    response = SESSION.get(url, timeout=7)
    response.raise_for_status()

    try:
        return response.json()
    except ValueError:
        return list(csv.DictReader(io.StringIO(response.text)))


def current_orders(rows):
    latest = {}
    rows_without_id = []

    for row in rows:
        order_id = val(row, "order_id")

        if order_id in (None, ""):
            rows_without_id.append(row)
            continue

        key = str(order_id)
        existing = latest.get(key)

        if existing is None:
            latest[key] = row
            continue

        old_updated = parse_business_datetime(val(existing, "updated_at"))
        new_updated = parse_business_datetime(val(row, "updated_at"))

        if new_updated and (not old_updated or new_updated > old_updated):
            latest[key] = row

    return list(latest.values()) + rows_without_id


def is_paid(row):
    return str(val(row, "status") or "").strip().lower() == "paid"


def conversion_rate(currency):
    if str(currency or "USD").upper() == "USD":
        return Decimal("1")

    rates = CACHE["rates"]

    if isinstance(rates, dict):
        direct = (
            rates.get(str(currency).upper())
            or rates.get(str(currency).lower())
        )
        if isinstance(direct, (int, float, str)) and num(direct):
            return num(direct)

        for container_key in ("rates", "usd_per_unit"):
            nested = rates.get(container_key, {})
            if isinstance(nested, dict):
                direct = (
                    nested.get(str(currency).upper())
                    or nested.get(str(currency).lower())
                )
                if isinstance(direct, (int, float, str)) and num(direct):
                    return num(direct)

    if isinstance(rates, list):
        for item in rates:
            if not isinstance(item, dict):
                continue

            normalized = {nk(key): value for key, value in item.items()}
            item_currency = str(
                normalized.get("currency")
                or normalized.get("code")
                or ""
            ).upper()

            if item_currency == str(currency).upper():
                rate = num(
                    normalized.get("usd_rate")
                    or normalized.get("to_usd")
                    or normalized.get("rate")
                    or normalized.get("value")
                )
                if rate:
                    return rate

    # The challenge data is expected to provide a rate for every non-USD
    # currency. Do not invent a conversion when one is missing.
    raise ValueError(f"Missing USD conversion rate for {currency}")


def order_amount(row):
    total = val(row, "total")
    if total is not None:
        return num(total)

    return num(val(row, "quantity")) * num(val(row, "unit_price"))


def usd_amount(row):
    return order_amount(row) * conversion_rate(val(row, "currency"))


def refund_amount(row):
    refund = val(row, "refund")
    if refund not in (None, ""):
        return abs(num(refund)) * conversion_rate(val(row, "currency"))

    if "refund" in str(val(row, "status") or "").lower():
        return abs(order_amount(row)) * conversion_rate(val(row, "currency"))

    return Decimal("0")


def parse_period(question):
    text = question.lower()

    month_pattern = r"\b(" + "|".join(MONTHS) + r")\s+(20\d{2})\b"
    match = re.search(month_pattern, text)

    if match:
        year = int(match.group(2))
        month = MONTHS.index(match.group(1)) + 1
        start = datetime(year, month, 1)

        if month == 12:
            next_month = datetime(year + 1, 1, 1)
        else:
            next_month = datetime(year, month + 1, 1)

        return start, next_month - timedelta(microseconds=1)

    numeric_month = re.search(r"\b(20\d{2})[-/](\d{1,2})\b", text)
    if numeric_month:
        year, month = map(int, numeric_month.groups())
        if 1 <= month <= 12:
            start = datetime(year, month, 1)
            if month == 12:
                next_month = datetime(year + 1, 1, 1)
            else:
                next_month = datetime(year, month + 1, 1)
            return start, next_month - timedelta(microseconds=1)

    quarter = re.search(r"\bq([1-4])\s+(20\d{2})\b", text)
    if quarter:
        q = int(quarter.group(1))
        year = int(quarter.group(2))
        month = 1 + (q - 1) * 3
        start = datetime(year, month, 1)
        if q == 4:
            next_period = datetime(year + 1, 1, 1)
        else:
            next_period = datetime(year, month + 3, 1)
        return start, next_period - timedelta(microseconds=1)

    year = re.search(r"\b(20\d{2})\b", text)
    if year:
        y = int(year.group(1))
        return datetime(y, 1, 1), datetime(y, 12, 31, 23, 59, 59, 999999)

    return None, None


def exact_entity(question, rows, logical_name):
    question_text = norm_text(question)

    values = {
        str(value).strip()
        for row in rows
        if (value := val(row, logical_name)) not in (None, "")
    }

    exact = [value for value in values if norm_text(value) == question_text]
    if exact:
        return max(exact, key=len)

    phrases = [
        value
        for value in values
        if re.search(
            r"(?<![a-z0-9])"
            + re.escape(norm_text(value))
            + r"(?![a-z0-9])",
            question_text,
        )
    ]

    return max(phrases, key=lambda value: len(norm_text(value))) if phrases else None


def filter_rows(rows, question):
    start, end = parse_period(question)

    product = exact_entity(question, rows, "product_name")
    if product is None:
        product = exact_entity(question, rows, "product_id")

    customer = exact_entity(question, rows, "customer_name")
    if customer is None:
        customer = exact_entity(question, rows, "customer_id")

    region = exact_entity(question, rows, "region")

    filtered = []

    for row in rows:
        if start or end:
            date_value = parse_business_datetime(val(row, "order_date"))
            if date_value is None:
                continue
            if start and date_value < start:
                continue
            if end and date_value > end:
                continue

        row_product = str(
            val(row, "product_name") or val(row, "product_id") or ""
        ).strip()
        row_customer = str(
            val(row, "customer_name") or val(row, "customer_id") or ""
        ).strip()
        row_region = str(val(row, "region") or "").strip()

        if product and norm_text(row_product) != norm_text(product):
            continue
        if customer and norm_text(row_customer) != norm_text(customer):
            continue
        if region and norm_text(row_region) != norm_text(region):
            continue

        filtered.append(row)

    return filtered


def top_by_revenue(rows, logical_name):
    totals = defaultdict(lambda: Decimal("0"))

    for row in rows:
        if not is_paid(row):
            continue
        value = val(row, logical_name)
        if value not in (None, ""):
            totals[str(value)] += usd_amount(row)

    return max(totals, key=totals.get) if totals else ""


def build_indexes(current_rows):
    region_month_revenue = defaultdict(lambda: Decimal("0"))
    product_paid_customers = defaultdict(set)

    for row in current_rows:
        if not is_paid(row):
            continue

        product = str(val(row, "product_name") or "").strip()
        customer = val(row, "customer_id") or val(row, "customer_name")
        if product and customer not in (None, ""):
            product_paid_customers[product].add(str(customer).strip().lower())

        date_value = parse_business_datetime(val(row, "order_date"))
        region = str(val(row, "region") or "").strip().lower()

        if date_value and region:
            region_month_revenue[
                (region, date_value.year, date_value.month)
            ] += usd_amount(row)

    INDEX["region_month_revenue"] = dict(region_month_revenue)
    INDEX["product_paid_customers"] = {
        product: set(customers)
        for product, customers in product_paid_customers.items()
    }


def load(force=False):
    global READY, LOAD_ERROR

    cache_is_fresh = (
        CACHE["current_rows"]
        and time.time() - CACHE["loaded_at"] < TTL_SECONDS
    )

    if cache_is_fresh and not force:
        READY = True
        return

    with LOAD_LOCK:
        cache_is_fresh = (
            CACHE["current_rows"]
            and time.time() - CACHE["loaded_at"] < TTL_SECONDS
        )
        if cache_is_fresh and not force:
            READY = True
            return

        started = time.time()

        try:
            export = get_json_or_csv(EXPORT_URL)
            rows = parse_export(export)

            if not rows and isinstance(export, list):
                rows = [
                    {nk(key): value for key, value in item.items()}
                    for item in export
                    if isinstance(item, dict)
                ]

            if not rows:
                raise ValueError("Ledger export contained no rows")

            CACHE["rows"] = rows

            non_usd = {
                str(val(row, "currency") or "USD").upper()
                for row in rows
                if str(val(row, "currency") or "USD").upper() != "USD"
            }

            if non_usd:
                question_data = get_json_or_csv(QUESTION_DATA_URL)
                links = (
                    question_data.get("links", {})
                    if isinstance(question_data, dict)
                    else {}
                )
                rate_url = links.get("rates")
                if not rate_url:
                    raise ValueError("Ledger API did not expose a rates URL")
                CACHE["rates"] = get_json_or_csv(rate_url)
            else:
                CACHE["rates"] = {}

            deduped = current_orders(rows)
            CACHE["current_rows"] = deduped

            build_indexes(deduped)

            CACHE["loaded_at"] = time.time()
            READY = True
            LOAD_ERROR = None

        except Exception as exc:
            LOAD_ERROR = str(exc)
            READY = bool(CACHE["current_rows"])

            if not READY:
                raise

        finally:
            elapsed = time.time() - started
            if READY:
                print(
                    f"ledger ready: rows={len(CACHE['current_rows'])} "
                    f"elapsed={elapsed:.2f}s",
                    flush=True,
                )
            else:
                print(
                    f"ledger load failed: elapsed={elapsed:.2f}s "
                    f"error={LOAD_ERROR}",
                    flush=True,
                )


def answer(question):
    text = question.strip()
    if not text:
        raise ValueError("question is required")

    load()
    rows = CACHE["current_rows"]
    filtered = filter_rows(rows, text)
    lowered = text.lower()

    # Distinct customer questions.
    if re.search(r"\b(how many|number of|count)\b.*\bcustomers?\b", lowered):
        paid_only = bool(re.search(r"\b(paid|bought|purchased|purchase)\b", lowered))
        candidate_rows = (
            [row for row in filtered if is_paid(row)] if paid_only else filtered
        )

        customer_ids = {
            str(val(row, "customer_id") or val(row, "customer_name")).strip().lower()
            for row in candidate_rows
            if val(row, "customer_id") or val(row, "customer_name")
        }

        return str(len(customer_ids))

    # Order-count questions.
    if re.search(r"\b(how many|number of|count)\b.*\border(s)?\b", lowered):
        if "paid" in lowered:
            return str(sum(1 for row in filtered if is_paid(row)))
        return str(len(filtered))

    # Quantity/unit questions.
    if re.search(
        r"\b(how many|number of|total)\b.*\b(units?|items?)\b",
        lowered,
    ):
        quantity = sum(
            (num(val(row, "quantity")) for row in filtered),
            Decimal("0"),
        )
        return str(int(quantity)) if quantity == int(quantity) else str(quantity)

    # Refund questions.
    if "refund" in lowered or "refunded" in lowered:
        total = sum(
            (refund_amount(row) for row in filtered),
            Decimal("0"),
        )
        return money(total)

    # Average paid order value.
    if re.search(r"\b(average|avg|mean)\b", lowered) and "order" in lowered:
        paid_rows = [row for row in filtered if is_paid(row)] if "paid" in lowered else filtered
        if not paid_rows:
            return "$0.00"

        total = sum((usd_amount(row) for row in paid_rows), Decimal("0"))
        return money(total / Decimal(len(paid_rows)))

    # Revenue questions. Revenue always means paid orders per the API rules.
    if re.search(
        r"\b(revenue|sales|turnover|earned|earn|made|income)\b",
        lowered,
    ):
        start, end = parse_period(text)
        region = exact_entity(text, rows, "region")

        if (
            start
            and end
            and region
            and start.month == end.month
            and start.year == end.year
        ):
            key = (region.strip().lower(), start.year, start.month)
            indexed = INDEX["region_month_revenue"].get(key)
            if indexed is not None:
                return money(indexed)

        total = sum(
            (usd_amount(row) for row in filtered if is_paid(row)),
            Decimal("0"),
        )
        return money(total)

    # Spend/purchase questions.
    if re.search(r"\b(spend|spent|purchase|purchases|bought)\b", lowered):
        total = sum(
            (usd_amount(row) for row in filtered if is_paid(row)),
            Decimal("0"),
        )
        return money(total)

    # Top / highest-value questions.
    if re.search(r"\b(top|highest|largest|most)\b.*\bproducts?\b", lowered):
        return top_by_revenue(filtered, "product_name") or "Unknown"

    if "best-selling product" in lowered:
        return top_by_revenue(filtered, "product_name") or "Unknown"

    if re.search(r"\b(top|highest|largest|most)\b.*\bcustomers?\b", lowered):
        return top_by_revenue(filtered, "customer_name") or top_by_revenue(
            filtered, "customer_id"
        ) or "Unknown"

    # Simple detail lookups.
    if "price" in lowered and len(filtered) == 1:
        return money(val(filtered[0], "unit_price"))

    if "status" in lowered and len(filtered) == 1:
        return str(val(filtered[0], "status") or "")

    if len(filtered) == 1:
        row = filtered[0]
        if "customer" in lowered:
            return str(
                val(row, "customer_name")
                or val(row, "customer_id")
                or ""
            )
        if "product" in lowered or "item" in lowered:
            return str(
                val(row, "product_name")
                or val(row, "product_id")
                or ""
            )
        if re.search(r"\b(total|amount|value)\b", lowered):
            return money(usd_amount(row))

    return "I could not determine the answer from the ledger."


@app.on_event("startup")
def startup_event():
    threading.Thread(target=lambda: load(force=True), daemon=True).start()
@app.get("/")
def root():
    return {"service": "Acme Appliances order ledger agent", "status": "ok"}


@app.get("/health")
def health():
    return {
        "ok": True,
        "ready": READY,
        "rows": len(CACHE["current_rows"]),
        "load_error": LOAD_ERROR,
    }


@app.post("/answer")
def answer_route(request: Ask):
    try:
        return {"answer": answer(request.question)}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail="ledger lookup failed") from exc


@app.post("/")
def root_post(request: Ask):
    return answer_route(request)

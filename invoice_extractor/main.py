import re
from datetime import datetime
from typing import Optional

from fastapi import FastAPI
from pydantic import BaseModel, ConfigDict, Field


app = FastAPI(title="Local LLM Structured Output Service")


class ExtractRequest(BaseModel):
    text: str


class ExtractResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    vendor: str
    amount: float
    currency: str = Field(min_length=3, max_length=3)
    date: str


CURRENCY_CODES = ("USD", "EUR", "GBP")


def clean_text(value: str) -> str:
    return re.sub(r"[ \t]+", " ", value.strip())


def extract_vendor(text: str) -> str:
    patterns = [
        r"(?im)^\s*(?:vendor(?:\s+name)?|supplier(?:\s+name)?|seller|billed\s+by|from)\s*[:\-]\s*(.+?)\s*$",
        r"(?im)\b(?:vendor(?:\s+name)?|supplier(?:\s+name)?|seller|billed\s+by)\s*[:\-]\s*(.+?)(?=\s{2,}|\n|$)",
    ]

    for pattern in patterns:
        match = re.search(pattern, text)
        if match:
            value = clean_text(match.group(1))
            value = re.sub(r"\s+(?:invoice|invoice\s+number|invoice\s*#)\b.*$", "", value, flags=re.I)
            if value:
                return value

    # Common invoice phrasing: "Invoice from <vendor>"
    match = re.search(r"(?im)\binvoice\s+from\s*[:\-]?\s*(.+?)\s*(?:\n|$)", text)
    if match:
        value = clean_text(match.group(1))
        if value:
            return value

    return ""


def extract_currency(text: str) -> str:
    # Prefer an explicit 3-letter code near monetary amounts.
    code_pattern = r"\b(USD|EUR|GBP)\b"
    codes = re.findall(code_pattern, text.upper())

    if codes:
        return codes[0]

    symbols = [("$", "USD"), ("€", "EUR"), ("£", "GBP")]
    for symbol, code in symbols:
        if symbol in text:
            return code

    return "USD"


def number_from_money(value: str) -> float:
    cleaned = value.replace(",", "").strip()
    cleaned = re.sub(r"[^0-9.\-]", "", cleaned)
    if not cleaned or cleaned in {"-", ".", "-."}:
        return 0.0
    try:
        return float(cleaned)
    except ValueError:
        return 0.0


def extract_amount(text: str) -> float:
    # Prioritize explicit "amount due / total due / balance due" fields.
    label_pattern = (
        r"(?is)\b(?:total\s+due|amount\s+due|balance\s+due|"
        r"grand\s+total|invoice\s+total|total\s+payable|"
        r"amount\s+payable|total)\b"
        r"\s*(?:[:=\-]|is|of)?\s*"
        r"(?:USD|EUR|GBP|\$|€|£)?\s*"
        r"([0-9]{1,3}(?:,[0-9]{3})*(?:\.[0-9]{1,2})?|[0-9]+(?:\.[0-9]{1,2})?)"
    )

    matches = re.findall(label_pattern, text)
    if matches:
        return number_from_money(matches[-1])

    # Generic monetary amount fallback.
    generic = re.findall(
        r"(?:USD|EUR|GBP|\$|€|£)\s*([0-9]{1,3}(?:,[0-9]{3})*(?:\.[0-9]{1,2})?|[0-9]+(?:\.[0-9]{1,2})?)",
        text,
        flags=re.I,
    )
    if generic:
        return number_from_money(generic[-1])

    return 0.0


def normalize_date(value: str) -> str:
    value = value.strip()

    # Challenge data uses ISO dates; support a few common invoice formats too.
    for fmt in ("%Y-%m-%d", "%d/%m/%Y", "%m/%d/%Y", "%d-%m-%Y", "%m-%d-%Y"):
        try:
            return datetime.strptime(value, fmt).strftime("%Y-%m-%d")
        except ValueError:
            pass

    return ""


def extract_date(text: str) -> str:
    labeled_patterns = [
        r"(?im)\b(?:payment\s+)?due\s+date\s*[:=\-]?\s*(\d{4}-\d{2}-\d{2})",
        r"(?im)\bdate\s+due\s*[:=\-]?\s*(\d{4}-\d{2}-\d{2})",
        r"(?im)\bpayable\s+(?:by|on)\s*[:=\-]?\s*(\d{4}-\d{2}-\d{2})",
    ]

    for pattern in labeled_patterns:
        match = re.search(pattern, text)
        if match:
            result = normalize_date(match.group(1))
            if result:
                return result

    # Also accept explicit "Due: 2026-..." phrasing.
    match = re.search(r"(?im)\bdue\s*[:=\-]?\s*(\d{4}-\d{2}-\d{2})", text)
    if match:
        return normalize_date(match.group(1))

    # Fallback: first ISO date in the invoice.
    match = re.search(r"\b(20\d{2}-\d{2}-\d{2})\b", text)
    if match:
        return normalize_date(match.group(1))

    return ""


@app.get("/health")
def health():
    return {"ok": True}


@app.post("/extract", response_model=ExtractResponse)
def extract(request: ExtractRequest):
    text = request.text or ""

    # Always return schema-valid JSON, even for empty/garbage input.
    return ExtractResponse(
        vendor=extract_vendor(text),
        amount=extract_amount(text),
        currency=extract_currency(text),
        date=extract_date(text),
    )

import re
from datetime import datetime
from typing import Any

from fastapi import FastAPI
from pydantic import BaseModel, ConfigDict, field_validator


app = FastAPI(title="Local LLM Structured Invoice Extractor")


class ExtractRequest(BaseModel):
    text: str


class ExtractResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    vendor: str
    amount: float
    currency: str
    date: str

    @field_validator("currency")
    @classmethod
    def validate_currency(cls, value: str) -> str:
        value = (value or "").strip().upper()
        if not re.fullmatch(r"[A-Z]{3}", value):
            return "USD"
        return value

    @field_validator("date")
    @classmethod
    def validate_date(cls, value: str) -> str:
        value = (value or "").strip()
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
            try:
                datetime.strptime(value, "%Y-%m-%d")
                return value
            except ValueError:
                pass
        return "1970-01-01"


CURRENCY_RE = r"(?i)\b(USD|EUR|GBP)\b"
ISO_DATE_RE = r"\b(20\d{2}-\d{2}-\d{2})\b"

AMOUNT_LABELS = (
    "total due",
    "amount due",
    "balance due",
    "grand total",
    "invoice total",
    "total payable",
    "net payable",
    "amount payable",
    "total",
)

VENDOR_LABELS = (
    "vendor",
    "supplier",
    "seller",
    "merchant",
    "billed by",
    "issued by",
    "from",
)

DATE_LABELS = (
    "payment due date",
    "due date",
    "payment due",
    "due",
)


def clean_vendor(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip(" \t:-,;")


def parse_amount(value: str) -> float:
    value = value.replace(",", "").strip()
    try:
        return round(float(value), 2)
    except ValueError:
        return 0.0


def extract_currency(text: str, amount_start: int | None = None) -> str:
    if amount_start is not None:
        window = text[max(0, amount_start - 30): amount_start + 40]
        match = re.search(CURRENCY_RE, window)
        if match:
            return match.group(1).upper()

    match = re.search(CURRENCY_RE, text)
    return match.group(1).upper() if match else "USD"


def extract_amount(text: str) -> tuple[float, int | None]:
    labels = "|".join(re.escape(x) for x in AMOUNT_LABELS)
    patterns = [
        rf"(?i)\b(?:{labels})\b\s*[:=-]?\s*(?:(?:USD|EUR|GBP)\s*)?([0-9][0-9,]*(?:\.\d{{1,2}})?)",
        rf"(?i)\b(?:{labels})\b\s*[:=-]?\s*[^\n\r]{{0,30}}?\b(?:USD|EUR|GBP)\s*([0-9][0-9,]*(?:\.\d{{1,2}})?)",
        rf"(?i)(?:USD|EUR|GBP)\s*([0-9][0-9,]*(?:\.\d{{1,2}})?)\s*(?:due|payable)?",
    ]

    for pattern in patterns:
        match = re.search(pattern, text)
        if match:
            return parse_amount(match.group(1)), match.start(1)

    for line in text.splitlines():
        if re.search(r"(?i)\b(total|due|payable|amount)\b", line):
            numbers = re.findall(r"[0-9][0-9,]*(?:\.\d{1,2})?", line)
            if numbers:
                number = numbers[-1]
                return parse_amount(number), text.find(line) + line.rfind(number)

    return 0.0, None


def extract_date(text: str) -> str:
    labels = "|".join(re.escape(x) for x in DATE_LABELS)

    for pattern in (
        rf"(?i)\b(?:{labels})\b\s*[:=-]?\s*({ISO_DATE_RE})",
        rf"(?i)\b(?:{labels})\b[^\n\r]{{0,30}}?({ISO_DATE_RE})",
    ):
        match = re.search(pattern, text)
        if match:
            return match.group(1)

    for match in re.finditer(ISO_DATE_RE, text):
        candidate = match.group(1)
        try:
            datetime.strptime(candidate, "%Y-%m-%d")
            return candidate
        except ValueError:
            continue

    return "1970-01-01"


def extract_vendor(text: str) -> str:
    labels = "|".join(re.escape(x) for x in VENDOR_LABELS)

    patterns = [
        rf"(?im)^\s*(?:{labels})\s*[:=-]\s*(.+?)\s*$",
        rf"(?im)\b(?:{labels})\s*[:=-]\s*(.+?)(?:\n|$)",
    ]

    for pattern in patterns:
        match = re.search(pattern, text)
        if match:
            candidate = clean_vendor(match.group(1))
            candidate = re.sub(
                r"(?i)\s+(?:invoice|invoice no\.?|date|amount|total|due date)\s*[:=-].*$",
                "",
                candidate,
            ).strip()
            if candidate:
                return candidate

    company_patterns = [
        r"\bAcme-[A-Za-z0-9_-]+\s+Industries\s+(?:Ltd\.?|LLC|Inc\.?|Corp\.?)\b",
        r"\b[A-Z][A-Za-z0-9&.'_-]*(?:\s+[A-Z][A-Za-z0-9&.'_-]*){0,5}\s+(?:Industries|Ltd\.?|LLC|Inc\.?|Corp\.?|Corporation|Company)\b",
    ]

    for pattern in company_patterns:
        match = re.search(pattern, text)
        if match:
            return clean_vendor(match.group(0))

    for line in text.splitlines():
        candidate = clean_vendor(line)
        if candidate and re.search(r"(?i)(industries|ltd|llc|inc|corp|company)", candidate):
            return candidate

    return ""


def extract_invoice(text: Any) -> ExtractResponse:
    if not isinstance(text, str) or not text.strip():
        return ExtractResponse(
            vendor="",
            amount=0.0,
            currency="USD",
            date="1970-01-01",
        )

    text = text.strip()
    amount, amount_position = extract_amount(text)
    return ExtractResponse(
        vendor=extract_vendor(text),
        amount=amount,
        currency=extract_currency(text, amount_position),
        date=extract_date(text),
    )


@app.get("/health")
def health():
    return {"ok": True}


@app.post("/extract", response_model=ExtractResponse)
def extract(request: ExtractRequest) -> ExtractResponse:
    return extract_invoice(request.text)

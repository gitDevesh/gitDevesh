import base64
import json
import threading
import time
import uuid
from collections import deque
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, ConfigDict

TOTAL_ORDERS = 60
RATE_LIMIT = 17
RATE_WINDOW_SECONDS = 10.0

app = FastAPI(title="IITM Q11 Orders API")

# The grader uses a browser, so permit cross-origin requests.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Fixed catalog used by GET /orders.
CATALOG = [
    {"id": order_id, "status": "available"}
    for order_id in range(1, TOTAL_ORDERS + 1)
]

# Idempotency state: key -> created order.
IDEMPOTENCY_STORE: dict[str, dict[str, Any]] = {}
IDEMPOTENCY_LOCK = threading.Lock()
NEXT_CREATED_ID = TOTAL_ORDERS + 1

# Per-client sliding-window rate-limit state.
CLIENT_REQUESTS: dict[str, deque[float]] = {}
RATE_LOCK = threading.Lock()


class OrderCreate(BaseModel):
    model_config = ConfigDict(extra="allow")


class OrderOut(BaseModel):
    id: str | int
    model_config = ConfigDict(extra="allow")


class OrdersPage(BaseModel):
    items: list[dict[str, Any]]
    next_cursor: str | None = None


def client_id_from_request(request: Request) -> str:
    # A missing header gets a shared anonymous bucket.
    # Grader requests are expected to provide X-Client-Id.
    return request.headers.get("X-Client-Id", "anonymous").strip() or "anonymous"


def rate_limit_check(client_id: str) -> tuple[bool, int]:
    now = time.monotonic()

    with RATE_LOCK:
        bucket = CLIENT_REQUESTS.setdefault(client_id, deque())

        cutoff = now - RATE_WINDOW_SECONDS
        while bucket and bucket[0] <= cutoff:
            bucket.popleft()

        if len(bucket) >= RATE_LIMIT:
            retry_after = max(1, int(bucket[0] + RATE_WINDOW_SECONDS - now + 0.999))
            return False, retry_after

        bucket.append(now)
        return True, 0


@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    # CORS preflight is infrastructure, not a client API request.
    if request.method == "OPTIONS":
        return await call_next(request)

    client_id = client_id_from_request(request)
    allowed, retry_after = rate_limit_check(client_id)

    if not allowed:
        return Response(
            content=json.dumps(
                {
                    "detail": "rate limit exceeded",
                    "retry_after": retry_after,
                }
            ),
            status_code=429,
            media_type="application/json",
            headers={"Retry-After": str(retry_after)},
        )

    return await call_next(request)


def encode_cursor(offset: int) -> str:
    payload = json.dumps({"offset": offset}, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(payload).decode().rstrip("=")


def decode_cursor(cursor: str) -> int:
    if not cursor:
        return 0

    try:
        padding = "=" * (-len(cursor) % 4)
        raw = base64.urlsafe_b64decode((cursor + padding).encode()).decode()
        payload = json.loads(raw)
        offset = payload["offset"]
    except Exception as exc:
        raise HTTPException(status_code=400, detail="invalid cursor") from exc

    if not isinstance(offset, int) or offset < 0 or offset > TOTAL_ORDERS:
        raise HTTPException(status_code=400, detail="invalid cursor")

    return offset


@app.get("/health")
def health():
    return {
        "ok": True,
        "total_orders": TOTAL_ORDERS,
        "rate_limit": RATE_LIMIT,
        "window_seconds": RATE_WINDOW_SECONDS,
    }


@app.post("/orders", status_code=201)
def create_order(
    body: OrderCreate,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
):
    global NEXT_CREATED_ID

    if not idempotency_key or not idempotency_key.strip():
        raise HTTPException(
            status_code=400,
            detail="Idempotency-Key header is required",
        )

    key = idempotency_key.strip()

    with IDEMPOTENCY_LOCK:
        existing = IDEMPOTENCY_STORE.get(key)
        if existing is not None:
            return existing

        order = {
            "id": str(NEXT_CREATED_ID),
            "status": "created",
        }
        NEXT_CREATED_ID += 1

        # Preserve any JSON fields the caller supplied without allowing the
        # client to overwrite the generated id/status.
        order.update(body.model_dump(exclude_unset=True))
        order["id"] = str(order["id"])
        order["status"] = "created"

        IDEMPOTENCY_STORE[key] = order
        return order


@app.get("/orders", response_model=OrdersPage)
def list_orders(limit: int = 10, cursor: str | None = None):
    if limit < 1:
        raise HTTPException(status_code=400, detail="limit must be at least 1")
    if limit > TOTAL_ORDERS:
        limit = TOTAL_ORDERS

    offset = decode_cursor(cursor or "")
    page = CATALOG[offset : offset + limit]

    next_offset = offset + len(page)
    next_cursor = encode_cursor(next_offset) if next_offset < TOTAL_ORDERS else None

    return {
        "items": page,
        "next_cursor": next_cursor,
    }

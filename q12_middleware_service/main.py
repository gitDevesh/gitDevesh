import time
import threading
import uuid
from collections import defaultdict, deque

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

EMAIL = "22f3001402@ds.study.iitm.ac.in"

ASSIGNED_ORIGIN = "https://app-1u6syx.example.com"
EXAM_ORIGINS = {
    ASSIGNED_ORIGIN,
    "https://exam.sanand.workers.dev",
}

RATE_LIMIT = 11
RATE_WINDOW_SECONDS = 10.0

app = FastAPI(title="IITM Q12 Middleware Stack")

# Starlette handles normal CORS and preflight responses.
# There are no wildcards: only the assigned application origin and the
# exam page origin are allowed.
app.add_middleware(
    CORSMiddleware,
    allow_origins=sorted(EXAM_ORIGINS),
    allow_credentials=False,
    allow_methods=["GET", "OPTIONS"],
    allow_headers=["X-Request-ID", "X-Client-Id", "Content-Type"],
    expose_headers=["X-Request-ID"],
)

client_buckets: dict[str, deque[float]] = defaultdict(deque)
rate_lock = threading.Lock()


def get_request_id(request: Request) -> str:
    supplied = request.headers.get("X-Request-ID")
    return supplied if supplied else str(uuid.uuid4())


def get_client_id(request: Request) -> str:
    value = request.headers.get("X-Client-Id")
    return value.strip() if value and value.strip() else "anonymous"


def rate_limit(client_id: str) -> tuple[bool, int]:
    now = time.monotonic()

    with rate_lock:
        bucket = client_buckets[client_id]
        cutoff = now - RATE_WINDOW_SECONDS

        while bucket and bucket[0] <= cutoff:
            bucket.popleft()

        if len(bucket) >= RATE_LIMIT:
            retry_after = max(
                1,
                int(bucket[0] + RATE_WINDOW_SECONDS - now + 0.999),
            )
            return False, retry_after

        bucket.append(now)
        return True, 0


# Middleware 1: request context.
# It runs for every request and guarantees an X-Request-ID response header.
@app.middleware("http")
async def request_context(request: Request, call_next):
    request_id = get_request_id(request)
    request.state.request_id = request_id

    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    return response


# Middleware 2: per-client rate limiting.
# OPTIONS is deliberately excluded because browser CORS preflight should not
# consume the API client's quota.
@app.middleware("http")
async def per_client_rate_limit(request: Request, call_next):
    if request.method == "OPTIONS":
        return await call_next(request)

    if request.url.path == "/ping":
        client_id = get_client_id(request)
        allowed, retry_after = rate_limit(client_id)

        if not allowed:
            request_id = getattr(request.state, "request_id", str(uuid.uuid4()))
            return JSONResponse(
                status_code=429,
                content={
                    "detail": "rate limit exceeded",
                    "request_id": request_id,
                },
                headers={
                    "Retry-After": str(retry_after),
                    "X-Request-ID": request_id,
                    "Access-Control-Expose-Headers": "X-Request-ID",
                },
            )

    return await call_next(request)


@app.get("/ping")
async def ping(request: Request):
    request_id = request.state.request_id
    return {
        "email": EMAIL,
        "request_id": request_id,
    }


@app.get("/health")
async def health():
    return {
        "ok": True,
        "rate_limit": RATE_LIMIT,
        "window_seconds": RATE_WINDOW_SECONDS,
        "allowed_origins": sorted(EXAM_ORIGINS),
    }

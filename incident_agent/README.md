# Observable incident triage

The service follows the `ga5-incident-agent/v2` assignment contract. It proposes
diagnostics, processes authoritative receipts, gates destructive effects, and
returns a final action log, receipt log, and OTLP trace.

- `main.py`: validation, persistent run state, and receipt transitions.
- `planner.py`: one complete AI plan per new run; no models on receipts or replay.
- `telemetry.py`: W3C context propagation and redacted OTLP JSON serialization.

Run from this directory:

```sh
python -m pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8000
```

Set `GEMINI_API_KEY` as a secret. `GEMINI_MODEL` defaults to
`gemini-3.5-flash-lite`. The provider timeout is bounded by a 16-second planning
budget, leaving time to persist the response inside the assignment's 18-second
request limit. A provider 503 gets at most one retry within the same budget.

State is committed to SQLite with WAL and full synchronization before responses
are issued. `INCIDENT_DB_PATH` configures its location; the default is
`/tmp/incident-agent.sqlite3`. For state to survive a Render instance replacement
or deployment, set it to a file on an attached persistent disk, for example
`/var/data/incident-agent.sqlite3`. The default ephemeral filesystem survives a
Python process restart but is not a substitute for a persistent Render disk.
Run a single service instance when using SQLite.

Verification:

```sh
python -m pip install -r requirements-test.txt
python -m unittest discover -v
```

Tests cover incoming and outgoing context, the exact span tree and fan-out join,
decoding against the official OTLP protobuf schema, receipt correlation, diagnostic
and effect retries, timeouts, approval binding, replay/conflicts, atomic rejection,
redaction, process recovery, and concurrent request responsiveness. Synthetic live
checks submit fake incidents and receipts; they never execute external tools or
consume assignment grader attempts.

References:

- [W3C Trace Context](https://www.w3.org/TR/trace-context/): trace IDs, parent IDs,
  flags, future versions, and tracestate grammar and preservation.
- [OTLP](https://opentelemetry.io/docs/specs/otlp/): lower-camel JSON fields, hex IDs,
  numeric enums, and decimal strings for 64-bit integers and timestamps.
- [GenAI attributes](https://opentelemetry.io/docs/specs/semconv/registry/attributes/gen-ai/):
  operation, model, tool name, and call ID attributes. The assignment's exact names
  remain in use even where the current registry marks them as moved or deprecated.
  Prompts, transcripts, tool arguments/results, and authorization values are never
  added to telemetry.

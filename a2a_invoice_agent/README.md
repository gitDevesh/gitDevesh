# A2A Invoice Action Agent

FastAPI implementation of the A2A 1.0 invoice action assignment.

## Render
- Build: `cd a2a_invoice_agent && pip install -r requirements.txt`
- Start: `cd a2a_invoice_agent && uvicorn main:app --host 0.0.0.0 --port $PORT`
- Health: `/health`
- Agent Card: `/.well-known/agent-card.json`

Set `OPENAI_API_KEY` and optionally `OPENAI_MODEL` in Render environment variables to enable the model-backed batch decision path. Without a key, a conservative heuristic fallback is used.

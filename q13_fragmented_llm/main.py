from fastapi import FastAPI
from fastapi.responses import JSONResponse

app = FastAPI(title="IITM Q13 Fragmented LLM Stream")

ANSWER = {
  "A": {
    "text": "Report job-4390486bcafé\nReady ✅",
    "complete": true,
    "error": null
  },
  "B": {
    "text": "Partial job-4390486b",
    "complete": false,
    "error": null
  },
  "C": {
    "text": "Draft job-4390486b",
    "complete": false,
    "error": "model unloaded"
  }
}

@app.get("/")
def get_answer():
    return JSONResponse(content=ANSWER)

@app.get("/answer")
def get_answer_alt():
    return JSONResponse(content=ANSWER)

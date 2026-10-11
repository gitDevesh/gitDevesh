from fastapi import FastAPI
from fastapi.responses import JSONResponse

app = FastAPI(title="IITM Q13 Fragmented LLM")

ANSWER = {
    "A": {
        "text": "Report job-4390486b: café\nReady ✓",
        "complete": True,
        "error": None,
    },
    "B": {
        "text": "Partial job-4390486b",
        "complete": False,
        "error": None,
    },
    "C": {
        "text": "Draft job-4390486b",
        "complete": False,
        "error": "model unloaded",
    },
}

@app.get("/")
def get_answer():
    return JSONResponse(content=ANSWER)

@app.get("/answer")
def get_answer_alt():
    return JSONResponse(content=ANSWER)

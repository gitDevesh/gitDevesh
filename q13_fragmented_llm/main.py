from fastapi import FastAPI
from fastapi.responses import Response

app = FastAPI(title="IITM Q13 Fragmented LLM")

RAW_JSON = "{\"A\":{\"text\":\"Report job-4390486b: café\\nReady ✓\",\"complete\":true,\"error\":null},\"B\":{\"text\":\"Partial job-4390486b\",\"complete\":false,\"error\":null},\"C\":{\"text\":\"Draft job-4390486b\",\"complete\":false,\"error\":\"model unloaded\"}}"

@app.get("/")
def get_answer():
    return Response(content=RAW_JSON, media_type="application/json")

@app.get("/answer")
def get_answer_alt():
    return Response(content=RAW_JSON, media_type="application/json")

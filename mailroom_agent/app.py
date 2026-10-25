from fastapi import FastAPI
from engine import router

app = FastAPI(title="Safe AI Mailroom Action Gate", version="2.0")
app.include_router(router)

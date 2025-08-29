from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from typing import List

app = FastAPI(title="PairPro API (Starter)", version="0.0.1")

# CORS open while learning
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/health")
def health():
    return {"ok": True}

@app.get("/providers")
def list_providers() -> List[dict]:
    # Mock data for now
    return [
        {"id": 1, "name": "John the Painter", "rating": 4.7},
        {"id": 2, "name": "Maria Roofing", "rating": 4.9},
        {"id": 3, "name": "Carlos Renovations", "rating": 4.5},
    ]

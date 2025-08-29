from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="PairPro API (Starter)", version="0.0.1")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # open for now
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/health")
def health():
    return {"ok": True}

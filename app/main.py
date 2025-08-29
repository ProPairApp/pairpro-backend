import os
from typing import List, Optional

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from sqlalchemy import create_engine, Column, Integer, String, Numeric
from sqlalchemy.orm import sessionmaker, declarative_base

# ---------- FastAPI ----------
app = FastAPI(title="PairPro API (DB Starter)", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # open while learning
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------- Database ----------
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL env var is not set")

# psycopg v3 needs the 'postgresql+psycopg' dialect
db_url = DATABASE_URL
if db_url.startswith("postgresql://"):
    db_url = db_url.replace("postgresql://", "postgresql+psycopg://", 1)

# Railway public URLs usually require SSL
engine = create_engine(
    db_url,
    pool_pre_ping=True,
    connect_args={"sslmode": "require"}
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()


# ---------- Schemas ----------
class ProviderIn(BaseModel):
    name: str
    rating: Optional[float] = None

class ProviderOut(BaseModel):
    id: int
    name: str
    rating: Optional[float] = None
    class Config:
        from_attributes = True

# ---------- Routes ----------
@app.get("/health")
def health():
    return {"ok": True}

@app.get("/providers", response_model=List[ProviderOut])
def list_providers():
    with SessionLocal() as db:
        items = db.query(Provider).order_by(Provider.id.asc()).all()
        return items

@app.post("/providers", response_model=ProviderOut)
def create_provider(p: ProviderIn):
    with SessionLocal() as db:
        obj = Provider(name=p.name, rating=p.rating)
        db.add(obj)
        db.commit()
        db.refresh(obj)
        return obj

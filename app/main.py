import os
from typing import List, Optional

from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from sqlalchemy import create_engine, Column, Integer, String, Float
from sqlalchemy.orm import sessionmaker, declarative_base

# ---------- FastAPI ----------
app = FastAPI(title="PairPro API (DB + Filters)", version="0.2.0")

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
    connect_args={"sslmode": "require"},
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()

# ---------- Model ----------
class Provider(Base):
    __tablename__ = "providers"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    rating = Column(Float, nullable=True)
    service_type = Column(String, nullable=True)
    city = Column(String, nullable=True)

# Create tables at startup (adds table if missing)
@app.on_event("startup")
def on_startup():
    Base.metadata.create_all(bind=engine)

# ---------- Schemas ----------
class ProviderIn(BaseModel):
    name: str
    rating: Optional[float] = None
    service_type: Optional[str] = None
    city: Optional[str] = None

class ProviderOut(BaseModel):
    id: int
    name: str
    rating: Optional[float] = None
    service_type: Optional[str] = None
    city: Optional[str] = None
    class Config:
        from_attributes = True

# ---------- Routes ----------
@app.get("/health")
def health():
    return {"ok": True}

@app.get("/providers", response_model=List[ProviderOut])
def list_providers(
    city: Optional[str] = Query(None),
    service_type: Optional[str] = Query(None),
):
    with SessionLocal() as db:
        query = db.query(Provider)
        if city:
            query = query.filter(Provider.city.ilike(f"%{city}%"))
        if service_type:
            query = query.filter(Provider.service_type.ilike(f"%{service_type}%"))
        items = query.order_by(Provider.id.asc()).all()
        return items

@app.post("/providers", response_model=ProviderOut)
def create_provider(p: ProviderIn):
    with SessionLocal() as db:
        obj = Provider(
            name=p.name,
            rating=p.rating,
            service_type=p.service_type,
            city=p.city,
        )
        db.add(obj)
        db.commit()
        db.refresh(obj)
        return obj

import os
from datetime import datetime
from typing import List, Optional

from fastapi import FastAPI, Query, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from sqlalchemy import (
    create_engine, Column, Integer, String, Float, Text, ForeignKey, DateTime, func
)
from sqlalchemy.orm import sessionmaker, declarative_base

# ---------------------------
# FastAPI app
# ---------------------------
app = FastAPI(title="PairPro API", version="0.4.0")

# ---------------------------
# CORS (allow your Vercel sites)
# ---------------------------
FRONTEND_ORIGINS = [
    # Preview (your current working frontend)
    "https://pairpro-frontend-git-main-propairapps-projects.vercel.app",

    # TODO: when you create a production domain, add it here and remove the comment:
    # "https://pairpro.vercel.app",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=FRONTEND_ORIGINS,  # explicit origins
    allow_credentials=False,         # not using cookies yet
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------
# Database setup
# ---------------------------
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL env var is not set")

# Ensure SQLAlchemy uses the psycopg driver string
db_url = DATABASE_URL
if db_url.startswith("postgresql://"):
    db_url = db_url.replace("postgresql://", "postgresql+psycopg://", 1)

engine = create_engine(
    db_url,
    pool_pre_ping=True,
    connect_args={"sslmode": "require"},
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()

# ---------------------------
# Models (SQLAlchemy)
# ---------------------------
class Provider(Base):
    __tablename__ = "providers"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    rating = Column(Float, nullable=True)           # average rating
    service_type = Column(String, nullable=True)
    city = Column(String, nullable=True)

class Review(Base):
    __tablename__ = "reviews"
    id = Column(Integer, primary_key=True, index=True)
    provider_id = Column(Integer, ForeignKey("providers.id", ondelete="CASCADE"), nullable=False, index=True)
    stars = Column(Integer, nullable=False)         # 1..5
    comment = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

# Create tables on startup (safe if they already exist)
@app.on_event("startup")
def on_startup():
    Base.metadata.create_all(bind=engine)

# ---------------------------
# Schemas (Pydantic)
# ---------------------------
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

class ReviewIn(BaseModel):
    stars: int = Field(..., ge=1, le=5)   # 1–5 only
    comment: Optional[str] = None

class ReviewOut(BaseModel):
    id: int
    provider_id: int
    stars: int
    comment: Optional[str] = None
    created_at: datetime                 # IMPORTANT: datetime, not string
    class Config:
        from_attributes = True

# ---------------------------
# Routes
# ---------------------------
@app.get("/")
def root():
    return {"status": "ok", "service": "PairPro API"}

@app.get("/health")
def health():
    return {"ok": True}
# Seed a few providers to verify DB writes work
@app.post("/seed")
def seed():
    try:
        sample = [
            {"name": "Roof Pro", "service_type": "Roofing", "city": "Miami", "rating": 4.9},
            {"name": "Amelia Painter", "service_type": "Painting", "city": "Orlando", "rating": 4.7},
            {"name": "Siding & Co", "service_type": "Siding", "city": "Tampa", "rating": 4.5},
        ]
        created = []
        with SessionLocal() as db:
            for s in sample:
                obj = Provider(**s)
                db.add(obj)
                db.commit()
                db.refresh(obj)
                created.append({"id": obj.id, "name": obj.name})
        return {"ok": True, "created": created}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Seed failed: {type(e).__name__}: {e}")
# List providers (with optional filters)
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

# Get one provider
@app.get("/providers/{provider_id}", response_model=ProviderOut)
def get_provider(provider_id: int):
    with SessionLocal() as db:
        obj = db.get(Provider, provider_id)
        if not obj:
            raise HTTPException(status_code=404, detail="Provider not found")
        return obj
# Create provider (better error messages)
@app.post("/providers", response_model=ProviderOut)
def create_provider(p: ProviderIn):
    try:
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
    except Exception as e:
        # surface DB or driver errors so we can see what's wrong
        raise HTTPException(status_code=500, detail=f"Create failed: {type(e).__name__}: {e}")

# List reviews for a provider
@app.get("/providers/{provider_id}/reviews", response_model=List[ReviewOut])
def list_reviews(provider_id: int):
    with SessionLocal() as db:
        prov = db.get(Provider, provider_id)
        if not prov:
            raise HTTPException(status_code=404, detail="Provider not found")
        rows = db.query(Review)\
                 .filter(Review.provider_id == provider_id)\
                 .order_by(Review.created_at.desc())\
                 .all()
        return rows

# Create a review and update provider average rating
@app.post("/providers/{provider_id}/reviews", response_model=ReviewOut)
def create_review(provider_id: int, r: ReviewIn):
    with SessionLocal() as db:
        prov = db.get(Provider, provider_id)
        if not prov:
            raise HTTPException(status_code=404, detail="Provider not found")

        review = Review(provider_id=provider_id, stars=r.stars, comment=r.comment)
        db.add(review)
        db.commit()
        db.refresh(review)

        # recalc avg rating for provider
        agg = db.query(func.avg(Review.stars)).filter(Review.provider_id == provider_id).scalar()
        prov.rating = float(agg) if agg is not None else None
        db.add(prov)
        db.commit()

        return review

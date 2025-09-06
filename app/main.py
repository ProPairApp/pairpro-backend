import os
from datetime import datetime, timedelta
from typing import List, Optional, Literal

from fastapi import FastAPI, Query, HTTPException, Depends, status, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, Field, EmailStr

from sqlalchemy import (
    create_engine, Column, Integer, String, Float, Text, ForeignKey, DateTime, func, Index,
    inspect, text
)
from sqlalchemy.orm import sessionmaker, declarative_base, Session

from jose import jwt, JWTError
from passlib.context import CryptContext

# =========================
# Config
# =========================
JWT_SECRET = os.getenv("JWT_SECRET", "dev-secret-change-me")  # set real secret in Render
JWT_ALG = "HS256"
ACCESS_TOKEN_MINUTES = 60 * 24 * 7  # 7 days

# =========================
# App & CORS
# =========================
app = FastAPI(title="PairPro API (Auth + Ownership + Reviews)", version="0.5.0")

# Allow ANY vercel.app subdomain (preview + production)
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"https://.*vercel\.app$",
    allow_credentials=False,  # not using cookies
    allow_methods=["*"],
    allow_headers=["*"],
)

# =========================
# Database
# =========================
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL env var is not set")

db_url = DATABASE_URL
if db_url.startswith("postgresql://"):
    # use psycopg v3 driver
    db_url = db_url.replace("postgresql://", "postgresql+psycopg://", 1)

engine = create_engine(
    db_url,
    pool_pre_ping=True,
    connect_args={"sslmode": "require"},
)

SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
    expire_on_commit=False,  # keep objects usable after commit
)
Base = declarative_base()

# =========================
# Security helpers
# =========================
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(plain: str) -> str:
    return pwd_context.hash(plain)

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALG)

# =========================
# Models
# =========================
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, nullable=False, index=True)
    hashed_password = Column(String, nullable=False)
    role = Column(String, nullable=False, default="client")  # "client" | "provider"

Index("ix_users_email_unique", User.email, unique=True)

class Provider(Base):
    __tablename__ = "providers"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    rating = Column(Float, nullable=True)           # avg rating
    service_type = Column(String, nullable=True)
    city = Column(String, nullable=True)
    # ownership (we'll bootstrap this column if missing at startup)
    owner_user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)

class Review(Base):
    __tablename__ = "reviews"
    id = Column(Integer, primary_key=True, index=True)
    provider_id = Column(Integer, ForeignKey("providers.id", ondelete="CASCADE"), nullable=False, index=True)
    stars = Column(Integer, nullable=False)         # 1..5
    comment = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

# Create tables & ensure owner_user_id exists on providers
@app.on_event("startup")
def on_startup():
    Base.metadata.create_all(bind=engine)
    # Bootstrap: add owner_user_id column if the table already existed without it
    with engine.connect() as conn:
        inspector = inspect(engine)
        cols = [c["name"] for c in inspector.get_columns("providers")]
        if "owner_user_id" not in cols:
            conn.execute(text("ALTER TABLE providers ADD COLUMN owner_user_id INTEGER"))
            conn.commit()

# =========================
# Schemas
# =========================
# Auth
class SignupIn(BaseModel):
    email: EmailStr
    password: str
    role: Literal["client", "provider"] = "client"

class UserOut(BaseModel):
    id: int
    email: EmailStr
    role: Literal["client", "provider"]
    class Config:
        from_attributes = True

class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"

# Providers
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

# Reviews
class ReviewIn(BaseModel):
    stars: int = Field(..., ge=1, le=5)
    comment: Optional[str] = None

class ReviewOut(BaseModel):
    id: int
    provider_id: int
    stars: int
    comment: Optional[str] = None
    created_at: datetime
    class Config:
        from_attributes = True

# Stats
class StatsOut(BaseModel):
    provider_id: int
    review_count: int
    avg_stars: Optional[float] = None

# =========================
# DB / Auth dependencies
# =========================
def get_db():
    db: Session = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def current_user(authorization: Optional[str] = Header(None), db: Session = Depends(get_db)) -> User:
    """
    Expect header: Authorization: Bearer <token>
    """
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    token = authorization.split(" ", 1)[1]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        uid = int(payload.get("sub"))
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    user = db.get(User, uid)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    return user

# =========================
# Routes: Health
# =========================
@app.get("/health")
def health():
    return {"ok": True}

# =========================
# Routes: Auth
# =========================
@app.post("/auth/signup", response_model=UserOut)
def signup(data: SignupIn, db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.email == data.email.lower()).one_or_none()
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    user = User(
        email=data.email.lower(),
        hashed_password=hash_password(data.password),
        role=data.role,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user

@app.post("/auth/login", response_model=TokenOut)
def login(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    """
    Accepts form fields: username (email), password
    """
    user = db.query(User).filter(User.email == form.username.lower()).one_or_none()
    if not user or not verify_password(form.password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Invalid email or password")
    token = create_access_token({"sub": str(user.id), "role": user.role})
    return TokenOut(access_token=token)

@app.get("/auth/me", response_model=UserOut)
def me(user: User = Depends(current_user)):
    return user

# =========================
# Routes: Providers
# =========================
@app.get("/providers", response_model=List[ProviderOut])
def list_providers(
    city: Optional[str] = Query(None),
    service_type: Optional[str] = Query(None),
    db: Session = Depends(get_db),
):
    query = db.query(Provider)
    if city:
        query = query.filter(Provider.city.ilike(f"%{city}%"))
    if service_type:
        query = query.filter(Provider.service_type.ilike(f"%{service_type}%"))
    items = query.order_by(Provider.id.asc()).all()
    return [ProviderOut.model_validate(p, from_attributes=True) for p in items]

@app.get("/providers/{provider_id}", response_model=ProviderOut)
def get_provider(provider_id: int, db: Session = Depends(get_db)):
    obj = db.get(Provider, provider_id)
    if not obj:
        raise HTTPException(status_code=404, detail="Provider not found")
    return ProviderOut.model_validate(obj, from_attributes=True)

@app.post("/providers", response_model=ProviderOut)
def create_provider(p: ProviderIn, user: User = Depends(current_user), db: Session = Depends(get_db)):
    if user.role != "provider":
        raise HTTPException(status_code=403, detail="Only providers can create providers")
    obj = Provider(
        name=p.name,
        rating=p.rating,
        service_type=p.service_type,
        city=p.city,
        owner_user_id=user.id,   # set owner
    )
    db.add(obj)
    db.commit()
    db.refresh(obj)
    return ProviderOut.model_validate(obj, from_attributes=True)

@app.get("/me/providers", response_model=List[ProviderOut])
def my_providers(user: User = Depends(current_user), db: Session = Depends(get_db)):
    if user.role != "provider":
        return []
    rows = db.query(Provider).filter(Provider.owner_user_id == user.id).order_by(Provider.id.asc()).all()
    return [ProviderOut.model_validate(p, from_attributes=True) for p in rows]

@app.delete("/providers/{provider_id}")
def delete_provider(provider_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    prov = db.get(Provider, provider_id)
    if not prov:
        raise HTTPException(status_code=404, detail="Provider not found")
    if user.role != "provider" or prov.owner_user_id != user.id:
        raise HTTPException(status_code=403, detail="Not allowed")
    db.delete(prov)
    db.commit()
    return {"ok": True}

# =========================
# Routes: Stats
# =========================
@app.get("/providers/{provider_id}/stats", response_model=StatsOut)
def provider_stats(provider_id: int, db: Session = Depends(get_db)):
    prov = db.get(Provider, provider_id)
    if not prov:
        raise HTTPException(status_code=404, detail="Provider not found")
    count = db.query(func.count(Review.id)).filter(Review.provider_id == provider_id).scalar()
    avg = db.query(func.avg(Review.stars)).filter(Review.provider_id == provider_id).scalar()
    return StatsOut(provider_id=provider_id, review_count=int(count or 0), avg_stars=float(avg) if avg is not None else None)

# =========================
# Routes: Reviews
# =========================
@app.get("/providers/{provider_id}/reviews", response_model=List[ReviewOut])
def list_reviews(provider_id: int, db: Session = Depends(get_db)):
    prov = db.get(Provider, provider_id)
    if not prov:
        raise HTTPException(status_code=404, detail="Provider not found")
    rows = (
        db.query(Review)
        .filter(Review.provider_id == provider_id)
        .order_by(Review.created_at.desc())
        .all()
    )
    return [ReviewOut.model_validate(r, from_attributes=True) for r in rows]

@app.post("/providers/{provider_id}/reviews", response_model=ReviewOut)
def create_review(provider_id: int, r: ReviewIn, db: Session = Depends(get_db)):
    prov = db.get(Provider, provider_id)
    if not prov:
        raise HTTPException(status_code=404, detail="Provider not found")

    review = Review(provider_id=provider_id, stars=r.stars, comment=r.comment)
    db.add(review)
    db.commit()
    db.refresh(review)

    # recalc provider avg
    agg = db.query(func.avg(Review.stars)).filter(Review.provider_id == provider_id).scalar()
    prov.rating = float(agg) if agg is not None else None
    db.add(prov)
    db.commit()

    return ReviewOut.model_validate(review, from_attributes=True)

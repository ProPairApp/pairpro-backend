# app/main.py
# ----- Config -----
import os
from datetime import datetime, timedelta
from typing import Optional, List

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from jose import jwt, JWTError
from passlib.context import CryptContext

from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, ForeignKey
from sqlalchemy.orm import sessionmaker, declarative_base, Session, relationship

# DB URL with dev fallback (SQLite)
RAW_DATABASE_URL = os.getenv("DATABASE_URL", "").strip()
if not RAW_DATABASE_URL:
    # Dev fallback
    DATABASE_URL = "sqlite:///./pairpro.db"
else:
    # Normalize Postgres URLs to psycopg2 driver
    url = RAW_DATABASE_URL
    # Railway/Heroku often give `postgres://...`; SQLAlchemy prefers `postgresql+psycopg2://...`
    if url.startswith("postgres://"):
        url = "postgresql+psycopg2://" + url[len("postgres://"):]
    elif url.startswith("postgresql://"):
        url = "postgresql+psycopg2://" + url[len("postgresql://"):]
    DATABASE_URL = url

JWT_SECRET = os.getenv("JWT_SECRET", "CHANGE_ME_SUPER_SECRET")
JWT_ALG = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 days
RESET_TOKEN_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ----- DB -----
# For SQLite, pass connect_args; for Postgres, leave default.
if DATABASE_URL.startswith("sqlite:///"):
    engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
else:
    engine = create_engine(DATABASE_URL, pool_pre_ping=True)

SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)
Base = declarative_base()

print(f"[PairPro] Using DB: {DATABASE_URL}")

# ----- Models -----
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(20), nullable=False, default="client")  # "client" | "provider"
    created_at = Column(DateTime, default=datetime.utcnow)

class Provider(Base):
    __tablename__ = "providers"
    id = Column(Integer, primary_key=True)
    name = Column(String(255), nullable=False)
    rating = Column(Float, nullable=True)
    service_type = Column(String(120), nullable=True)
    city = Column(String(120), nullable=True)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    owner = relationship("User")

class Review(Base):
    __tablename__ = "reviews"
    id = Column(Integer, primary_key=True)
    provider_id = Column(Integer, ForeignKey("providers.id"), nullable=False)
    stars = Column(Integer, nullable=False)
    comment = Column(String(1000), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    provider = relationship("Provider")

Base.metadata.create_all(bind=engine)

# ----- FastAPI -----
app = FastAPI(title="PairPro API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # dev-friendly; tighten later
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ----- Helpers -----
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def hash_password(pw: str) -> str:
    return pwd_context.hash(pw)

def verify_password(pw: str, hashed: str) -> bool:
    return pwd_context.verify(pw, hashed)

def create_access_token(sub: str, expires_minutes: int = ACCESS_TOKEN_EXPIRE_MINUTES) -> str:
    payload = {"sub": sub, "exp": datetime.utcnow() + timedelta(minutes=expires_minutes)}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)

def decode_token(token: str) -> int:
    payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
    return int(payload.get("sub"))

def auth_user(db: Session, email: str, pw: str) -> Optional[User]:
    user = db.query(User).filter(User.email == email.lower()).one_or_none()
    if user and verify_password(pw, user.hashed_password):
        return user
    return None

# ----- Schemas -----
class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"

class SignupIn(BaseModel):
    email: EmailStr
    password: str
    role: str  # "client" | "provider"

class UserOut(BaseModel):
    id: int
    email: EmailStr
    role: str

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

class ReviewIn(BaseModel):
    stars: int
    comment: Optional[str] = None

class ReviewOut(BaseModel):
    id: int
    provider_id: int
    stars: int
    comment: Optional[str] = None
    created_at: datetime

class ForgotIn(BaseModel):
    email: EmailStr

class ResetIn(BaseModel):
    token: str
    new_password: str

# ----- Auth deps -----
def get_current_user(db: Session = Depends(get_db), authorization: Optional[str] = None) -> User:
    # read header
    if not authorization:
        from fastapi import Request
        def _extract(req: Request):
            return req.headers.get("Authorization")
        authorization = _extract  # noqa
    # Try reading via fastapi Request directly
    from fastapi import Request
    import inspect
    frame = inspect.currentframe()
    req: Request = None  # type: ignore
    while frame:
        for v in frame.f_locals.values():
            if isinstance(v, Request):
                req = v
                break
        if req:
            break
        frame = frame.f_back
    token = None
    if req:
        auth = req.headers.get("Authorization")
        if auth and auth.lower().startswith("bearer "):
            token = auth.split(" ", 1)[1].strip()
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        uid = decode_token(token)
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    user = db.get(User, uid)
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user

# ----- Routes -----
@app.get("/health")
def health():
    return {"ok": True}

# Auth
@app.post("/auth/signup", response_model=UserOut)
def signup(data: SignupIn, db: Session = Depends(get_db)):
    exists = db.query(User).filter(User.email == data.email.lower()).first()
    if exists:
        raise HTTPException(status_code=400, detail="Email already registered")
    if data.role not in ("client", "provider"):
        raise HTTPException(status_code=400, detail="Invalid role")
    user = User(email=data.email.lower(), hashed_password=hash_password(data.password), role=data.role)
    db.add(user)
    db.commit()
    db.refresh(user)
    return UserOut(id=user.id, email=user.email, role=user.role)

@app.post("/auth/login", response_model=TokenOut)
def login(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = auth_user(db, form.username, form.password)
    if not user:
        raise HTTPException(status_code=400, detail="Invalid email or password")
    token = create_access_token(str(user.id))
    return TokenOut(access_token=token)

@app.get("/auth/me", response_model=UserOut)
def me(user: User = Depends(get_current_user)):
    return UserOut(id=user.id, email=user.email, role=user.role)

# Forgot / Reset
@app.post("/auth/forgot")
def forgot_password(data: ForgotIn, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == data.email.lower()).one_or_none()
    if not user:
        return {"ok": True}
    payload = {"sub": str(user.id), "kind": "reset", "exp": datetime.utcnow() + timedelta(minutes=RESET_TOKEN_MINUTES)}
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)
    reset_url = f"https://{os.getenv('FRONTEND_HOST','pairpro-frontend.vercel.app')}/auth/reset?t={token}"
    print("PASSWORD RESET LINK:", reset_url)  # dev helper
    return {"ok": True, "reset_url": reset_url}

@app.post("/auth/reset")
def reset_password(data: ResetIn, db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(data.token, JWT_SECRET, algorithms=[JWT_ALG])
        if payload.get("kind") != "reset":
            raise HTTPException(status_code=400, detail="Invalid token")
        uid = int(payload.get("sub"))
    except JWTError:
        raise HTTPException(status_code=400, detail="Invalid or expired token")
    user = db.get(User, uid)
    if not user:
        return {"ok": True}
    if not data.new_password or len(data.new_password) < 6:
        raise HTTPException(status_code=400, detail="Password too short")
    user.hashed_password = hash_password(data.new_password)
    db.add(user)
    db.commit()
    return {"ok": True}

# Providers
@app.get("/providers", response_model=List[ProviderOut])
def list_providers(city: Optional[str] = None, service: Optional[str] = None, db: Session = Depends(get_db)):
    q = db.query(Provider)
    if city:
        q = q.filter(Provider.city.ilike(f"%{city}%"))
    if service:
        q = q.filter(Provider.service_type.ilike(f"%{service}%"))
    rows = q.order_by(Provider.id.asc()).all()
    return [ProviderOut(id=r.id, name=r.name, rating=r.rating, service_type=r.service_type, city=r.city) for r in rows]

@app.post("/providers", response_model=ProviderOut)
def create_provider(data: ProviderIn, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if user.role != "provider":
        raise HTTPException(status_code=403, detail="Only providers can create profiles")
    obj = Provider(
        name=data.name,
        rating=data.rating,
        service_type=data.service_type,
        city=data.city,
        owner_id=user.id,
    )
    db.add(obj)
    db.commit()
    db.refresh(obj)
    return ProviderOut(id=obj.id, name=obj.name, rating=obj.rating, service_type=obj.service_type, city=obj.city)

@app.get("/providers/{provider_id}", response_model=ProviderOut)
def get_provider(provider_id: int, db: Session = Depends(get_db)):
    p = db.get(Provider, provider_id)
    if not p:
        raise HTTPException(status_code=404, detail="Provider not found")
    return ProviderOut(id=p.id, name=p.name, rating=p.rating, service_type=p.service_type, city=p.city)

# Reviews
@app.get("/providers/{provider_id}/reviews", response_model=List[ReviewOut])
def list_reviews(provider_id: int, db: Session = Depends(get_db)):
    rows = db.query(Review).filter(Review.provider_id == provider_id).order_by(Review.id.desc()).all()
    return [ReviewOut(id=r.id, provider_id=r.provider_id, stars=r.stars, comment=r.comment, created_at=r.created_at) for r in rows]

@app.post("/providers/{provider_id}/reviews", response_model=ReviewOut)
def add_review(provider_id: int, data: ReviewIn, db: Session = Depends(get_db)):
    prov = db.get(Provider, provider_id)
    if not prov:
        raise HTTPException(status_code=404, detail="Provider not found")
    r = Review(provider_id=provider_id, stars=data.stars, comment=data.comment)
    db.add(r)
    db.commit()
    db.refresh(r)
    return ReviewOut(id=r.id, provider_id=r.provider_id, stars=r.stars, comment=r.comment, created_at=r.created_at)

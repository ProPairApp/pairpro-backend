# app/main.py
import os, hashlib
from datetime import datetime, timedelta
from typing import Optional, List

from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from jose import jwt, JWTError
from passlib.context import CryptContext

from sqlalchemy import (
    create_engine, Column, Integer, String, Float, DateTime, ForeignKey, Text, Boolean, text, func
)
from sqlalchemy.orm import sessionmaker, declarative_base, Session, relationship

from sqlalchemy import inspect
from sqlalchemy.exc import SQLAlchemyError, IntegrityError


# ---------------- Config: DB with dev-safe fallback ----------------
RAW_DATABASE_URL = os.getenv("DATABASE_URL", "").strip()
if not RAW_DATABASE_URL:
    DATABASE_URL = "sqlite:///./pairpro.db"
else:
    url = RAW_DATABASE_URL
    # Use psycopg v3 driver
    if url.startswith("postgres://"):
        url = "postgresql+psycopg://" + url[len("postgres://"):]
    elif url.startswith("postgresql://"):
        url = "postgresql+psycopg://" + url[len("postgresql://"):]
    DATABASE_URL = url
    
JWT_SECRET = os.getenv("JWT_SECRET", "CHANGE_ME_SUPER_SECRET")
JWT_ALG = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 days
RESET_TOKEN_MINUTES = 30

# (Optional) Cloudinary for photo uploads
CLOUDINARY_CLOUD_NAME = os.getenv("CLOUDINARY_CLOUD_NAME")
CLOUDINARY_API_KEY = os.getenv("CLOUDINARY_API_KEY")
CLOUDINARY_API_SECRET = os.getenv("CLOUDINARY_API_SECRET")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ---------------- Engine / Session ----------------
if DATABASE_URL.startswith("sqlite:///"):
    engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
else:
    engine = create_engine(DATABASE_URL, pool_pre_ping=True)

SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)
Base = declarative_base()
print(f"[PairPro] Using DB: {DATABASE_URL}")

# ---------------- Models ----------------
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(20), nullable=False, default="client")  # client | provider
    # created_at removed for now because the DB table doesn't have it

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

# NEW: jobs / job_photos / job_plans — these tables must exist in your DB
class Job(Base):
    __tablename__ = "jobs"
    id = Column(Integer, primary_key=True)
    client_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    provider_id = Column(Integer, ForeignKey("providers.id"), nullable=True)
    title = Column(String(200), nullable=False)
    service_type = Column(String(120), nullable=False)
    city = Column(String(120), nullable=False)
    description = Column(Text, nullable=True)
    status = Column(String(40), nullable=False, default="open")  # open | assigned | done | canceled
    created_at = Column(DateTime, default=datetime.utcnow)

class JobPhoto(Base):
    __tablename__ = "job_photos"
    id = Column(Integer, primary_key=True)
    job_id = Column(Integer, ForeignKey("jobs.id"), nullable=False)
    url = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

class JobPlan(Base):
    __tablename__ = "job_plans"
    id = Column(Integer, primary_key=True)
    job_id = Column(Integer, ForeignKey("jobs.id"), nullable=False)
    text = Column(Text, nullable=False)
    done = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)

# Create tables that don't exist (safe)
Base.metadata.create_all(bind=engine)

# ---------------- FastAPI App ----------------
app = FastAPI(title="PairPro API", version="0.3.0")

# CORS: allow your Vercel site + localhost
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",            # local dev
        "https://pairpro-frontend.vercel.app",  # your production frontend
    ],
    allow_origin_regex=r"https://.*\.vercel\.app",  # allow all Vercel previews
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------- Utils ----------------
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
# --- Debug DB connectivity (temporary) ---
@app.get("/debug/db")
def debug_db(db: Session = Depends(get_db)):
    try:
        db.execute(text("SELECT 1"))
        return {"db": "ok"}
    except Exception as e:
        return {"db": "error", "detail": str(e)}

def hash_password(pw: str) -> str:
    return pwd_context.hash(pw)

def verify_password(pw: str, hashed: str) -> bool:
    return pwd_context.verify(pw, hashed)

def create_access_token(sub: str, minutes: int = ACCESS_TOKEN_EXPIRE_MINUTES) -> str:
    payload = {"sub": sub, "exp": datetime.utcnow() + timedelta(minutes=minutes)}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)

def decode_token(token: str) -> int:
    payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
    return int(payload.get("sub"))

# Extract bearer token and get current user
def get_current_user(db: Session = Depends(get_db)) -> User:
    from fastapi import Request
    request: Request

    # Find Request object from dependency stack
    import inspect
    frame = inspect.currentframe()
    request = None  # type: ignore
    while frame:
        for v in frame.f_locals.values():
            if v.__class__.__name__ == "Request":
                request = v
                break
        if request:
            break
        frame = frame.f_back  # type: ignore

    if not request:
        raise HTTPException(status_code=401, detail="Not authenticated")
    auth = request.headers.get("Authorization", "")
    token = auth.split(" ", 1)[1] if auth.lower().startswith("bearer ") else None
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

# ---------------- Schemas ----------------
class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"

class SignupIn(BaseModel):
    email: EmailStr
    password: str
    role: str  # client | provider

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

# Jobs
class JobCreateIn(BaseModel):
    title: str
    service_type: str
    city: str
    description: Optional[str] = None
    photo_urls: Optional[List[str]] = None  # Cloudinary URLs

class JobOut(BaseModel):
    id: int
    title: str
    service_type: str
    city: str
    description: Optional[str] = None
    status: str
    provider_id: Optional[int] = None
    created_at: datetime

class JobDetailOut(JobOut):
    photos: List[str] = []

class PlanItemIn(BaseModel):
    text: str

class PlanItemOut(BaseModel):
    id: int
    text: str
    done: bool
    created_at: datetime

# ---------------- Routes ----------------
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
    db.add(user); db.commit(); db.refresh(user)
    return UserOut(id=user.id, email=user.email, role=user.role)

@app.post("/auth/login", response_model=TokenOut)
def login(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == form.username.lower()).one_or_none()
    if not user or not verify_password(form.password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Invalid email or password")
    return TokenOut(access_token=create_access_token(str(user.id)))

@app.get("/auth/me", response_model=UserOut)
def me(user: User = Depends(get_current_user)):
    return UserOut(id=user.id, email=user.email, role=user.role)

@app.post("/auth/forgot")
def forgot_password(data: ForgotIn, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == data.email.lower()).one_or_none()
    if not user:
        return {"ok": True}
    payload = {"sub": str(user.id), "kind": "reset", "exp": datetime.utcnow() + timedelta(minutes=RESET_TOKEN_MINUTES)}
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)
    reset_url = f"https://{os.getenv('FRONTEND_HOST','pairpro-frontend.vercel.app')}/auth/reset?t={token}"
    print("PASSWORD RESET LINK:", reset_url)
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
    db.add(user); db.commit()
    return {"ok": True}

@app.get("/debug/tables")
def debug_tables():
    try:
        insp = inspect(engine)
        return {"tables": insp.get_table_names()}
    except Exception as e:
        return {"error": str(e)}

from sqlalchemy import inspect  # (you already added this earlier)

@app.get("/debug/columns/{table}")
def debug_columns(table: str):
    try:
        insp = inspect(engine)
        cols = []
        for c in insp.get_columns(table):
            cols.append({
                "name": c.get("name"),
                "type": str(c.get("type")),
                "nullable": c.get("nullable"),
                "default": str(c.get("default")),
            })
        return {"table": table, "columns": cols}
    except Exception as e:
        return {"error": str(e)}

# Providers + Reviews + Recommendations
@app.get("/providers", response_model=List[ProviderOut])
def list_providers(city: Optional[str] = None, service: Optional[str] = None, db: Session = Depends(get_db)):
    q = db.query(Provider)
    if city:
        q = q.filter(Provider.city.ilike(f"%{city}%"))
    if service:
        q = q.filter(Provider.service_type.ilike(f"%{service}%"))
    # DB-safe ordering: treat NULL ratings as -1 to sort lowest
    rows = q.order_by(func.coalesce(Provider.rating, -1).desc(), Provider.id.asc()).all()
    return [
        ProviderOut(id=r.id, name=r.name, rating=r.rating, service_type=r.service_type, city=r.city)
        for r in rows
    ]

@app.get("/providers/recommendations", response_model=List[ProviderOut])
def recommended(city: str, service: Optional[str] = None, db: Session = Depends(get_db)):
    q = db.query(Provider).filter(Provider.city.ilike(f"%{city}%"))
    if service:
        q = q.filter(Provider.service_type.ilike(f"%{service}%"))
    rows = q.order_by(func.coalesce(Provider.rating, -1).desc(), Provider.id.asc()).limit(10).all()
    return [
        ProviderOut(id=r.id, name=r.name, rating=r.rating, service_type=r.service_type, city=r.city)
        for r in rows
    ]

@app.post("/providers", response_model=ProviderOut)
def create_provider(data: ProviderIn, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if user.role != "provider":
        raise HTTPException(status_code=403, detail="Only providers can create profiles")
    obj = Provider(name=data.name, rating=data.rating, service_type=data.service_type, city=data.city, owner_id=user.id)
    db.add(obj); db.commit(); db.refresh(obj)
    return ProviderOut(id=obj.id, name=obj.name, rating=obj.rating, service_type=obj.service_type, city=obj.city)

@app.get("/providers/{provider_id}", response_model=ProviderOut)
def get_provider(provider_id: int, db: Session = Depends(get_db)):
    p = db.get(Provider, provider_id)
    if not p:
        raise HTTPException(status_code=404, detail="Provider not found")
    return ProviderOut(id=p.id, name=p.name, rating=p.rating, service_type=p.service_type, city=p.city)

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
    db.add(r); db.commit(); db.refresh(r)
    return ReviewOut(id=r.id, provider_id=r.provider_id, stars=r.stars, comment=r.comment, created_at=r.created_at)

@app.get("/debug/providers")
def debug_providers(db: Session = Depends(get_db)):
    try:
        rows = db.query(Provider).all()
        return {"count": len(rows)}
    except Exception as e:
        return {"error": str(e)}

# ---------------- Jobs (Hires) ----------------
@app.post("/jobs", response_model=JobDetailOut)
def create_job(payload: JobCreateIn, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if user.role != "client":
        raise HTTPException(status_code=403, detail="Only clients can create jobs")
    job = Job(
        client_id=user.id,
        title=payload.title.strip(),
        service_type=payload.service_type.strip(),
        city=payload.city.strip(),
        description=(payload.description or "").strip() or None,
        status="open",
    )
    db.add(job); db.commit(); db.refresh(job)

    photos = []
    if payload.photo_urls:
        for url in payload.photo_urls[:12]:
            jp = JobPhoto(job_id=job.id, url=url)
            db.add(jp); photos.append(url)
        db.commit()

    return JobDetailOut(
        id=job.id, title=job.title, service_type=job.service_type, city=job.city,
        description=job.description, status=job.status, provider_id=job.provider_id,
        created_at=job.created_at, photos=photos
    )

@app.get("/jobs/mine", response_model=List[JobOut])
def my_jobs(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    q = db.query(Job)
    if user.role == "client":
        q = q.filter(Job.client_id == user.id)
    else:
        # Provider sees jobs assigned to any provider profile they own
        my_provs = db.query(Provider.id).filter(Provider.owner_id == user.id).all()
        ids = [p[0] for p in my_provs]
        q = q.filter(Job.provider_id.in_(ids)) if ids else q.filter(Job.id == -1)
    rows = q.order_by(Job.id.desc()).all()
    return [JobOut(
        id=r.id, title=r.title, service_type=r.service_type, city=r.city,
        description=r.description, status=r.status, provider_id=r.provider_id, created_at=r.created_at
    ) for r in rows]

@app.get("/jobs/{job_id}", response_model=JobDetailOut)
def job_detail(job_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    job = db.get(Job, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    photos = [p.url for p in db.query(JobPhoto).filter(JobPhoto.job_id == job.id).order_by(JobPhoto.id.asc()).all()]
    return JobDetailOut(
        id=job.id, title=job.title, service_type=job.service_type, city=job.city,
        description=job.description, status=job.status, provider_id=job.provider_id,
        created_at=job.created_at, photos=photos
    )

@app.patch("/jobs/{job_id}/assign/{provider_id}", response_model=JobOut)
def assign_job(job_id: int, provider_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    job = db.get(Job, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    if user.role != "client" or job.client_id != user.id:
        raise HTTPException(status_code=403, detail="Not allowed")
    prov = db.get(Provider, provider_id)
    if not prov:
        raise HTTPException(status_code=404, detail="Provider not found")
    job.provider_id = provider_id
    job.status = "assigned"
    db.add(job); db.commit(); db.refresh(job)
    return JobOut(
        id=job.id, title=job.title, service_type=job.service_type, city=job.city,
        description=job.description, status=job.status, provider_id=job.provider_id, created_at=job.created_at
    )

# Plans per Job
@app.get("/jobs/{job_id}/plans", response_model=List[PlanItemOut])
def list_plans(job_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    items = db.query(JobPlan).filter(JobPlan.job_id == job_id).order_by(JobPlan.id.asc()).all()
    return [PlanItemOut(id=i.id, text=i.text, done=i.done, created_at=i.created_at) for i in items]

@app.post("/jobs/{job_id}/plans", response_model=PlanItemOut)
def add_plan(job_id: int, payload: PlanItemIn, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    job = db.get(Job, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    if user.role != "client" or job.client_id != user.id:
        raise HTTPException(status_code=403, detail="Not allowed")
    it = JobPlan(job_id=job_id, text=payload.text.strip()[:2000])
    db.add(it); db.commit(); db.refresh(it)
    return PlanItemOut(id=it.id, text=it.text, done=it.done, created_at=it.created_at)

# ---------------- Cloudinary upload signing ----------------
@app.post("/uploads/sign")
def sign_upload(user: User = Depends(get_current_user)):
    """
    Returns a signature + timestamp for direct upload to Cloudinary.
    Frontend will POST to: https://api.cloudinary.com/v1_1/<cloud_name>/image/upload
    fields: file, api_key, timestamp, signature, (optionally folder)
    """
    if not (CLOUDINARY_CLOUD_NAME and CLOUDINARY_API_KEY and CLOUDINARY_API_SECRET):
        raise HTTPException(status_code=500, detail="Cloudinary not configured")
    ts = int(datetime.utcnow().timestamp())
    to_sign = f"timestamp={ts}{CLOUDINARY_API_SECRET}"
    signature = hashlib.sha1(to_sign.encode("utf-8")).hexdigest()
    return {"cloud_name": CLOUDINARY_CLOUD_NAME, "api_key": CLOUDINARY_API_KEY, "timestamp": ts, "signature": signature}

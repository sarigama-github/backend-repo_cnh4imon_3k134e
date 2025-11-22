import os
from datetime import datetime, timedelta, timezone
from typing import Optional, List

from fastapi import FastAPI, Depends, HTTPException, status, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr, Field
from bson import ObjectId

from database import db

# App setup
app = FastAPI(title="Store Rating App")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security
SECRET_KEY = os.getenv("JWT_SECRET", "change-this-secret")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

# Helpers

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(password: str, password_hash: str) -> bool:
    return pwd_context.verify(password, password_hash)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# Pydantic models
class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: dict

class RegisterRequest(BaseModel):
    name: str
    email: EmailStr
    password: str

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class StoreIn(BaseModel):
    name: str
    description: Optional[str] = None
    address: Optional[str] = None

class StoreOut(BaseModel):
    id: str
    name: str
    description: Optional[str] = None
    address: Optional[str] = None
    owner_id: str
    average_rating: float = 0
    review_count: int = 0

class ReviewIn(BaseModel):
    rating: int = Field(..., ge=1, le=5)
    comment: Optional[str] = None

# Dependency: get current user
async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = db["user"].find_one({"_id": ObjectId(user_id)})
    if not user:
        raise credentials_exception
    user["id"] = str(user.pop("_id"))
    return user

# Role guard
def require_role(*roles):
    async def _guard(user=Depends(get_current_user)):
        if user.get("role") not in roles:
            raise HTTPException(status_code=403, detail="Forbidden")
        return user
    return _guard

# Utilities

def serialize_store(doc) -> dict:
    return {
        "id": str(doc["_id"]),
        "name": doc.get("name"),
        "description": doc.get("description"),
        "address": doc.get("address"),
        "owner_id": str(doc.get("owner_id")) if isinstance(doc.get("owner_id"), ObjectId) else doc.get("owner_id"),
        "average_rating": round(float(doc.get("average_rating", 0)), 2),
        "review_count": int(doc.get("review_count", 0)),
    }

# Routes
@app.get("/")
def root():
    return {"message": "Store Rating App API"}

@app.get("/test")
def test_database():
    try:
        collections = db.list_collection_names()
        return {"backend": "ok", "database": "ok", "collections": collections}
    except Exception as e:
        return {"backend": "ok", "database": f"error: {str(e)[:80]}"}

# Auth
@app.post("/auth/register")
def register(payload: RegisterRequest):
    existing = db["user"].find_one({"email": payload.email})
    if existing:
        raise HTTPException(400, detail="Email already registered")
    user_doc = {
        "name": payload.name,
        "email": payload.email,
        "password_hash": hash_password(payload.password),
        "role": "user",
        "is_active": True,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    res = db["user"].insert_one(user_doc)
    user_doc["id"] = str(res.inserted_id)
    user_doc.pop("_id", None)
    user_doc.pop("password_hash", None)
    return user_doc

@app.post("/auth/login", response_model=TokenResponse)
def login(payload: LoginRequest):
    user = db["user"].find_one({"email": payload.email})
    if not user or not verify_password(payload.password, user.get("password_hash", "")):
        raise HTTPException(status_code=400, detail="Invalid email or password")
    if not user.get("is_active", True):
        raise HTTPException(status_code=403, detail="Account disabled")
    access_token = create_access_token({"sub": str(user["_id"]), "role": user.get("role", "user")})
    user_out = {"id": str(user["_id"]), "name": user.get("name"), "email": user.get("email"), "role": user.get("role", "user")}
    return TokenResponse(access_token=access_token, user=user_out)

@app.get("/me")
def me(user=Depends(get_current_user)):
    u = {"id": user["id"], "name": user.get("name"), "email": user.get("email"), "role": user.get("role")}
    return u

# Stores
@app.post("/stores", response_model=StoreOut)
def create_store(payload: StoreIn, user=Depends(require_role("owner", "admin"))):
    doc = {
        "name": payload.name,
        "description": payload.description,
        "address": payload.address,
        "owner_id": ObjectId(user["id"]) if user.get("role") == "owner" else ObjectId(user["id"]),
        "average_rating": 0.0,
        "review_count": 0,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    res = db["store"].insert_one(doc)
    doc["_id"] = res.inserted_id
    return serialize_store(doc)

@app.get("/stores", response_model=List[StoreOut])
def list_stores():
    stores = db["store"].find({}).sort("created_at", -1)
    return [serialize_store(s) for s in stores]

@app.get("/stores/my", response_model=List[StoreOut])
def my_stores(user=Depends(require_role("owner", "admin"))):
    query = {}
    if user.get("role") == "owner":
        query = {"owner_id": ObjectId(user["id"])}
    stores = db["store"].find(query).sort("created_at", -1)
    return [serialize_store(s) for s in stores]

@app.patch("/stores/{store_id}", response_model=StoreOut)
def update_store(store_id: str, payload: StoreIn, user=Depends(require_role("owner", "admin"))):
    store = db["store"].find_one({"_id": ObjectId(store_id)})
    if not store:
        raise HTTPException(404, "Store not found")
    if user.get("role") == "owner" and store.get("owner_id") != ObjectId(user["id"]):
        raise HTTPException(403, "Forbidden")
    update = {"$set": {"name": payload.name, "description": payload.description, "address": payload.address, "updated_at": datetime.now(timezone.utc)}}
    db["store"].update_one({"_id": ObjectId(store_id)}, update)
    store = db["store"].find_one({"_id": ObjectId(store_id)})
    return serialize_store(store)

@app.delete("/stores/{store_id}")
def delete_store(store_id: str, user=Depends(require_role("owner", "admin"))):
    store = db["store"].find_one({"_id": ObjectId(store_id)})
    if not store:
        raise HTTPException(404, "Store not found")
    if user.get("role") == "owner" and store.get("owner_id") != ObjectId(user["id"]):
        raise HTTPException(403, "Forbidden")
    db["store"].delete_one({"_id": ObjectId(store_id)})
    db["review"].delete_many({"store_id": ObjectId(store_id)})
    return {"deleted": True}

# Reviews
@app.get("/stores/{store_id}/reviews")
def list_reviews(store_id: str):
    reviews = db["review"].find({"store_id": ObjectId(store_id)}).sort("created_at", -1)
    out = []
    for r in reviews:
        out.append({
            "id": str(r["_id"]),
            "store_id": store_id,
            "user_id": str(r.get("user_id")),
            "rating": r.get("rating"),
            "comment": r.get("comment"),
            "created_at": r.get("created_at")
        })
    return out

@app.post("/stores/{store_id}/reviews")
def add_review(store_id: str, payload: ReviewIn, user=Depends(require_role("user", "owner", "admin"))):
    store = db["store"].find_one({"_id": ObjectId(store_id)})
    if not store:
        raise HTTPException(404, "Store not found")
    # A user can only have one review per store; update if exists
    existing = db["review"].find_one({"store_id": ObjectId(store_id), "user_id": ObjectId(user["id"])})
    now = datetime.now(timezone.utc)
    if existing:
        db["review"].update_one({"_id": existing["_id"]}, {"$set": {"rating": payload.rating, "comment": payload.comment, "updated_at": now}})
    else:
        db["review"].insert_one({
            "store_id": ObjectId(store_id),
            "user_id": ObjectId(user["id"]),
            "rating": payload.rating,
            "comment": payload.comment,
            "created_at": now,
            "updated_at": now,
        })
    # Recalculate store rating
    agg = list(db["review"].aggregate([
        {"$match": {"store_id": ObjectId(store_id)}},
        {"$group": {"_id": "$store_id", "avg": {"$avg": "$rating"}, "count": {"$sum": 1}}}
    ]))
    avg = float(agg[0]["avg"]) if agg else 0.0
    cnt = int(agg[0]["count"]) if agg else 0
    db["store"].update_one({"_id": ObjectId(store_id)}, {"$set": {"average_rating": avg, "review_count": cnt, "updated_at": now}})
    store = db["store"].find_one({"_id": ObjectId(store_id)})
    return serialize_store(store)

@app.delete("/reviews/{review_id}")
def delete_review(review_id: str, user=Depends(require_role("user", "owner", "admin"))):
    review = db["review"].find_one({"_id": ObjectId(review_id)})
    if not review:
        raise HTTPException(404, "Review not found")
    # Ownership: user can delete own, owner/admin can delete reviews on their stores
    if user.get("role") == "user" and review.get("user_id") != ObjectId(user["id"]):
        raise HTTPException(403, "Forbidden")
    if user.get("role") == "owner":
        store = db["store"].find_one({"_id": review.get("store_id")})
        if not store or store.get("owner_id") != ObjectId(user["id"]):
            raise HTTPException(403, "Forbidden")
    db["review"].delete_one({"_id": ObjectId(review_id)})
    # update store rating
    store_id = review.get("store_id")
    agg = list(db["review"].aggregate([
        {"$match": {"store_id": store_id}},
        {"$group": {"_id": "$store_id", "avg": {"$avg": "$rating"}, "count": {"$sum": 1}}}
    ]))
    avg = float(agg[0]["avg"]) if agg else 0.0
    cnt = int(agg[0]["count"]) if agg else 0
    db["store"].update_one({"_id": store_id}, {"$set": {"average_rating": avg, "review_count": cnt, "updated_at": datetime.now(timezone.utc)}})
    return {"deleted": True}

# Admin endpoints
@app.get("/admin/users")
def admin_users(user=Depends(require_role("admin"))):
    users = db["user"].find({}).sort("created_at", -1)
    out = []
    for u in users:
        out.append({"id": str(u["_id"]), "name": u.get("name"), "email": u.get("email"), "role": u.get("role", "user"), "is_active": u.get("is_active", True)})
    return out

@app.patch("/admin/users/{user_id}")
def admin_update_user(user_id: str, updates: dict = Body(...), user=Depends(require_role("admin"))):
    allowed = {"role", "is_active", "name"}
    set_fields = {k: v for k, v in updates.items() if k in allowed}
    if not set_fields:
        raise HTTPException(400, "No valid fields")
    db["user"].update_one({"_id": ObjectId(user_id)}, {"$set": set_fields})
    u = db["user"].find_one({"_id": ObjectId(user_id)})
    return {"id": str(u["_id"]), "name": u.get("name"), "email": u.get("email"), "role": u.get("role"), "is_active": u.get("is_active", True)}

@app.delete("/admin/users/{user_id}")
def admin_delete_user(user_id: str, user=Depends(require_role("admin"))):
    db["user"].delete_one({"_id": ObjectId(user_id)})
    return {"deleted": True}

@app.get("/admin/stores")
def admin_stores(user=Depends(require_role("admin"))):
    stores = db["store"].find({}).sort("created_at", -1)
    return [serialize_store(s) for s in stores]

@app.delete("/admin/stores/{store_id}")
def admin_delete_store(store_id: str, user=Depends(require_role("admin"))):
    db["store"].delete_one({"_id": ObjectId(store_id)})
    db["review"].delete_many({"store_id": ObjectId(store_id)})
    return {"deleted": True}

@app.get("/admin/reviews")
def admin_reviews(user=Depends(require_role("admin"))):
    reviews = db["review"].find({}).sort("created_at", -1)
    out = []
    for r in reviews:
        out.append({"id": str(r["_id"]), "store_id": str(r.get("store_id")), "user_id": str(r.get("user_id")), "rating": r.get("rating"), "comment": r.get("comment")})
    return out

@app.delete("/admin/reviews/{review_id}")
def admin_delete_review(review_id: str, user=Depends(require_role("admin"))):
    db["review"].delete_one({"_id": ObjectId(review_id)})
    return {"deleted": True}

# Seed/demo endpoint
@app.post("/seed")
def seed():
    # Create demo users if not exist
    def ensure_user(name, email, password, role):
        u = db["user"].find_one({"email": email})
        if u:
            return u
        doc = {"name": name, "email": email, "password_hash": hash_password(password), "role": role, "is_active": True, "created_at": datetime.now(timezone.utc), "updated_at": datetime.now(timezone.utc)}
        db["user"].insert_one(doc)
        return doc

    admin = ensure_user("Admin", "admin@demo.com", "admin123", "admin")
    owner = ensure_user("Owner", "owner@demo.com", "owner123", "owner")
    user = ensure_user("User", "user@demo.com", "user123", "user")

    # Create sample stores for owner
    owner_id = owner.get("_id") or db["user"].find_one({"email": "owner@demo.com"})["_id"]
    if db["store"].count_documents({"owner_id": owner_id}) == 0:
        s1 = db["store"].insert_one({"name": "Blue Cafe", "description": "Cozy coffee and snacks", "address": "123 Main St", "owner_id": owner_id, "average_rating": 0.0, "review_count": 0, "created_at": datetime.now(timezone.utc), "updated_at": datetime.now(timezone.utc)})
        s2 = db["store"].insert_one({"name": "Tech Hub", "description": "Gadgets and accessories", "address": "45 Market Ave", "owner_id": owner_id, "average_rating": 0.0, "review_count": 0, "created_at": datetime.now(timezone.utc), "updated_at": datetime.now(timezone.utc)})
        # Add a review from demo user
        db["review"].insert_one({"store_id": s1.inserted_id, "user_id": db["user"].find_one({"email": "user@demo.com"})["_id"], "rating": 5, "comment": "Great coffee!", "created_at": datetime.now(timezone.utc), "updated_at": datetime.now(timezone.utc)})
        # Recalc ratings
        for sid in [s1.inserted_id, s2.inserted_id]:
            agg = list(db["review"].aggregate([
                {"$match": {"store_id": sid}},
                {"$group": {"_id": "$store_id", "avg": {"$avg": "$rating"}, "count": {"$sum": 1}}}
            ]))
            avg = float(agg[0]["avg"]) if agg else 0.0
            cnt = int(agg[0]["count"]) if agg else 0
            db["store"].update_one({"_id": sid}, {"$set": {"average_rating": avg, "review_count": cnt}})

    return {
        "demo_accounts": {
            "admin": {"email": "admin@demo.com", "password": "admin123"},
            "owner": {"email": "owner@demo.com", "password": "owner123"},
            "user": {"email": "user@demo.com", "password": "user123"},
        }
    }

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)

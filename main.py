from fastapi import FastAPI, Depends, HTTPException, Header
from pydantic import BaseModel
import bcrypt
from jose import jwt, JWTError
from datetime import datetime, timedelta, timezone
import secrets
import hashlib

ALGORITHM = "RS256"
ACCESS_TOKEN_TTL_MINUTES = 15
REFRESH_TOKEN_TTL_DAYS = 7

with open("private_key.pem") as f:
    PRIVATE_KEY = f.read()

with open("public_key.pem") as f:
    PUBLIC_KEY = f.read()

app = FastAPI()


@app.get("/health")
def health():
    return {"status": "ok"}


# ---------- users ----------

class RegisterRequest(BaseModel):
    email: str
    password: str

# in-memory "database" — just a dict for now, no real DB yet
fake_users_db: dict[str, dict] = {}

@app.post("/register")
def register(req: RegisterRequest):
    if req.email in fake_users_db:
        return {"error": "user already exists"}

    password_bytes = req.password.encode("utf-8")
    hashed = bcrypt.hashpw(password_bytes, bcrypt.gensalt())

    fake_users_db[req.email] = {"email": req.email, "hashed_password": hashed}
    return {"message": "registered", "user": {"email": req.email}}

# since fake_users_db is a in-memory "database", it restarts evey time you restrat the server.


# ---------- access tokens (JWT) ----------

def create_access_token(email: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": email,                                    # "subject" - who this token is about
        "iat": now,                                       # issued at
        "exp": now + timedelta(minutes=ACCESS_TOKEN_TTL_MINUTES),  # expiry
    }
    return jwt.encode(payload, PRIVATE_KEY, algorithm=ALGORITHM)


def get_current_user(authorization: str = Header(None)) -> str:
    if authorization is None or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="missing or malformed token")

    token = authorization.removeprefix("Bearer ")
    try:
        payload = jwt.decode(token, PUBLIC_KEY, algorithms=[ALGORITHM])
    except JWTError:
        raise HTTPException(status_code=401, detail="invalid or expired token")

    return payload["sub"]  # the email


@app.get("/me")
def me(current_user: str = Depends(get_current_user)):
    return {"email": current_user}


# ---------- refresh tokens (opaque, hashed, rotating) ----------

# hashed token -> {"email", "expires_at", "revoked", "family_id"}
fake_refresh_tokens: dict[str, dict] = {}

def hash_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()

def create_refresh_token(email: str, family_id: str = None) -> str:
    raw_token = secrets.token_urlsafe(32)
    hashed = hash_token(raw_token)

    if family_id is None:
        family_id = secrets.token_urlsafe(16)  # new login = new family

    fake_refresh_tokens[hashed] = {
        "email": email,
        "expires_at": datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_TTL_DAYS),
        "revoked": False,
        "family_id": family_id,
    }
    return raw_token


# ---------- login ----------

class LoginRequest(BaseModel):
    email: str
    password: str

@app.post("/login")
def login(req: LoginRequest):
    user = fake_users_db.get(req.email)
    if user is None:
        return {"error": "invalid credentials"}

    password_bytes = req.password.encode("utf-8")
    if not bcrypt.checkpw(password_bytes, user["hashed_password"]):
        return {"error": "invalid credentials"}

    access_token = create_access_token(email=req.email)
    refresh_token = create_refresh_token(email=req.email)
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }


# ---------- refresh ----------

class RefreshRequest(BaseModel):
    refresh_token: str

@app.post("/refresh")
def refresh(req: RefreshRequest):
    hashed = hash_token(req.refresh_token)
    record = fake_refresh_tokens.get(hashed)

    if record is None:
        raise HTTPException(status_code=401, detail="invalid refresh token")

    if record["revoked"]:
        # reuse of a dead token = theft signal. Kill the whole family.
        for r in fake_refresh_tokens.values():
            if r["family_id"] == record["family_id"]:
                r["revoked"] = True
        raise HTTPException(status_code=401, detail="token reuse detected, all sessions revoked")

    if datetime.now(timezone.utc) > record["expires_at"]:
        raise HTTPException(status_code=401, detail="refresh token expired")

    # rotate: kill this one, issue a new one in the same family
    record["revoked"] = True
    new_refresh_token = create_refresh_token(email=record["email"], family_id=record["family_id"])
    new_access_token = create_access_token(email=record["email"])

    return {
        "access_token": new_access_token,
        "refresh_token": new_refresh_token,
        "token_type": "bearer",
    }
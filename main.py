from fastapi import FastAPI, Depends, HTTPException, Header
from pydantic import BaseModel
import bcrypt
from jose import jwt, JWTError
from datetime import datetime, timedelta, timezone
import secrets

SECRET_KEY = "change-me-later"   # deliberately bad for now — we'll fix this
ALGORITHM = "RS256"
ACCESS_TOKEN_TTL_MINUTES = 15
REFRESH_TOKEN_TTL_DAYS = 7

with open("private_key.pem") as f:
    PRIVATE_KEY = f.read()

with open("public_key.pem") as f:
    PUBLIC_KEY = f.read()

def create_access_token(email: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": email,                                    # "subject" - who this token is about
        "iat": now,                                       # issued at
        "exp": now + timedelta(minutes=ACCESS_TOKEN_TTL_MINUTES),  # expiry
    }
    return jwt.encode(payload, PRIVATE_KEY, algorithm=ALGORITHM)

app = FastAPI()

@app.get("/health")
def health():
    return {"status": "ok"}

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

# naive in-memory store: token string -> email
fake_refresh_tokens: dict[str, str] = {}

def create_refresh_token(email: str) -> str:
    token = secrets.token_urlsafe(32)
    fake_refresh_tokens[token] = email
    return token

class RefreshRequest(BaseModel):
    refresh_token: str

@app.post("/refresh")
def refresh(req: RefreshRequest):
    email = fake_refresh_tokens.get(req.refresh_token)
    if email is None:
        raise HTTPException(status_code=401, detail="invalid refresh token")
    
    new_access_token = create_access_token(email=email)
    return {"access_token": new_access_token, "token_type": "bearer"}
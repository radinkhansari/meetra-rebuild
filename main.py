from fastapi import FastAPI
from pydantic import BaseModel
import bcrypt

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
    
    return {"message": "login successful", "email": req.email}
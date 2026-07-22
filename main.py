from fastapi import FastAPI
from pydantic import BaseModel

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
    fake_users_db[req.email] = {"email": req.email, "password": req.password}
    return {"message": "registered", "user": fake_users_db[req.email]}

# since fake_users_db is a in-memory "database", it restarts evey time you restrat the server.
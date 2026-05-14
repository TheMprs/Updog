import os
from fastapi import FastAPI, HTTPException, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv

from scorer import analyze

load_dotenv()

API_TOKEN = os.getenv("API_TOKEN")
if not API_TOKEN:
    raise RuntimeError("API_TOKEN env var is not set")

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://mail.google.com"],
    allow_methods=["POST"],
    allow_headers=["Authorization", "Content-Type"],
)

bearer = HTTPBearer()


def verify_token(credentials: HTTPAuthorizationCredentials = Security(bearer)):
    if credentials.credentials != API_TOKEN:
        raise HTTPException(status_code=401, detail="Invalid token")


class AnalyzeRequest(BaseModel):
    raw_email: str


@app.post("/analyze")
def analyze_email(
    body: AnalyzeRequest,
    credentials: HTTPAuthorizationCredentials = Security(bearer),
):
    verify_token(credentials)
    if not body.raw_email.strip():
        raise HTTPException(status_code=400, detail="raw_email is empty")
    return analyze(body.raw_email)


@app.get("/health")
def health():
    return {"status": "ok"}

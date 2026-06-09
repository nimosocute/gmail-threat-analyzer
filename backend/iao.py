from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.routes import router

app = FastAPI(
    title="Phishing Mail Detection Backend",
    version="1.0.0",
    description="Backend API cho Chrome Extension quét phishing mail",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)


@app.get("/")
def root():
    return {
        "ok": True,
        "message": "Phishing backend is running",
        "docs": "/docs",
        "health": "/health",
        "api_health": "/api/health",
    }   


@app.get("/health")
def root_health():
    return {
        "ok": True,
        "service": "phishing-backend",
        "source": "root",
    }
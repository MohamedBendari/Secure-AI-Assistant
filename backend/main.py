
from fastapi import FastAPI

from backend.database import engine, Base
from backend import models
from backend.routes.auth import router as auth_router
from backend.routes.privacy import router as privacy_router
from backend.routes.chat import router as chat_router

# Create database tables
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Secure AI Assistant",
    description="AI Chatbot with Multi-Layer Security",
    version="1.0.0"
)

# Register authentication routes
app.include_router(auth_router)
app.include_router(privacy_router)
app.include_router(chat_router)


@app.get("/")
def home():
    return {
        "message": "Welcome to Secure AI Assistant",
        "status": "Running Successfully"
    }


@app.get("/health")
def health_check():
    return {
        "status": "Healthy",
        "database": "Connected"
    }

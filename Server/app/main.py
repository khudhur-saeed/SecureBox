from fastapi import FastAPI
from app.api.v1.router import api_v1_router

app = FastAPI(
    title="SecureBox API",
    description="Zero-Knowledge Password Manager REST Backend",
    version="1.0.0",
)

app.include_router(api_v1_router)


@app.get("/health", tags=["System"])
async def health_check():
    return {"status": "healthy", "service": "SecureBox Backend"}
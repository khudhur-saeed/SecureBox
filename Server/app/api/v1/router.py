from fastapi import APIRouter
from app.api.v1.endpoints.auth import router as auth_router
from app.api.v1.endpoints.vault import router as vault_router

api_v1_router = APIRouter(prefix="/api/v1")

api_v1_router.include_router(auth_router) 
api_v1_router.include_router(vault_router) 




"""API v1 router aggregating AegisAI control-plane endpoints."""

from fastapi import APIRouter

from app.api.v1.assessments import router as assessments_router
from app.api.v1.auth import router as auth_router
from app.api.v1.findings import router as findings_router
from app.api.v1.frameworks import router as frameworks_router
from app.api.v1.reports import router as reports_router
from app.api.v1.targets import router as targets_router

api_v1_router = APIRouter()
api_v1_router.include_router(auth_router)
api_v1_router.include_router(targets_router)
api_v1_router.include_router(assessments_router)
api_v1_router.include_router(findings_router)
api_v1_router.include_router(frameworks_router)
api_v1_router.include_router(reports_router)

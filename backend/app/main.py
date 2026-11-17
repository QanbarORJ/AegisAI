"""AegisAI FastAPI Control Plane Application Factory, Lifespan, Exception Handlers, and CORS."""

import logging
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Request, status
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.orm import Session

import app.models  # noqa: F401 - ensure all ORM models are registered
from app import __version__
from app.api.v1 import api_v1_router
from app.core.config import get_settings
from app.core.exceptions import AegisError
from app.core.logging import configure_logging
from app.db.base import Base
from app.db.session import engine, get_db
from app.engine.framework_mapper import ensure_knowledge_base_seeded

logger = logging.getLogger("aegis.main")


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncGenerator[None, None]:
    """Initialize structured logging, ensure database schema exists, and seed knowledge base on startup."""
    settings = get_settings()
    configure_logging(settings.aegis_log_level)
    Base.metadata.create_all(bind=engine)
    with Session(bind=engine) as db:
        ensure_knowledge_base_seeded(db)
    logger.info(
        "AegisAI Control Plane started (version=%s, env=%s, runner=%s)",
        __version__,
        settings.aegis_env,
        settings.aegis_runner_mode,
    )
    yield
    logger.info("AegisAI Control Plane shutting down.")


def create_app() -> FastAPI:
    """Construct and configure the AegisAI FastAPI application."""
    settings = get_settings()
    configure_logging(settings.aegis_log_level)

    app = FastAPI(
        title=settings.aegis_app_name,
        version=__version__,
        description=(
            "Enterprise AI Application Security Assessment & Red Teaming Platform "
            "(LLM, RAG, and Autonomous Agent Security)"
        ),
        lifespan=lifespan,
    )

    # CORS configuration
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins_list,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Global Domain Exception Handler
    @app.exception_handler(AegisError)
    async def aegis_error_handler(_request: Request, exc: AegisError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": {
                    "code": exc.code,
                    "message": exc.message,
                    "details": exc.details,
                }
            },
        )

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(
        _request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={
                "error": {
                    "code": "REQUEST_VALIDATION_FAILED",
                    "message": "Request payload failed schema validation.",
                    "details": {"errors": jsonable_encoder(exc.errors())},
                }
            },
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(
        _request: Request, exc: Exception
    ) -> JSONResponse:
        logger.exception("Unhandled server exception: %s", exc)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "error": {
                    "code": "INTERNAL_SERVER_ERROR",
                    "message": "An unexpected internal error occurred.",
                    "details": {},
                }
            },
        )

    def _build_health_payload(db: Session) -> dict[str, object]:
        db_ok = False
        try:
            db.execute(text("SELECT 1"))
            db_ok = True
        except Exception as exc:
            logger.error("Health check database ping failed: %s", exc)

        return {
            "status": "healthy" if db_ok else "degraded",
            "service": settings.aegis_app_name,
            "version": __version__,
            "environment": settings.aegis_env,
            "runner_mode": settings.aegis_runner_mode,
            "database_connected": db_ok,
        }

    @app.get("/health", tags=["System Health"])
    def root_health_check(db: Session = Depends(get_db)) -> dict[str, object]:
        """Root health endpoint for container orchestrators and load balancers."""
        return _build_health_payload(db)

    @app.get(f"{settings.aegis_api_v1_prefix}/health", tags=["System Health"])
    def api_v1_health_check(db: Session = Depends(get_db)) -> dict[str, object]:
        """Versioned API health check endpoint."""
        return _build_health_payload(db)

    app.include_router(api_v1_router, prefix=settings.aegis_api_v1_prefix)
    return app


app = create_app()

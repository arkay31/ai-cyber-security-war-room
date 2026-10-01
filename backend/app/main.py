import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.app.config import settings
from backend.app.database import init_db, SessionLocal
from backend.app.services.mitre_service import MitreService
from backend.app.routes import health, events, incidents, mitre, dashboard, analytics, verification, responses
from backend.app.models.knowledge import KnowledgeEmbedding
from scripts.ingest_knowledge import ingest_knowledge

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s"
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Initializing AI Cyber Security War Room database...")
    init_db()
    with SessionLocal() as db:
        seeded = MitreService.seed_techniques(db)
        if seeded > 0:
            logger.info(f"Successfully seeded {seeded} MITRE techniques.")
        kb_count = db.query(KnowledgeEmbedding).count()
        if kb_count == 0:
            logger.info("Knowledge base empty, auto-ingesting standard security playbooks...")
            try:
                ingest_knowledge()
            except Exception as e:
                logger.warning(f"Auto-ingestion encountered notice: {e}")
    logger.info("War Room backend startup complete.")
    yield
    logger.info("War Room backend shutting down.")


app = FastAPI(
    title=settings.APP_NAME,
    version="1.0.0",
    description="AI-assisted Security Operations and Incident Investigation Platform API",
    lifespan=lifespan
)

# CORS middleware for Next.js frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS or ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API routers
app.include_router(health.router)
app.include_router(events.router)
app.include_router(incidents.router)
app.include_router(mitre.router)
app.include_router(dashboard.router)
app.include_router(analytics.router)
app.include_router(verification.router)
app.include_router(responses.router)


@app.get("/")
def root():
    return {
        "service": settings.APP_NAME,
        "version": "1.0.0",
        "docs": "/docs",
        "health": "/api/health"
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.app.main:app", host=settings.HOST, port=settings.PORT, reload=settings.DEBUG)

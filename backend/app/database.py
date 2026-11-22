import os
from sqlalchemy import create_engine, text
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy.pool import StaticPool
from backend.app.config import settings

db_url = os.environ.get("TEST_DATABASE_URL") or settings.DATABASE_URL
engine_kwargs = {}
if "sqlite" in db_url:
    engine_kwargs = {"connect_args": {"check_same_thread": False}, "poolclass": StaticPool}
else:
    engine_kwargs = {"pool_pre_ping": True, "pool_size": 10, "max_overflow": 20}

engine = create_engine(db_url, **engine_kwargs)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """Ensure extensions and database tables are created."""
    import backend.app.models  # noqa: F401 - Register models with Base.metadata
    with engine.connect() as conn:
        try:
            conn.execute(text("CREATE EXTENSION IF NOT EXISTS vector;"))
            conn.commit()
        except Exception as e:
            # Expected on SQLite test runs or when vector extension is already managed
            pass
    Base.metadata.create_all(bind=engine)

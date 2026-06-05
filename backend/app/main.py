from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.api import alerts, investigations, settings, auth
from app.config import get_settings
from app.database import init_db, seed_test_data


@asynccontextmanager
async def lifespan(_app: FastAPI):
    Path("data").mkdir(parents=True, exist_ok=True)
    await init_db()
    await seed_test_data()
    yield


settings_cfg = get_settings()
app = FastAPI(title=settings_cfg.app_name, version=settings_cfg.app_version, lifespan=lifespan)

origins = [o.strip() for o in settings_cfg.cors_origins.split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins or ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(alerts.router)
app.include_router(investigations.router)
app.include_router(settings.router)


@app.get("/api/health")
async def health():
    return {"status": "ok", "version": settings_cfg.app_version}


static_dir = settings_cfg.static_dir
if static_dir and Path(static_dir).is_dir():
    assets = Path(static_dir) / "assets"
    if assets.is_dir():
        app.mount("/assets", StaticFiles(directory=assets), name="assets")

    @app.get("/{full_path:path}")
    async def spa(full_path: str):
        index = Path(static_dir) / "index.html"
        if full_path.startswith("api"):
            return {"detail": "Not Found"}
        file_path = Path(static_dir) / full_path
        if file_path.is_file():
            return FileResponse(file_path)
        return FileResponse(index)

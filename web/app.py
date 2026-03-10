"""
Trend Vision One Reporter — FastAPI application factory.
"""

import os
import sys
from contextlib import asynccontextmanager
from pathlib import Path

# Allow imports from the web/ directory itself (database, models, security, …)
_web_dir_path = str(Path(__file__).resolve().parent)
if _web_dir_path not in sys.path:
    sys.path.insert(0, _web_dir_path)

# Allow imports from the parent project directory (client, collectors, reports)
_parent_dir = str(Path(__file__).resolve().parent.parent)
if _parent_dir not in sys.path:
    sys.path.insert(0, _parent_dir)

from dotenv import load_dotenv

load_dotenv()

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from slowapi.util import get_remote_address

from database import SessionLocal, engine
from models import Base, User
from security import hash_password


# ── Lifespan: DB init + seed admin ────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Create all tables
    Base.metadata.create_all(bind=engine)

    # Seed admin user if no users exist
    db = SessionLocal()
    try:
        user_count = db.query(User).count()
        if user_count == 0:
            admin_username = os.getenv("ADMIN_USERNAME", "admin")
            admin_password = os.getenv("ADMIN_PASSWORD", "changeme123")
            admin_email = os.getenv("ADMIN_EMAIL", "admin@localhost")

            admin = User(
                username=admin_username,
                email=admin_email,
                hashed_password=hash_password(admin_password),
                is_admin=True,
                is_active=True,
            )
            db.add(admin)
            db.commit()
            print(
                f"\n[TV1 Reporter] Admin user created.\n"
                f"  Username : {admin_username}\n"
                f"  Password : {admin_password}\n"
                f"  >>> Change the password after first login! <<<\n"
            )
        else:
            print("[TV1 Reporter] Database ready.")
    finally:
        db.close()

    yield
    # Shutdown — nothing to clean up


# ── App factory ───────────────────────────────────────────────────────────────

limiter = Limiter(key_func=get_remote_address)

MAX_UPLOAD_BYTES = 500 * 1024 * 1024  # 500 MB

# True when running behind HTTPS (set in .env for production)
HTTPS_ENABLED: bool = os.getenv("HTTPS_ENABLED", "false").lower() == "true"

app = FastAPI(
    title="Trend Vision One Reporter",
    description="Multi-customer security report management portal",
    version="1.0.0",
    lifespan=lifespan,
    docs_url=None,   # Disable Swagger UI in production
    redoc_url=None,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)

# Reject oversized request bodies before they reach route handlers
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response as StarletteResponse

class _MaxBodyMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        cl = request.headers.get("content-length")
        if cl and int(cl) > MAX_UPLOAD_BYTES:
            return StarletteResponse(
                content=f"Upload exceeds {MAX_UPLOAD_BYTES // (1024*1024)} MB limit.",
                status_code=413,
            )
        return await call_next(request)

app.add_middleware(_MaxBodyMiddleware)


# Security headers on every response
class _SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        if HTTPS_ENABLED:
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains"
            )
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' cdn.jsdelivr.net; "
            "font-src 'self' cdn.jsdelivr.net; "
            "img-src 'self' data:; "
            "connect-src 'self';"
        )
        return response

app.add_middleware(_SecurityHeadersMiddleware)

# ── Static files ──────────────────────────────────────────────────────────────

_web_dir = Path(__file__).resolve().parent
app.mount(
    "/static",
    StaticFiles(directory=str(_web_dir / "static")),
    name="static",
)

# ── Flash message middleware ──────────────────────────────────────────────────

@app.middleware("http")
async def flash_middleware(request: Request, call_next):
    """
    Read and clear flash cookie before passing to route,
    so templates can access request.state.flash.
    """
    import json as _json
    flash_data = None
    flash_cookie = request.cookies.get("flash")
    if flash_cookie:
        try:
            from itsdangerous import URLSafeSerializer, BadSignature
            secret = os.getenv("SECRET_KEY")
            s = URLSafeSerializer(secret, salt="flash")
            flash_data = s.loads(flash_cookie)
        except Exception:
            flash_data = None

    request.state.flash = flash_data

    response = await call_next(request)

    # Clear the flash cookie after it has been read
    if flash_cookie:
        response.delete_cookie("flash")

    return response


# ── Include routers ───────────────────────────────────────────────────────────

from routes.auth import router as auth_router
from routes.dashboard import router as dashboard_router
from routes.customers import router as customers_router
from routes.reports import router as reports_router
from routes.admin import router as admin_router

app.include_router(auth_router)
app.include_router(dashboard_router)
app.include_router(customers_router)
app.include_router(reports_router)
app.include_router(admin_router)


# ── Global 307 redirect handler (login redirect) ─────────────────────────────

from fastapi import HTTPException as FastAPIHTTPException
from fastapi.responses import RedirectResponse


@app.exception_handler(FastAPIHTTPException)
async def http_exception_handler(request: Request, exc: FastAPIHTTPException):
    if exc.status_code == 307 and exc.headers and exc.headers.get("Location") == "/login":
        return RedirectResponse(url="/login", status_code=302)
    from fastapi.exception_handlers import http_exception_handler as default_handler
    return await default_handler(request, exc)

import html
import logging
import os
import pathlib
import re

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from . import __version__
from .config import settings
from .routers import auth, integrations, inventory, risks, security_api

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("patchy")
STATIC = pathlib.Path(os.getenv("STATIC_DIR", pathlib.Path(__file__).resolve().parents[2] / "frontend" / "dist"))
DOCS = os.getenv("ENABLE_API_DOCS", "false").lower() == "true"

app = FastAPI(title="Patchy", version=__version__, openapi_url="/api/openapi.json",
              docs_url="/api/docs" if DOCS else None, redoc_url=None)
app.include_router(auth.router)
app.include_router(inventory.router)
app.include_router(security_api.router)
app.include_router(security_api.agent_router)
app.include_router(integrations.router)
app.include_router(risks.router)

# base-uri 'self' allows the <base href> that sets the mount path. frame-ancestors 'self' lets a
# same-origin portal (SWSuite) show Patchy in a frame; no other site can.
CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; "
       "font-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'self'")


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    docs = DOCS and request.url.path == "/api/docs"
    response.headers.setdefault("Content-Security-Policy", CSP if not docs else
                                CSP.replace("script-src 'self'", "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net")
                                .replace("style-src 'self'", "style-src 'self' https://cdn.jsdelivr.net"))
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    if request.url.path.startswith("/api/"):
        response.headers.setdefault("Cache-Control", "no-store")
    return response


@app.middleware("http")
async def demo_read_only(request: Request, call_next):
    """The public demo refuses every change, before any route runs."""
    if settings.demo_mode and request.url.path.startswith("/api/") and request.method not in ("GET", "HEAD", "OPTIONS"):
        return JSONResponse({"detail": "This is a demo, so changes are turned off."}, status_code=403)
    return await call_next(request)


@app.exception_handler(RequestValidationError)
async def validation_error(request: Request, exc: RequestValidationError):
    # Field locations and messages only: never echo submitted values back.
    errors = [{"loc": [str(x) for x in e.get("loc", [])], "msg": e.get("msg", "")} for e in exc.errors()]
    return JSONResponse({"detail": "Validation failed.", "errors": errors}, status_code=422)


@app.exception_handler(Exception)
async def unhandled(request: Request, exc: Exception):
    log.exception("unhandled error on %s %s", request.method, request.url.path)
    return JSONResponse({"detail": "Internal server error."}, status_code=500)


@app.get("/api/health", tags=["system"])
def health():
    return {"status": "ok"}


# Path prefix a reverse proxy mounts Patchy under (eg /patchy), from X-Forwarded-Prefix.
# Only plain path segments are accepted, so the header can never inject markup.
PREFIX_RE = re.compile(r"(/[A-Za-z0-9_-]+)*")


def render_index(index: pathlib.Path, prefix: str) -> str:
    page = index.read_text(encoding="utf-8")
    if not PREFIX_RE.fullmatch(prefix):
        prefix = ""
    page = page.replace('<base href="/"', f'<base href="{prefix}/"', 1)
    head = ""
    if settings.suite_assets_path:  # suite theme first, so Patchy's own theme-init sees data-theme
        s = settings.suite_assets_path
        head += f'<script src="{s}/theme-init.js"></script><link rel="stylesheet" href="{s}/theme.css">'
    if settings.blocked_url:  # in the page itself, as the API is what gets blocked
        head += f'<meta name="blocked-url" content="{html.escape(settings.blocked_url)}">'
    return page.replace("<head>", "<head>" + head, 1)


@app.get("/{path:path}", include_in_schema=False)
def spa(path: str, request: Request):
    """Serve the built React app; unknown non-API paths fall back to index.html for client routing."""
    if path.startswith("api/"):
        raise StarletteHTTPException(404)
    target = (STATIC / path).resolve()
    if path and target.is_file() and STATIC.resolve() in target.parents:
        return FileResponse(target)
    index = STATIC / "index.html"
    if not index.exists():
        return JSONResponse({"detail": "Frontend not built. Run `npm run build` in frontend/."}, status_code=503)
    return HTMLResponse(render_index(index, request.headers.get("x-forwarded-prefix", "")),
                        headers={"Cache-Control": "no-cache"})

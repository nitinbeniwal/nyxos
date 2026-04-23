"""
NyxOS Dashboard — FastAPI Server

Main entry point for the NyxOS web dashboard.  Starts a FastAPI application
on ``127.0.0.1:8080`` (localhost only — never exposed to the network) as a
background daemon thread so it doesn't block the NyxOS interactive shell.

Usage from the shell (Agent 1):
    from nyxos.dashboard.backend.server import start_dashboard, stop_dashboard
    start_dashboard()          # non-blocking, runs in daemon thread
    stop_dashboard()           # graceful shutdown

Usage standalone (for testing):
    python -m nyxos.dashboard.backend.server
"""

from __future__ import annotations

import signal
import sys
import threading
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

from loguru import logger

# ---------------------------------------------------------------------------
# Resolve paths
# ---------------------------------------------------------------------------
_THIS_DIR = Path(__file__).resolve().parent          # backend/
_DASHBOARD_DIR = _THIS_DIR.parent                    # dashboard/
_FRONTEND_DIR = _DASHBOARD_DIR / "frontend"          # dashboard/frontend/
_PROJECT_ROOT = _DASHBOARD_DIR.parent                # nyxos/ (package root)


# ---------------------------------------------------------------------------
# FastAPI application factory
# ---------------------------------------------------------------------------

def _create_app():
    """
    Build and return the configured FastAPI application.

    Separated into a factory so we can import it for testing without
    side-effects.
    """
    from fastapi import FastAPI, Request
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import FileResponse, JSONResponse
    from fastapi.staticfiles import StaticFiles

    # ------------------------------------------------------------------
    # Lifespan handler (replaces deprecated on_event)
    # ------------------------------------------------------------------
    @asynccontextmanager
    async def lifespan(application: FastAPI):
        """Handle startup and shutdown events."""
        # --- STARTUP ---
        logger.info("NyxOS Dashboard server starting up")
        try:
            from nyxos.dashboard.backend.api import routes
            routes._server_start_time = time.time()
        except Exception:
            pass
        yield
        # --- SHUTDOWN ---
        logger.info("NyxOS Dashboard server shutting down")
        try:
            from nyxos.dashboard.backend.api.websocket import manager
            for ws in list(manager._active_connections):
                try:
                    await ws.close()
                except Exception:
                    pass
        except Exception:
            pass

    app = FastAPI(
        title="NyxOS Dashboard",
        description="Web dashboard for NyxOS — the AI-native cybersecurity OS",
        version="0.1.0",
        docs_url="/api/docs",
        redoc_url="/api/redoc",
        lifespan=lifespan,
    )

    # ------------------------------------------------------------------
    # CORS — allow localhost origins only
    # ------------------------------------------------------------------
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[
            "http://localhost:8080",
            "http://127.0.0.1:8080",
            "http://localhost:3000",
            "http://127.0.0.1:3000",
        ],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ------------------------------------------------------------------
    # Import and include API routers
    # ------------------------------------------------------------------
    try:
        from nyxos.dashboard.backend.api.routes import router as api_router
        app.include_router(api_router, prefix="/api")
        logger.debug("Registered API routes at /api")
    except ImportError as exc:
        logger.error(f"Could not import API routes: {exc}")

    try:
        from nyxos.dashboard.backend.api.auth_routes import router as auth_router
        app.include_router(auth_router, prefix="/api/auth")
        logger.debug("Registered auth routes at /api/auth")
    except ImportError as exc:
        logger.error(f"Could not import auth routes: {exc}")

    try:
        from nyxos.dashboard.backend.api.websocket import router as ws_router
        app.include_router(ws_router, prefix="/ws")
        logger.debug("Registered WebSocket routes at /ws")
    except ImportError as exc:
        logger.error(f"Could not import WebSocket routes: {exc}")

    # ------------------------------------------------------------------
    # Mount static frontend files (if directory exists)
    # ------------------------------------------------------------------
    if _FRONTEND_DIR.is_dir():
        assets_dir = _FRONTEND_DIR / "assets"
        if assets_dir.is_dir():
            app.mount(
                "/static/assets",
                StaticFiles(directory=str(assets_dir)),
                name="static_assets",
            )
        components_dir = _FRONTEND_DIR / "components"
        if components_dir.is_dir():
            app.mount(
                "/static/components",
                StaticFiles(directory=str(components_dir)),
                name="static_components",
            )
        app.mount(
            "/static",
            StaticFiles(directory=str(_FRONTEND_DIR)),
            name="static",
        )
        logger.debug(f"Mounted static files from {_FRONTEND_DIR}")
    else:
        logger.warning(
            f"Frontend directory not found at {_FRONTEND_DIR} — "
            "dashboard UI will not be available"
        )

    # ------------------------------------------------------------------
    # Root route — serve index.html or JSON fallback
    # ------------------------------------------------------------------
    @app.get("/", include_in_schema=False)
    async def root():
        """Serve the dashboard index.html or a JSON status."""
        index_path = _FRONTEND_DIR / "index.html"
        if index_path.is_file():
            return FileResponse(str(index_path), media_type="text/html")
        return JSONResponse({
            "name": "NyxOS Dashboard",
            "version": "0.1.0",
            "status": "running",
            "api_docs": "/api/docs",
            "message": "Frontend files not found. Place index.html in nyxos/dashboard/frontend/",
        })

    # ------------------------------------------------------------------
    # Health check (no auth required)
    # ------------------------------------------------------------------
    @app.get("/health", include_in_schema=False)
    async def health():
        """Simple health-check endpoint."""
        return {"status": "healthy", "timestamp": time.time()}

    # ------------------------------------------------------------------
    # Global exception handler
    # ------------------------------------------------------------------
    @app.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception):
        logger.error(f"Unhandled exception on {request.url}: {exc}")
        return JSONResponse(
            status_code=500,
            content={
                "success": False,
                "detail": "Internal server error",
                "message": str(exc),
            },
        )

    return app


# Build the application instance
app = _create_app()


# ---------------------------------------------------------------------------
# Server lifecycle management
# ---------------------------------------------------------------------------

_server_thread: Optional[threading.Thread] = None
_server_should_stop = threading.Event()


def start_dashboard(
    host: str = "127.0.0.1",
    port: int = 8080,
    block: bool = False,
    log_level: str = "warning",
) -> Optional[threading.Thread]:
    """
    Start the NyxOS Dashboard server.

    By default runs in a background daemon thread so it doesn't block
    the NyxOS interactive shell.

    Args:
        host: Bind address.  MUST be 127.0.0.1 for security.
        port: Port number (default 8080).
        block: If True, run in the foreground (blocks the caller).
        log_level: Uvicorn log level.

    Returns:
        The background Thread if block=False, else None (never returns).
    """
    global _server_thread

    # Security: never bind to 0.0.0.0
    if host not in ("127.0.0.1", "localhost", "::1"):
        logger.warning(
            f"Refusing to bind to {host} — NyxOS dashboard must only listen on localhost."
        )
        host = "127.0.0.1"

    if block:
        _run_server(host, port, log_level)
        return None

    if _server_thread is not None and _server_thread.is_alive():
        logger.info(f"Dashboard server already running on {host}:{port}")
        return _server_thread

    _server_should_stop.clear()

    _server_thread = threading.Thread(
        target=_run_server,
        args=(host, port, log_level),
        name="nyxos-dashboard",
        daemon=True,
    )
    _server_thread.start()

    time.sleep(0.5)
    if _server_thread.is_alive():
        logger.info(f"NyxOS Dashboard started at http://{host}:{port}")
    else:
        logger.error("Dashboard server thread died on startup")

    return _server_thread


def _run_server(host: str, port: int, log_level: str) -> None:
    """Internal: run the uvicorn server."""
    try:
        import uvicorn

        config = uvicorn.Config(
            app=app,
            host=host,
            port=port,
            log_level=log_level,
            access_log=False,
            loop="asyncio",
        )
        server = uvicorn.Server(config)
        _run_server._uvicorn_server = server  # type: ignore[attr-defined]
        server.run()
    except ImportError:
        logger.error("uvicorn is not installed. Install with: pip install uvicorn")
    except OSError as exc:
        if "already in use" in str(exc).lower():
            logger.warning(f"Port {port} is already in use.")
        else:
            logger.error(f"Dashboard server OS error: {exc}")
    except Exception as exc:
        logger.error(f"Dashboard server error: {exc}")


def stop_dashboard() -> None:
    """Gracefully stop the dashboard server."""
    global _server_thread

    logger.info("Stopping NyxOS Dashboard server...")
    _server_should_stop.set()

    server = getattr(_run_server, "_uvicorn_server", None)
    if server is not None:
        server.should_exit = True

    if _server_thread is not None and _server_thread.is_alive():
        _server_thread.join(timeout=5.0)
        if _server_thread.is_alive():
            logger.warning("Dashboard server thread did not stop within 5 seconds")
        else:
            logger.info("Dashboard server stopped")
    _server_thread = None


def is_dashboard_running() -> bool:
    """Check whether the dashboard server thread is alive."""
    return _server_thread is not None and _server_thread.is_alive()


def get_dashboard_url(host: str = "127.0.0.1", port: int = 8080) -> str:
    """Return the dashboard URL string."""
    return f"http://{host}:{port}"


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def _cli_main() -> None:
    """Command-line entry point for running the dashboard standalone."""
    import argparse

    parser = argparse.ArgumentParser(description="NyxOS Dashboard Server")
    parser.add_argument("--host", default="127.0.0.1", help="Bind address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8080, help="Port (default: 8080)")
    parser.add_argument(
        "--log-level", default="info",
        choices=["debug", "info", "warning", "error", "critical"],
    )
    args = parser.parse_args()

    print(
        f"\n"
        f"  ╔═══════════════════════════════════════════════╗\n"
        f"  ║          NyxOS Dashboard Server               ║\n"
        f"  ║   URL:      http://{args.host}:{args.port}          ║\n"
        f"  ║   API docs: http://{args.host}:{args.port}/api/docs ║\n"
        f"  ║   Press Ctrl+C to stop                        ║\n"
        f"  ╚═══════════════════════════════════════════════╝\n"
    )

    def _signal_handler(signum, frame):
        print("\nShutting down...")
        stop_dashboard()
        sys.exit(0)

    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    start_dashboard(host=args.host, port=args.port, block=True, log_level=args.log_level)


if __name__ == "__main__":
    _cli_main()

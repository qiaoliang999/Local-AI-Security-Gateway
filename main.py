"""
Local AI Security Gateway - Main Application
A transparent security proxy for AI API traffic with DLP protection.

Supports: OpenAI, Anthropic, Google Gemini, Groq, Mistral, DeepSeek,
          xAI, Cohere, Together AI, OpenRouter, Ollama, and custom endpoints.
"""
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse, HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
import httpx
import json
import logging
import os
import time

from dlp import dlp_engine
from config import config, AI_PROVIDERS

# ─── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=getattr(logging, config.log_level.upper(), logging.INFO),
    format="%(asctime)s %(levelname)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)

# ─── FastAPI App ──────────────────────────────────────────────────────────────
app = FastAPI(
    title="Local AI Security Gateway",
    description="Transparent DLP security proxy for AI API requests",
    version="2.0.0",
)

# CORS support for web-based AI tools
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Static files for the dashboard
os.makedirs("static", exist_ok=True)
app.mount("/static", StaticFiles(directory="static"), name="static")


# ─── Utility: Resolve Target URL ──────────────────────────────────────────────

# Known AI API domains → provider key mapping
DOMAIN_TO_PROVIDER = {
    "api.openai.com": "openai",
    "api.anthropic.com": "anthropic",
    "generativelanguage.googleapis.com": "google",
    "api.groq.com": "groq",
    "api.mistral.ai": "mistral",
    "api.deepseek.com": "deepseek",
    "api.x.ai": "xai",
    "api.cohere.com": "cohere",
    "api.together.xyz": "together",
    "openrouter.ai": "openrouter",
    "localhost:11434": "ollama",
}


def resolve_target_url(request: Request) -> str:
    """
    Determines the upstream target URL for the incoming request.

    Supports three modes:
    1. Direct proxy — client sent request with original Host (transparent proxy)
    2. Custom upstream — CUSTOM_UPSTREAM_URL is configured
    3. Default provider — falls back to configured DEFAULT_PROVIDER
    """
    hostname = request.url.hostname or ""
    path = request.url.path

    # Mode 1: If the request's host is NOT localhost, it's a transparent proxy request
    if hostname not in ("127.0.0.1", "localhost", "0.0.0.0", ""):
        # The client is connecting through a system proxy; use original destination
        return str(request.url)

    # Mode 2: Custom upstream URL override
    if config.custom_upstream_url:
        base = config.custom_upstream_url.rstrip("/")
        return f"{base}{path}"

    # Mode 3: Smart routing by path prefix
    # Try to match path to known providers
    default_provider = config.get_default_provider()
    base_url = default_provider.base_url.rstrip("/")
    return f"{base_url}{path}"


def detect_provider_from_url(url: str) -> str:
    """Detect which AI provider a URL belongs to (for logging)."""
    for domain, provider_key in DOMAIN_TO_PROVIDER.items():
        if domain in url:
            return AI_PROVIDERS[provider_key].name
    return "Custom/Unknown"


# ─── Dashboard & API Endpoints ────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def dashboard():
    """Serves the security audit dashboard."""
    html_path = os.path.join("static", "index.html")
    if os.path.exists(html_path):
        with open(html_path, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse(
        content="<h1>Dashboard UI not found. Please ensure static/index.html exists.</h1>",
        status_code=404,
    )


@app.get("/health")
async def health_check():
    """Health check endpoint for monitoring."""
    return {
        "status": "healthy",
        "version": "2.0.0",
        "dlp_enabled": config.dlp_enabled,
        "default_provider": config.default_provider,
        "patterns_loaded": len(dlp_engine.patterns),
        "uptime_note": "Use a process manager for uptime tracking",
    }


@app.get("/api/logs")
async def get_logs():
    """Returns the list of DLP interception events."""
    stats = dlp_engine.get_stats()
    return {
        "logs": list(reversed(dlp_engine.incident_log)),
        "total_intercepts": stats["total_intercepts"],
        "type_breakdown": stats["type_breakdown"],
        "patterns_loaded": stats["patterns_loaded"],
    }


@app.get("/api/providers")
async def list_providers():
    """Lists all supported AI providers."""
    return {
        "providers": {
            key: {"name": p.name, "base_url": p.base_url, "api_path_prefix": p.api_path_prefix}
            for key, p in AI_PROVIDERS.items()
        },
        "default": config.default_provider,
        "custom_upstream": config.custom_upstream_url,
    }


# ─── Proxy Middleware ─────────────────────────────────────────────────────────

# Paths that should NOT be proxied (served locally)
LOCAL_PATHS = {"/", "/health", "/api/logs", "/api/providers", "/static", "/docs", "/openapi.json", "/redoc", "/favicon.ico"}


@app.middleware("http")
async def intercept_and_proxy(request: Request, call_next):
    """
    Core middleware: intercepts AI API requests, applies DLP, proxies upstream.
    Supports both regular JSON responses and SSE streaming.
    """
    path = request.url.path

    # Skip local dashboard/API routes and non-API paths
    if path in LOCAL_PATHS or path.startswith("/static") or path.startswith("/json"):
        return await call_next(request)

    # ── Resolve target URL ──────────────────────────────────────────────
    target_url = resolve_target_url(request)
    provider_name = detect_provider_from_url(target_url)

    logger.info(f"🌐 [PROXY] → {provider_name} | {request.method} {target_url}")

    # ── Read & Redact Request Body ──────────────────────────────────────
    body_bytes = await request.body()
    redacted_body = body_bytes  # Default: pass through as-is
    is_streaming = False

    if body_bytes and config.dlp_enabled:
        try:
            payload_str = body_bytes.decode("utf-8")
            json_payload = json.loads(payload_str)

            # Detect if client wants streaming
            is_streaming = json_payload.get("stream", False)

            # Run DLP redaction
            redacted_payload = dlp_engine.redact_payload(json_payload)
            redacted_body = json.dumps(redacted_payload).encode("utf-8")
            logger.info("✅ [DLP] Request payload scanned and sanitized.")
        except (json.JSONDecodeError, UnicodeDecodeError):
            logger.warning("⚠️ [DLP] Non-JSON body, passing through as-is.")
            redacted_body = body_bytes
    elif not body_bytes:
        redacted_body = b""

    # ── Prepare Headers ─────────────────────────────────────────────────
    # Forward all headers except hop-by-hop headers
    excluded_headers = {"host", "content-length", "transfer-encoding", "connection"}
    headers = {
        k: v for k, v in request.headers.items()
        if k.lower() not in excluded_headers
    }

    # ── Proxy Configuration ─────────────────────────────────────────────
    proxy_url = config.http_proxy
    if proxy_url:
        logger.info(f"🔗 [PROXY CHAIN] Upstream proxy: {proxy_url}")

    # ── Forward Request ─────────────────────────────────────────────────
    start_time = time.time()

    if is_streaming:
        # ── SSE Streaming Mode ──────────────────────────────────────────
        return await _handle_streaming_request(
            method=request.method,
            url=target_url,
            headers=headers,
            body=redacted_body,
            proxy_url=proxy_url,
            start_time=start_time,
            provider_name=provider_name,
        )
    else:
        # ── Standard Request/Response Mode ──────────────────────────────
        return await _handle_standard_request(
            method=request.method,
            url=target_url,
            headers=headers,
            body=redacted_body,
            proxy_url=proxy_url,
            start_time=start_time,
            provider_name=provider_name,
        )


async def _handle_standard_request(
    method: str,
    url: str,
    headers: dict,
    body: bytes,
    proxy_url: str | None,
    start_time: float,
    provider_name: str,
) -> JSONResponse:
    """Handle a standard (non-streaming) proxy request."""
    async with httpx.AsyncClient(proxy=proxy_url, timeout=config.upstream_timeout) as client:
        try:
            response = await client.request(
                method=method,
                url=url,
                headers=headers,
                content=body,
            )
        except httpx.TimeoutException:
            logger.error(f"⏱️ [TIMEOUT] Request to {provider_name} timed out after {config.upstream_timeout}s")
            raise HTTPException(status_code=504, detail="Upstream request timed out.")
        except httpx.RequestError as exc:
            logger.error(f"❌ [ERROR] Connection error to {provider_name}: {exc}")
            raise HTTPException(status_code=502, detail=f"Cannot reach upstream: {exc}")

    elapsed = time.time() - start_time
    logger.info(f"⚡ [DONE] {provider_name} responded {response.status_code} in {elapsed:.2f}s")

    # ── Unredact Response ───────────────────────────────────────────────
    try:
        response_json = response.json()
        if config.dlp_enabled:
            unredacted = dlp_engine.unredact_payload(response_json)
            logger.info("🔄 [DLP] Response placeholders restored.")
        else:
            unredacted = response_json
        return JSONResponse(content=unredacted, status_code=response.status_code)
    except (json.JSONDecodeError, ValueError):
        # Non-JSON response — return raw text
        return JSONResponse(
            content={"error": "Non-JSON upstream response", "raw": response.text[:500]},
            status_code=response.status_code,
        )


async def _handle_streaming_request(
    method: str,
    url: str,
    headers: dict,
    body: bytes,
    proxy_url: str | None,
    start_time: float,
    provider_name: str,
) -> StreamingResponse:
    """Handle a streaming (SSE) proxy request."""

    async def _stream_generator():
        async with httpx.AsyncClient(proxy=proxy_url, timeout=config.upstream_timeout) as client:
            try:
                async with client.stream(
                    method=method,
                    url=url,
                    headers=headers,
                    content=body,
                ) as response:
                    if response.status_code != 200:
                        # Read full error body and return it
                        error_body = await response.aread()
                        yield error_body
                        return

                    async for chunk in response.aiter_bytes():
                        if config.dlp_enabled:
                            # Unredact any placeholders that appear in streamed chunks
                            decoded = chunk.decode("utf-8", errors="replace")
                            unredacted = dlp_engine.unredact_text(decoded)
                            yield unredacted.encode("utf-8")
                        else:
                            yield chunk

            except httpx.TimeoutException:
                logger.error(f"⏱️ [TIMEOUT] Streaming from {provider_name} timed out")
                yield b'data: {"error": "upstream timeout"}\n\n'
            except httpx.RequestError as exc:
                logger.error(f"❌ [ERROR] Streaming error from {provider_name}: {exc}")
                yield f'data: {{"error": "connection error: {exc}"}}\n\n'.encode()

        elapsed = time.time() - start_time
        logger.info(f"⚡ [STREAM DONE] {provider_name} stream completed in {elapsed:.2f}s")

    return StreamingResponse(
        _stream_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


# ─── Entrypoint ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn

    print("=" * 60)
    print("🛡️  Local AI Security Gateway v2.0.0")
    print("=" * 60)
    print(f"  🌐 Listening:        http://{config.host}:{config.port}")
    print(f"  🎯 Default Provider: {config.get_default_provider().name}")
    print(f"  🔍 DLP Engine:       {'✅ ON' if config.dlp_enabled else '❌ OFF'}")
    print(f"  📋 DLP Patterns:     {len(dlp_engine.patterns)} loaded")
    if config.custom_upstream_url:
        print(f"  🔗 Custom Upstream:  {config.custom_upstream_url}")
    if config.http_proxy:
        print(f"  🔗 Upstream Proxy:   {config.http_proxy}")
    print("=" * 60)
    print("  Configure your AI tool's base_url to:")
    print(f"    http://{config.host}:{config.port}/v1")
    print("=" * 60)

    uvicorn.run(app, host=config.host, port=config.port)

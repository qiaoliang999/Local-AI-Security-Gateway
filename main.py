from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
import httpx
import logging
import os

from dlp import dlp_engine

app = FastAPI(title="Local AI Security Gateway")

# Ensure static dir exists
os.makedirs("static", exist_ok=True)
app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/api/logs")
async def get_logs():
    """Returns the list of intercepted sensitive data events."""
    return {"logs": list(reversed(dlp_engine.incident_log)), "total_intercepts": len(dlp_engine.incident_log)}

@app.get("/")
async def dashboard():
    """Serves the security audit dashboard."""
    html_path = os.path.join("static", "index.html")
    if os.path.exists(html_path):
        with open(html_path, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse(content="<h1>Dashboard UI not found. Please ensure static/index.html exists.</h1>")

OPENAI_URL = "https://api.openai.com"

@app.middleware("http")
async def intercept_and_proxy(request: Request, call_next):
    # Only proxy requests meant for OpenAI (e.g. /v1/chat/completions)
    if not request.url.path.startswith("/v1"):
        return await call_next(request)

    # True transparent proxying: Forward to the original intended destination
    # e.g. api.anthropic.com or api.openai.com depending on what the client requested
    original_url = request.url
    target_url = str(original_url)
    
    # In some setups, the request might come in as just the path (e.g. if the client configured
    # base_url = http://localhost:8000). In that specific case, we default to OpenAI for backward compatibility.
    if request.url.hostname in ("127.0.0.1", "localhost", "0.0.0.0"):
         target_url = f"https://api.openai.com{request.url.path}"
         
    logging.info(f"🌐 [PROXY] Intercepting request to: {target_url}")

    try:
        # Read the raw request body
        body_bytes = await request.body()
        payload = body_bytes.decode("utf-8")
        
        # Parse JSON and run DLP Engine to redact sensitive information
        import json
        json_payload = json.loads(payload)
        redacted_payload = dlp_engine.redact_payload(json_payload)
        logging.info("✅ [REDACT] Payload sanitized successfully.")
        
    except json.JSONDecodeError:
        # If it's not valid JSON, we don't proxy it right now for safety
        logging.warning("⚠️ [WARN] Non-JSON body detected, passing through as-is.")
        redacted_payload = payload

    # Forward the modified request to OpenAI using httpx
    # Exclude headers that might cause issues like content-length (which changes) or host
    headers = {k: v for k, v in request.headers.items() if k.lower() not in ('host', 'content-length')}
    
    # Support for upstream VPNs/Proxies (e.g., Clash, V2Ray) via environment variables
    import os
    http_proxy = os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy")
    https_proxy = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
    proxy_url = https_proxy or http_proxy
        
    if proxy_url:
        logging.info(f"🔗 [PROXY CHAIN] Routing traffic through upstream VPN/Proxy: {proxy_url}")

    async with httpx.AsyncClient(proxy=proxy_url) as client:
        try:
            response = await client.request(
                method=request.method,
                url=target_url,
                headers=headers,
                json=redacted_payload, # sending the redacted dict
                timeout=60.0
            )
        except httpx.RequestError as exc:
            logging.error(f"❌ [ERROR] An error occurred while requesting {exc.request.url!r}.")
            raise HTTPException(status_code=502, detail="Upstream API error.")

    # Process the response from OpenAI
    try:
        response_json = response.json()
        # Run DLP Engine to un-redact placeholders back to real data so the developer sees the real variable names
        unredacted_response = dlp_engine.unredact_payload(response_json)
        logging.info("🔄 [RESTORE] Response original values restored for local display.")
        
        # Return the modified response to the local client
        return JSONResponse(content=unredacted_response, status_code=response.status_code)
    except json.JSONDecodeError:
        # Handle non-JSON responses (like server errors)
        return JSONResponse(content={"error": "Invalid JSON response from upstream"}, status_code=502)

if __name__ == "__main__":
    import uvicorn
    # Start the local proxy on port 8000
    uvicorn.run(app, host="127.0.0.1", port=8000)

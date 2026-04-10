from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
import httpx
import logging

from dlp import dlp_engine

app = FastAPI(title="Local AI Security Gateway")

OPENAI_URL = "https://api.openai.com"

@app.middleware("http")
async def intercept_and_proxy(request: Request, call_next):
    # Only proxy requests meant for OpenAI (e.g. /v1/chat/completions)
    if not request.url.path.startswith("/v1"):
        return await call_next(request)

    target_url = f"{OPENAI_URL}{request.url.path}"
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
    
    async with httpx.AsyncClient() as client:
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

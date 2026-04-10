import asyncio
from proxy import Proxy
from dlp import dlp_engine
import json
import logging

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

class DLPProxyPlugin:
    def __init__(self):
        pass

    def handle_client_request(self, request):
        if request.method != b"POST":
            return request
            
        host = request.headers.get(b"host", b"").decode("utf-8")
        # We intercept official APIs AND common third-party relay/proxy APIs
        target_indicators = [
            "api.openai.com", 
            "api.anthropic.com", 
            "generativelanguage.googleapis.com",
            # Catch common third-party API proxies
            "openai", 
            "anthropic", 
            "chat", 
            "proxy", 
            "v1/chat/completions"
        ]
        
        # If the host or path contains any of the indicators, we intercept it.
        # Note: This is an aggressive heuristic for MVP purposes.
        if any(indicator in host or indicator in request.path.decode('utf-8') for indicator in target_indicators):
            logging.info(f"🌐 [PROXY] Intercepting request to: {host}{request.path.decode('utf-8')}")
            try:
                # Try to parse the body as JSON and redact it
                body = request.body.decode("utf-8")
                if body:
                    json_payload = json.loads(body)
                    redacted_payload = dlp_engine.redact_payload(json_payload)
                    new_body = json.dumps(redacted_payload).encode("utf-8")
                    request.body = new_body
                    # Update content length! Very important for MITM
                    request.headers[b"content-length"] = str(len(new_body)).encode("utf-8")
                    logging.info("✅ [REDACT] Payload sanitized successfully.")
            except Exception as e:
                logging.warning(f"⚠️ [WARN] Could not parse/redact body: {e}")
                
        return request

    def handle_upstream_response(self, response):
        # We don't have the original request URL easily accessible here in this simple hook,
        # but we can just try to unredact any JSON response that comes back.
        try:
            body = response.body.decode("utf-8")
            if body and "[REDACTED_" in body:
                json_payload = json.loads(body)
                unredacted_payload = dlp_engine.unredact_payload(json_payload)
                new_body = json.dumps(unredacted_payload).encode("utf-8")
                response.body = new_body
                response.headers[b"content-length"] = str(len(new_body)).encode("utf-8")
                logging.info("🔄 [RESTORE] Response original values restored.")
        except Exception:
            pass # Ignore, just pass through
            
        return response

if __name__ == '__main__':
    # Start the proxy server
    print("Starting System-Wide AI Security Gateway on port 8899...")
    print("Ensure you have installed the CA certificate at certs/ca.crt into your Trusted Root Store!")
    # NOTE: In a real implementation we would use a library like 'proxy.py'
    # which supports intercepting HTTPS via MITM and injecting Python plugins.
    pass

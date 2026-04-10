# 🛡️ Local AI Security Gateway

**Secure your development workflow. Stop accidental leakage of secrets to LLMs.**

The **Local AI Security Gateway** is a lightweight, high-performance transparent proxy designed for developers and security-conscious teams. It intercepts requests from your IDE, CLI, or any AI-integrated tool to LLM providers, automatically detects and redacts sensitive information, and restores them in the response for a seamless, secure coding experience.

---

## ✨ Key Features

- **🔍 24+ DLP Patterns:** Detects AWS keys, OpenAI/Anthropic/Google/Groq API keys, emails, phone numbers, SSNs, credit cards, database URLs, JWT tokens, private keys, and more.
- **🌐 Multi-Provider Support:** Works with **OpenAI, Anthropic (Claude), Google Gemini, Groq, Mistral, DeepSeek, xAI (Grok), Cohere, Together AI, OpenRouter, Ollama**, and any custom OpenAI-compatible endpoint.
- **⚡ SSE Streaming:** Full support for `stream: true` — critical for real-time AI chat experiences.
- **🔄 Bidirectional Mapping:** Redacts secrets in outgoing prompts and intelligently restores them in incoming responses so your code logic remains intact.
- **🔗 Proxy Chaining:** Route traffic through upstream VPN/proxies (Clash, V2Ray) via environment variables.
- **🎨 Premium Dashboard:** Real-time security monitoring with type breakdown, provider overview, and audit logs.
- **🛠️ Zero Config Start:** Just point your AI tool's base URL to `localhost:8000` and you're protected.
- **⚙️ Fully Configurable:** Environment variables and `.env` file support for all settings.

---

## 🚀 Quick Start

### 1. Requirements
- Python 3.10+

### 2. Installation
```bash
# Clone the repository
git clone https://github.com/qiaoliang999/Local-AI-Security-Gateway.git
cd Local-AI-Security-Gateway

# Set up virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .\.venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Run the Gateway
```bash
python main.py
```

Output:
```
============================================================
🛡️  Local AI Security Gateway v2.0.0
============================================================
  🌐 Listening:        http://127.0.0.1:8000
  🎯 Default Provider: OpenAI
  🔍 DLP Engine:       ✅ ON
  📋 DLP Patterns:     24 loaded
============================================================
  Configure your AI tool's base_url to:
    http://127.0.0.1:8000/v1
============================================================
```

---

## 🔌 Configure Your AI Tools

### OpenAI Python SDK
```python
from openai import OpenAI
client = OpenAI(base_url="http://127.0.0.1:8000/v1")
```

### Anthropic Python SDK
```python
import anthropic
# Set DEFAULT_PROVIDER=anthropic in .env
client = anthropic.Anthropic(base_url="http://127.0.0.1:8000/v1")
```

### Cursor IDE
1. Open Settings → Models
2. Set **OpenAI API Base** to `http://127.0.0.1:8000/v1`
3. Enter your API key as usual — the gateway proxies it securely

### Windsurf / Continue.dev / Cline
Set the base URL in your extension settings:
```
http://127.0.0.1:8000/v1
```

### cURL / HTTPie
```bash
curl http://127.0.0.1:8000/v1/chat/completions \
  -H "Authorization: Bearer YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4","messages":[{"role":"user","content":"Hello"}]}'
```

### Custom / Third-Party API
```bash
# Use CUSTOM_UPSTREAM_URL for any OpenAI-compatible API
CUSTOM_UPSTREAM_URL=https://your-custom-api.com python main.py
```

---

## ⚙️ Configuration

Copy `.env.example` to `.env` and customize:

| Variable | Default | Description |
|----------|---------|-------------|
| `GATEWAY_HOST` | `127.0.0.1` | Listen address |
| `GATEWAY_PORT` | `8000` | Listen port |
| `DEFAULT_PROVIDER` | `openai` | Default upstream: `openai`, `anthropic`, `google`, `groq`, `mistral`, `deepseek`, `xai`, `cohere`, `together`, `openrouter`, `ollama` |
| `CUSTOM_UPSTREAM_URL` | — | Custom endpoint (overrides DEFAULT_PROVIDER) |
| `HTTPS_PROXY` | — | Upstream proxy (Clash/V2Ray) |
| `UPSTREAM_TIMEOUT` | `120` | Request timeout (seconds) |
| `DLP_ENABLED` | `true` | Enable/disable DLP scanning |
| `LOG_LEVEL` | `INFO` | Logging verbosity |

---

## 🛡️ DLP Detection Patterns

| Category | Patterns Detected |
|----------|------------------|
| **Cloud Keys** | AWS Access Key, AWS Secret Key, GCP Service Key, Azure Key |
| **AI API Keys** | OpenAI (legacy + project), Anthropic, Google AI, Groq, DeepSeek, Cohere, HuggingFace |
| **PII** | Email, US/CN Phone, SSN, Credit Card, CN ID Card |
| **Infrastructure** | Database URLs, Private Keys, JWT Tokens, Private IPs |
| **Generic** | Any `key=`, `token=`, `secret=`, `password=` patterns |

---

## 🛡️ Interception in Action

```text
06:32:15 INFO: 🌐 [PROXY] → OpenAI | POST https://api.openai.com/v1/chat/completions
06:32:15 WARNING: 🛡️ [DLP] Sensitive EMAIL detected and secured → [REDACTED_EMAIL_0]
06:32:15 WARNING: 🛡️ [DLP] Sensitive AWS_ACCESS_KEY detected and secured → [REDACTED_AWS_ACCESS_KEY_1]
06:32:15 INFO: ✅ [DLP] Request payload scanned and sanitized.
06:32:16 INFO: ⚡ [DONE] OpenAI responded 200 in 1.23s
06:32:16 INFO: 🔄 [DLP] Response placeholders restored.
```

---

## 🧪 Testing

```bash
python test_proxy.py
```

Runs:
1. **DLP Unit Tests** — validates all 15+ pattern detections
2. **Bidirectional Test** — ensures redact → unredact round-trip
3. **Proxy Integration Test** — starts server, sends request, checks health

---

## 📊 API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Security Dashboard UI |
| `/health` | GET | Health check (monitoring) |
| `/api/logs` | GET | DLP audit log with statistics |
| `/api/providers` | GET | List all supported AI providers |
| `/v1/*` | ANY | Proxy to upstream AI provider |

---

## 🗺️ Roadmap
- [x] Multi-provider support (OpenAI, Anthropic, Google, Groq, etc.)
- [x] SSE streaming support
- [x] Comprehensive DLP patterns (24+)
- [x] Configuration via environment variables
- [x] Security audit dashboard
- [ ] Context-aware redaction using local NLP models (e.g., Presidio)
- [ ] Per-request DLP rules (allow/block modes)
- [ ] Log persistence (SQLite / file-based)
- [ ] Docker deployment
- [ ] Plugin system for custom patterns

## 🤝 Contributing
Contributions are welcome! Whether it's adding new DLP patterns, supporting new providers, or improving the proxy logic, feel free to open a PR.

## 📜 License
MIT License. Free for personal and commercial use.

---
**Built with ❤️ by [Qiao Liang](https://github.com/qiaoliang999)**

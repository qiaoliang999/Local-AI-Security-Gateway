# 🛡️ Local AI Security Gateway

**Secure your development workflow. Stop accidental leakage of secrets to LLMs.**

The **Local AI Security Gateway** is a lightweight, high-performance transparent proxy designed for developers and security-conscious teams. It intercepts requests from your IDE or CLI to LLM providers (like OpenAI), automatically detects and redacts sensitive information (API keys, emails, cloud credentials), and restores them in the response for a seamless, secure coding experience.

---

## ✨ Key Features

- **🔍 Intelligent DLP (Data Loss Prevention):** Automatically identifies and secures sensitive patterns like AWS Keys, Emails, and generic API tokens using regex and pattern matching.
- **⚡ Transparent Proxying:** Built on **FastAPI** and **AnyIO**, ensuring zero noticeable latency in your development loop.
- **🔄 Bidirectional Mapping:** Redacts secrets in outgoing prompts and intelligently restores them in incoming responses so your code logic remains intact.
- **🎨 Visual Audit Logs:** Real-time logging with intuitive emojis to let you know exactly when a potential leak was prevented.
- **🛠️ Easy Integration:** Just point your OpenAI base URL to `localhost:8000` and you're protected.

---

## 🚀 Quick Start

### 1. Requirements
- Python 3.11+

### 2. Installation
```bash
# Clone the repository
git clone https://github.com/qiaoliang999/Local-AI-Security-Gateway.git
cd Local-AI-Security-Gateway

# Set up virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows use `.\.venv\Scripts\activate`

# Install dependencies
pip install -r requirements.txt
```

### 3. Run the Gateway
```bash
python main.py
```
The gateway will start at `http://127.0.0.1:8000`.

### 4. Configure Your Tools
Point your OpenAI-compatible tools to use the local gateway:
```python
# Example in Python
import openai
openai.api_base = "http://127.0.0.1:8000/v1"
```

---

## 🛡️ Interception in Action

When the gateway detects sensitive data, you'll see instant feedback in your terminal:

```text
INFO: 🌐 [PROXY] Intercepting request to: https://api.openai.com/v1/chat/completions
WARNING: 🛡️ [DLP INTERCEPT] Sensitive AWS_KEY detected and secured!
INFO: ✂️ [REDACT] Payload sanitized successfully.
INFO: 🔄 [RESTORE] Response original values restored for local display.
```

---

## 🗺️ Roadmap
- [ ] Support for more LLM providers (Anthropic, Google Gemini).
- [ ] Context-aware redaction using local NLP models (e.g., Presidio).
- [ ] Web-based Dashboard for security auditing.
- [ ] Custom rule engine for enterprise-specific secrets.

## 🤝 Contributing
Contributions are welcome! Whether it's adding new DLP patterns or improving the proxy logic, feel free to open a PR.

## 📜 License
MIT License. Free for personal and commercial use.

---
**Built with ❤️ by [Qiao Liang](https://github.com/qiaoliang999)**

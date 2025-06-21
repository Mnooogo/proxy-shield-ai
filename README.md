# Proxy Shield AI — Stable Backend

A secure proxy + memory backend for AI assistants and apps.

## Setup
1. Clone repo
2. Add environment variables via Render or .env
3. Deploy to Render.com

## Endpoints
- `POST /chat` — secure GPT chat
- `POST /proxy` — OpenAI proxy
- `POST /save-memory` — save user memory
- `POST /load-memory` — load user memory

## Notes
- IP-based rate limiting and token tracking
- Telegram alerts for abuse
- Memory stored per user as flat files
<!-- force deploy on render -->

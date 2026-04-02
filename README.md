# SecureChat

Encrypted chat with hardware-key authentication and E2E room secrets.

## Render Deploy

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=<YOUR_GITHUB_REPO_URL>)

## Local Run

```bash
python chat_server.py
```

Open `http://localhost:5000`.

## Health Check

`/healthz` returns `{ "ok": true }`.

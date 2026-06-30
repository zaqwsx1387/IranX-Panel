# ⚡ XRay Panel

[![Python](https://img.shields.io/badge/Python-3.11-blue)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.111-green)](https://fastapi.tiangolo.com/)
[![License](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)

> A lightweight, self-hosted subscription management panel for VLESS over WebSocket + TLS.  
> Built entirely in a single Python file, powered by FastAPI and SQLite.

**Readme:** [English](README.md) | [فارسی](README-fa.md)

---

## ✨ Key Features

- **User Management** — Create users with traffic limits, expiry, max connections, country flags
- **Subscription Links** — Auto-generated sub links for v2rayNG, Nekobox, etc.
- **Clean IP Manager** — Add/bulk import IPs that get embedded in sub links
- **Real-time Dashboard** — CPU, RAM, Disk, Network monitoring + user charts
- **Telegram Notifications** — Login alerts, expiry warnings, new user alerts
- **Keep-Alive** — Simple/Advanced modes to prevent service sleeping
- **JWT Auth** — Secure cookie-based sessions

## 🚀 Quick Deploy on Railway

1. Fork this repository
2. Go to [railway.app](https://railway.app) → New Project → Deploy from GitHub
3. Select your forked repo (Railway auto-detects the Dockerfile)
4. Set environment variables:

| Variable | Example | Description |
|----------|---------|-------------|
| `ADMIN_USERNAME` | `admin` | Panel login username |
| `ADMIN_PASSWORD` | `Admin@12345` | Panel login password |
| `SECRET_KEY` | `random_string` | JWT signing key |
| `DOMAIN` | `xyz.up.railway.app` | Your public domain |
| `DB_PATH` | `/data/panel.db` | SQLite database path |
| `TG_BOT_TOKEN` | `123:ABC...` | Telegram bot token (optional) |
| `TG_CHAT_ID` | `-100...` | Telegram chat ID (optional) |

5. Add a Volume with mount path `/data`
6. Access panel at: `https://your-domain/panel`

## 📁 Repository Structure

| File | Purpose |
|------|---------|
| `main.py` | Core application — FastAPI backend + embedded HTML/JS frontend |
| `Dockerfile` | Container build |
| `requirements.txt` | Python dependencies |
| `render.yaml` | Render deployment blueprint |
| `Procfile` | Railway/Heroku start command |
| `panel-config.toml` | Configuration reference |

## ⚖️ Disclaimer

For personal, educational, and experimental use only. Not for commercial VPN services.

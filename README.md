# SOC Alert Triage

Production-oriented security alert triage platform: **Python (FastAPI) backend**, **SQLite/Postgres** persistence, **React** UI, **Docker** images for Docker Hub, and **GitHub Actions** CI/CD with GitFlow-style branching.

**Phase 1** focuses on alert logging, owner validation messages, and **parallel investigation agents**. **AI is disabled by default** — enable it in Settings with your own API key (OpenAI, Anthropic, Ollama, or OpenAI-compatible endpoints).

## Features

- Log alerts with process tree, timeline logs, IOCs, and raw logs
- Persist all data in a database (SQLite by default)
- Run **one investigation agent per alert** (parallel across alerts)
- Live agent feed with progress bar and Markdown investigation report
- Rule-based investigation when AI is off
- Optional LLM investigation when AI is enabled + API key configured
- Copy owner validation request text
- Container image ready for Docker Hub

## Quick start (local dev)

### Backend

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
$env:SECRET_KEY = "dev-secret-change-in-prod"
uvicorn app.main:app --reload --port 8000
```

### Frontend

```powershell
cd frontend
npm install
npm run dev
```

Open http://localhost:5173 (API proxied to :8000).

## Docker (recommended)

```powershell
cp .env.example .env
# Edit SECRET_KEY

docker compose build
docker compose up -d
```

Open http://localhost:8000

## Docker Hub

1. Create a [Docker Hub](https://hub.docker.com/) access token.
2. Add GitHub repository secrets:
   - `DOCKERHUB_USERNAME`
   - `DOCKERHUB_TOKEN`
3. Merge to `main` and push a semver tag, e.g. `v1.0.0`:

```bash
git tag v1.0.0
git push origin v1.0.0
```

The **Release** workflow builds multi-arch images and pushes:

- `YOUR_USER/soc-alert-triage:1.0.0`
- `YOUR_USER/soc-alert-triage:latest`

### Run published image

```bash
docker pull YOUR_USER/soc-alert-triage:latest
docker run -p 8000:8000 \
  -e SECRET_KEY=your-long-random-secret \
  -v triage-data:/app/data \
  YOUR_USER/soc-alert-triage:latest
```

## AI settings (optional)

| Setting | Description |
|---------|-------------|
| Enable AI | Off by default — no external calls until enabled |
| Provider | `openai`, `anthropic`, `ollama`, `openai_compatible` |
| Model | e.g. `gpt-4o-mini`, `claude-3-5-haiku-20241022`, `llama3.2` |
| API Base URL | Required for Ollama/custom (`http://localhost:11434/v1`) |
| API Key | Stored encrypted (Fernet + `SECRET_KEY`) |

Use **Test API key** after saving. Without AI, agents still produce a structured **rule-based** investigation report.

## CI/CD

| Workflow | Trigger | Actions |
|----------|---------|---------|
| `ci.yml` | PR / push to `main`, `develop` | pytest, frontend build, Docker build |
| `release.yml` | Tag `v*.*.*` | Tests, push image to Docker Hub, GitHub Release |
| `auto-tag.yml` | Push to `main` | Auto patch tag `v*.*.*` (disable if you prefer manual tags) |

See [docs/BRANCHING.md](docs/BRANCHING.md) for branch strategy.

## Project layout

```
backend/          FastAPI + SQLAlchemy
frontend/         React (Vite)
Dockerfile        Multi-stage build
docker-compose.yml
.github/workflows/
docs/BRANCHING.md
```

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SECRET_KEY` | (required in prod) | Encrypts stored API keys |
| `DATABASE_URL` | SQLite file in `./data` | Use Postgres URL for scale |
| `STATIC_DIR` | set in Docker | Serves built React app |
| `CORS_ORIGINS` | `*` | Comma-separated origins |

## License

MIT — use and extend for your SOC workflows.

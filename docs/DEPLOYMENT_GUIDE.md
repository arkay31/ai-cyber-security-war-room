# Cloud & Local Deployment Guide
## Aegis One – AI Cyber Security War Room

This guide provides step-by-step instructions for deploying Aegis One locally for offline evaluation, in Docker containers, and on public cloud platforms (Vercel + Render + PostgreSQL pgvector).

---

## 1. Local Hybrid Architecture (Recommended for Development & Interviews)

This mode runs PostgreSQL in Docker (with hardware port mapping) and runs FastAPI and Next.js natively with Apple Silicon GPU acceleration for Ollama.

### Prerequisites
- macOS, Linux, or Windows (WSL2)
- Docker Desktop
- Python 3.11+
- Node.js 20+ / 22+

### One-Command Startup
```bash
./start_warroom.sh
```
This script automatically:
1. Validates `.nosync` protections on `node_modules` and Python `venv` (guarding against iCloud file eviction on macOS).
2. Starts the PostgreSQL 16 `pgvector` container on port `5432`.
3. Validates database connectivity and initializes tables/extensions.
4. Starts the FastAPI backend daemon on `http://localhost:8000`.
5. Starts the Next.js development server on `http://localhost:3000`.

---

## 2. Full-Stack Docker Compose Deployment

To run the entire platform within isolated Docker containers:

```bash
docker compose up -d
```

### Services Orchestrated:
- **`warroom-postgres`**: PostgreSQL 16 + pgvector on port `5432`.
- **`warroom-backend`**: FastAPI application on port `8000` (`Dockerfile.backend`).
- **`warroom-frontend`**: Next.js 16 production build on port `3000` (`Dockerfile.frontend`).

---

## 3. Public Cloud Deployment (Production)

### Architecture
- **Frontend**: Next.js 16 deployed on **Vercel** with edge routing.
- **Backend**: FastAPI deployed on **Render** (Docker Web Service).
- **Database**: Managed PostgreSQL 16 with `pgvector` on **Render** or **Neon / Supabase**.
- **LLM Provider**: Hosted **Groq** (`llama-3.3-70b-versatile`) or **OpenAI** (`gpt-4o-mini`).

---

### Step 3.1: Deploy Backend & Database on Render

1. Fork or push the repository to GitHub.
2. Log into [Render Dashboard](https://dashboard.render.com).
3. Click **New +** $\to$ **Blueprint**.
4. Connect your repository and select [`render.yaml`](file:///Users/rakshitkapoor/Desktop/ai-cyber-security-war-room/render.yaml).
5. Set environment variables in the Render dashboard:
   - `LLM_PROVIDER`: `groq`
   - `GROQ_API_KEY`: your Groq API key (`gsk_...`)
   - `GROQ_MODEL`: `llama-3.3-70b-versatile`
   - `CORS_ORIGINS`: `["https://your-vercel-domain.vercel.app","http://localhost:3000"]`
6. Click **Apply Blueprint**. Render builds the backend using `Dockerfile.backend` and provisions a PostgreSQL instance with pgvector.
7. Copy your deployed backend service URL (e.g. `https://aegis-warroom-backend.onrender.com`).

---

### Step 3.2: Deploy Frontend on Vercel

1. Log into [Vercel](https://vercel.com).
2. Click **Add New** $\to$ **Project**.
3. Import your repository.
4. Set Environment Variables:
   - `NEXT_PUBLIC_API_URL`: `https://aegis-warroom-backend.onrender.com`
5. Update [`vercel.json`](file:///Users/rakshitkapoor/Desktop/ai-cyber-security-war-room/vercel.json) destination URL if using API rewrites.
6. Click **Deploy**. Vercel optimizes and builds the production Next.js frontend with zero server-side rendering latency.

---

## 4. Production Security & Hardening Checklist

- [x] **CORS Origin Whitelisting**: Restricted strictly to authorized frontend domains.
- [x] **Database Isolation**: Database container runs on non-default passwords with SSL required in cloud mode.
- [x] **Secrets Management**: No API keys or credentials committed to git; `.env.example` templates provided.
- [x] **Fail-Safe Inference**: Automated fallback to `RULE_BASED` when cloud LLM quotas or local daemons are exhausted.
- [x] **Audit Trail Integrity**: All autonomous analyst recommendations and human decisions are written to immutable PostgreSQL audit logs.

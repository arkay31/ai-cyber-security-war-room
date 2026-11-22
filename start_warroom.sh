#!/usr/bin/env bash
# ==============================================================================
# Aegis One – AI Cyber Security War Room Startup Script
# Orchestrates Database, Backend (FastAPI), and Frontend (Next.js)
# ==============================================================================

set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

# Color codes
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}===================================================================${NC}"
echo -e "${BLUE}       Aegis One – AI Cyber Security War Room Orchestrator         ${NC}"
echo -e "${BLUE}===================================================================${NC}"

# 1. Check Docker Daemon
echo -e "\n${YELLOW}[1/5] Checking Docker Desktop & Database Container...${NC}"
if ! docker info >/dev/null 2>&1; then
    echo -e "${RED}Error: Docker is not running. Please start Docker Desktop and try again.${NC}"
    exit 1
fi

# Check if warroom-postgres is running
if [ "$(docker ps -q -f name=warroom-postgres)" ]; then
    echo -e "${GREEN}✓ Container 'warroom-postgres' is already running.${NC}"
elif [ "$(docker ps -aq -f name=warroom-postgres)" ]; then
    echo -e "${YELLOW}Starting existing 'warroom-postgres' container...${NC}"
    docker start warroom-postgres >/dev/null
    echo -e "${GREEN}✓ Container 'warroom-postgres' started.${NC}"
else
    echo -e "${YELLOW}Creating 'warroom-postgres' container via docker-compose...${NC}"
    docker compose up -d warroom-postgres
    echo -e "${GREEN}✓ Container 'warroom-postgres' initialized.${NC}"
fi

# Wait for PostgreSQL to accept connections on port 5432
echo -e "${YELLOW}Waiting for PostgreSQL on localhost:5432...${NC}"
RETRIES=15
until docker exec warroom-postgres pg_isready -U warroom -d warroom >/dev/null 2>&1 || [ $RETRIES -eq 0 ]; do
    sleep 1
    RETRIES=$((RETRIES - 1))
done

if [ $RETRIES -eq 0 ]; then
    echo -e "${RED}Error: PostgreSQL did not become ready in time.${NC}"
    exit 1
fi
echo -e "${GREEN}✓ PostgreSQL database is healthy and accepting connections.${NC}"

# 2. Check Ollama LLM Service
echo -e "\n${YELLOW}[2/5] Checking Ollama LLM Engine...${NC}"
if /usr/bin/curl -s http://localhost:11434/api/tags >/dev/null 2>&1; then
    echo -e "${GREEN}✓ Ollama LLM daemon is reachable on http://localhost:11434.${NC}"
else
    echo -e "${YELLOW}! Ollama daemon is not running on port 11434.${NC}"
    echo -e "${YELLOW}  (AI Analyst will automatically operate in deterministic fallback mode.)${NC}"
    echo -e "${YELLOW}  To enable full LLM inference, run: 'ollama serve' in another terminal.${NC}"
fi

# 3. Check macOS iCloud node_modules.nosync & backend/venv.nosync links
echo -e "\n${YELLOW}[3/5] Verifying Dependencies & iCloud Protection...${NC}"
if [ -d "node_modules.nosync" ] && [ -L "node_modules" ]; then
    echo -e "${GREEN}✓ node_modules is shielded from iCloud eviction via .nosync symlink.${NC}"
elif [ -d "node_modules" ] && [ ! -L "node_modules" ]; then
    echo -e "${YELLOW}Shielding node_modules with .nosync convention...${NC}"
    mv node_modules node_modules.nosync
    ln -s node_modules.nosync node_modules
    echo -e "${GREEN}✓ Converted node_modules to .nosync symlink.${NC}"
fi

if [ -d "backend/venv.nosync" ] && [ -L "backend/venv" ]; then
    echo -e "${GREEN}✓ backend/venv is shielded from iCloud eviction via .nosync symlink.${NC}"
elif [ -d "backend/venv" ] && [ ! -L "backend/venv" ]; then
    echo -e "${YELLOW}Shielding backend/venv with .nosync convention...${NC}"
    mv backend/venv backend/venv.nosync
    ln -s venv.nosync backend/venv
    echo -e "${GREEN}✓ Converted backend/venv to .nosync symlink.${NC}"
fi

# Cleanup any stale dev locks
rm -f .next/dev/lock

# 4. Start FastAPI Backend in Background
echo -e "\n${YELLOW}[4/5] Launching FastAPI Backend...${NC}"
BACKEND_PID=""

cleanup() {
    echo -e "\n${YELLOW}Shutting down War Room services...${NC}"
    if [ -n "$BACKEND_PID" ]; then
        echo "Stopping FastAPI backend (PID: $BACKEND_PID)..."
        kill -TERM "$BACKEND_PID" 2>/dev/null || true
    fi
    echo -e "${GREEN}War Room services stopped.${NC}"
    exit 0
}

trap cleanup SIGINT SIGTERM EXIT

PYTHONPATH=. backend/venv/bin/uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 &
BACKEND_PID=$!

# Wait for backend healthcheck
echo -e "${YELLOW}Waiting for FastAPI to report healthy on http://localhost:8000/api/health...${NC}"
BACKEND_RETRIES=20
until /usr/bin/curl -s http://localhost:8000/api/health | grep -q '"status":"healthy"' || [ $BACKEND_RETRIES -eq 0 ]; do
    sleep 1
    BACKEND_RETRIES=$((BACKEND_RETRIES - 1))
done

if [ $BACKEND_RETRIES -eq 0 ]; then
    echo -e "${RED}Error: Backend failed to start.${NC}"
    exit 1
fi
echo -e "${GREEN}✓ FastAPI backend is active and healthy.${NC}"

# 5. Service Summary & Launch Frontend
echo -e "\n${BLUE}===================================================================${NC}"
echo -e "${GREEN}       Aegis One – AI Cyber Security War Room is READY             ${NC}"
echo -e "${BLUE}===================================================================${NC}"
echo -e "  Frontend Dashboard : ${GREEN}http://localhost:3000${NC}"
echo -e "  FastAPI Backend    : ${GREEN}http://localhost:8000${NC}"
echo -e "  Swagger API Docs   : ${GREEN}http://localhost:8000/docs${NC}"
echo -e "  PostgreSQL Server  : ${GREEN}localhost:5432 (warroom-postgres)${NC}"
echo -e "${BLUE}===================================================================${NC}"
echo -e "${YELLOW}Starting Next.js frontend on http://localhost:3000 (Press Ctrl+C to stop all)...${NC}\n"

npm run dev

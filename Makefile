.PHONY: help dev pcap test clean install backend frontend docker-build docker-up docker-down logs

help:
	@echo "Home Net Guardian - Development Commands"
	@echo ""
	@echo "  make dev        - Run both backend and frontend in development mode"
	@echo "  make pcap       - Generate sample PCAP and run in offline mode"
	@echo "  make test       - Run all tests"
	@echo "  make clean      - Clean generated files and caches"
	@echo "  make install    - Install all dependencies"
	@echo "  make backend    - Run backend only"
	@echo "  make frontend   - Run frontend only"
	@echo "  make docker-build - Build Docker images"
	@echo "  make docker-up  - Start services with Docker Compose"
	@echo "  make docker-down - Stop Docker Compose services"
	@echo "  make logs       - Show Docker logs"

# Development
dev: docker-up
	@echo "Starting Home Net Guardian..."
	@echo "Backend: http://localhost:8000"
	@echo "Frontend: http://localhost:5173"

backend:
	cd backend && poetry run uvicorn app:app --reload --host 0.0.0.0 --port 8000

frontend:
	cd frontend && pnpm dev

# PCAP mode with sample data
pcap:
	@echo "Generating synthetic PCAP..."
	cd backend && poetry run python scripts/generate_synthetic_pcap.py
	@echo "Starting in PCAP mode..."
	CAPTURE_MODE=pcap PCAP_PATH=data/sample.pcap $(MAKE) dev

# Testing
test:
	@echo "Running backend tests..."
	cd backend && poetry run pytest tests/ -v --cov=app --cov=core --cov=capture --cov=detection
	@echo "Running frontend tests..."
	cd frontend && pnpm test

lint:
	@echo "Linting backend..."
	cd backend && poetry run ruff check . && poetry run black --check .
	@echo "Linting frontend..."
	cd frontend && pnpm lint

format:
	@echo "Formatting backend..."
	cd backend && poetry run black . && poetry run ruff check --fix .
	@echo "Formatting frontend..."
	cd frontend && pnpm format

# Installation
install: install-backend install-frontend

install-backend:
	cd backend && poetry install

install-frontend:
	cd frontend && pnpm install

# Docker
docker-build:
	docker-compose build

docker-up:
	docker-compose up -d

docker-down:
	docker-compose down

docker-clean:
	docker-compose down -v
	docker-compose rm -f

logs:
	docker-compose logs -f

# Clean
clean:
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".ruff_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name "node_modules" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".next" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name "dist" -exec rm -rf {} + 2>/dev/null || true
	rm -rf backend/.coverage backend/htmlcov
	rm -f backend/guardian.db

# Database
db-reset:
	rm -f backend/guardian.db
	cd backend && poetry run python -c "from db.models import create_tables; create_tables()"

# Development helpers
shell:
	cd backend && poetry run python

watch-backend:
	cd backend && poetry run watchmedo auto-restart --pattern="*.py" --recursive --signal SIGTERM python app.py

generate-oui:
	cd backend && poetry run python scripts/fetch_oui.py

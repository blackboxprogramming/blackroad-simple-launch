# BlackRoad OS - Development Commands
.PHONY: help install dev run test deploy clean

# Default target
help:
	@echo "BlackRoad OS - Available Commands"
	@echo ""
	@echo "  make install     - Install Python dependencies"
	@echo "  make dev         - Run development server"
	@echo "  make run         - Run production server"
	@echo "  make db-init     - Initialize database"
	@echo "  make db-reset    - Reset database"
	@echo "  make admin       - Create admin user"
	@echo "  make test        - Run tests"
	@echo "  make deploy-fe   - Deploy frontend to Cloudflare"
	@echo "  make stripe-test - Test Stripe webhooks locally"
	@echo "  make clean       - Clean cache files"
	@echo ""

# Setup & Installation
install:
	python3 -m venv .venv
	. .venv/bin/activate && pip install -r requirements.txt
	@echo "Virtual environment created. Run: source .venv/bin/activate"

# Development
dev:
	. .venv/bin/activate && python app.py

run:
	. .venv/bin/activate && gunicorn -w 4 -b 0.0.0.0:5000 app:app

# Database
db-init:
	. .venv/bin/activate && flask init-db

db-reset:
	rm -f blackroad.db
	. .venv/bin/activate && flask init-db
	@echo "Database reset complete"

admin:
	. .venv/bin/activate && flask create-admin

# Testing
test:
	. .venv/bin/activate && pytest -v

# Deployment
deploy-fe:
	npx wrangler pages deploy . --project-name=app-blackroad-io

# Stripe
stripe-test:
	stripe listen --forward-to localhost:5000/webhook/stripe

stripe-setup:
	. .venv/bin/activate && python setup-stripe.py

stripe-promo:
	. .venv/bin/activate && python create-promo-codes.py

# Cleanup
clean:
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	find . -type f -name ".DS_Store" -delete 2>/dev/null || true
	rm -rf .pytest_cache 2>/dev/null || true
	@echo "Cleaned up cache files"

# Environment
env-check:
	@echo "Checking environment variables..."
	@test -n "$$STRIPE_SECRET_KEY" || echo "WARNING: STRIPE_SECRET_KEY not set"
	@test -n "$$SECRET_KEY" || echo "WARNING: SECRET_KEY not set"
	@test -n "$$SENDGRID_API_KEY" || echo "INFO: SENDGRID_API_KEY not set (emails will be logged only)"

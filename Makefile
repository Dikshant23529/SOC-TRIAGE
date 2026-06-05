.PHONY: dev-backend dev-frontend test docker-up

dev-backend:
	cd backend && uvicorn app.main:app --reload --port 8000

dev-frontend:
	cd frontend && npm run dev

test:
	cd backend && pytest -q
	cd frontend && npm run build

docker-up:
	docker compose up --build -d

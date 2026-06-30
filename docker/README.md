# AC3 Docker Development Environment

## Quick Start

```bash
# 1. Copy environment template
cp docker/env.example.txt .env
# Edit .env with your API keys

# 2. Start MySQL only (for local Node.js development)
docker compose up -d mysql

# 3. Run the app locally with hot reload
pnpm dev

# 4. Or run the full production stack locally
docker compose up -d
# App available at http://localhost:8080
```

## Services

| Service | Port | Purpose |
|---------|------|---------|
| `mysql` | 3306 | MySQL 8.0 (mirrors RDS `ac3-dev-mysql` parameter group) |
| `app` | 8080 | AC3 application (built from `Dockerfile.aws`) |
| `localstack` | 4566 | S3 emulation for offline dev (optional, use `--profile offline`) |

## Common Commands

```bash
# Start everything
docker compose up -d

# Start with LocalStack for offline S3
docker compose --profile offline up -d

# View logs
docker compose logs -f app
docker compose logs -f mysql

# Rebuild after code changes
docker compose up -d --build app

# Reset database (destroys all data)
docker compose down -v
docker compose up -d mysql

# Run database migrations
docker compose exec app node -e "require('./dist/index.js')"
# Or connect directly:
docker compose exec mysql mysql -u ac3admin -p ac3dev

# Shell into the app container
docker compose exec app sh
```

## MySQL Connection

From your local machine (for tools like DBeaver, DataGrip):
- Host: `localhost`
- Port: `3306`
- User: `ac3admin`
- Password: (from `.env` MYSQL_PASSWORD)
- Database: `ac3dev`

## Architecture Notes

The `docker-compose.yml` mirrors the AWS deployment architecture:
- MySQL config (`docker/mysql/my.cnf`) matches the RDS parameter group `ac3-dev-mysql80`
- The app container uses `Dockerfile.aws` (multi-stage, non-root, same as ECS)
- S3 buckets are real AWS (or LocalStack for offline mode)

This ensures local development behavior matches production as closely as possible.

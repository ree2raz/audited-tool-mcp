# Temporal Docker Compose

Local Temporal cluster for development and testing.

## Quick Start

```bash
docker compose -f docker/docker-compose.temporal.yml up -d
```

## Services

| Service | Port | Description |
|---------|------|-------------|
| PostgreSQL | 5432 | Persistence for Temporal |
| Temporal Server | 7233 | gRPC endpoint for workers and clients |
| Temporal UI | 8080 | Web UI for workflow inspection |

## Verify

```bash
# Check Temporal server is running
temporalio/tctl:1.24 --address localhost:7233 cluster health

# Open UI
open http://localhost:8080
```

## Stop

```bash
docker compose -f docker/docker-compose.temporal.yml down
```

## Data Persistence

Postgres data is stored in a Docker volume `temporal-postgres-data`.
To reset all data:

```bash
docker compose -f docker/docker-compose.temporal.yml down -v
```

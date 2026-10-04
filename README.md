# Oryon Go

A Go backend for authentication, user profiles, and notifications. It includes MFA, JWT auth, pluggable messaging/storage backends, and OpenTelemetry instrumentation.

## Features

- User registration, email verification, login, refresh tokens
- MFA with TOTP and backup code rotation
- Password reset/change flows and profile management
- RESTful JSON API with Swagger/OpenAPI specs
- Pluggable messaging (NSQ/Kafka/NATS/Pub/Sub) and storage (S3/GCS/MinIO)
- Observability via OpenTelemetry

## Tech Stack

- Go 1.27.0
- postgreSQL 18+ (pgx)
- redis 8+
- JWT (HS512), 
- SMTP mailer
- goose for Database migration tool (v3.28.0)
- sqlc for Generate type-safe code from SQL (v1.31.1)
- lefthook for Git hooks
- golangci-lint for static analysis

## Project Structure

```sh
.
├── main.go           # application entrypoint
├── api               # Swagger/OpenAPI artifacts
├── config            # YAML configuration
├── database          # migrations, sqlc queries, seed scripts
├── deploy            # observability stack configs
├── docs              # documentation
├── internal          # application modules and shared packages
│   ├── app           # bootstrapping and wiring
│   ├── identity      # auth and profile domain
│   ├── notification  # notification and email domain
│   ├── media         # media module
│   ├── pkg           # shared packages
```

## Setup (Local)

1) Install required tools
    - Install Go v1.27.0 or above.
    - Install lefthook: see [install](https://lefthook.dev/installation/go/)
    - Install golangci-lint: see [install](https://golangci-lint.run/docs/welcome/install/local/)
    - Install goose: see [install](https://github.com/pressly/goose)
    - Install sqlc: see [install](https://docs.sqlc.dev/en/latest/overview/install.html)
    - Install swag: see [install](https://github.com/swaggo/swag)

    The repository uses Lefthook to run checks before commits and pushes. Git hooks are not installed automatically by `git clone`, so each developer must run `lefthook install` once after cloning the repository.

2) Copy config:
```bash
cp config/config.example.yaml config/config.yaml
```

3) Start dependencies:
```bash
podman-compose up -d
```

3) Run migrations and seeds:
```bash
export POSTGRES_USER=user
export POSTGRES_PASSWORD=password
export POSTGRES_DB=gobite

# or create .env

make migrate-up
make seed-up
```

## Git Hooks

This project uses Lefthook for local Git hooks.

### Pre-commit

Before every commit, Lefthook runs:

- `gofmt` on staged Go files
- `go vet ./...`
- `golangci-lint run`

Formatting changes made by `gofmt` are automatically re-staged.

### Pre-push

Before every push:

- `go test ./...`

must pass.

### Manual installation

After cloning the repository:

```bash
go install github.com/evilmartians/lefthook@latest
lefthook install
```

You only need to install the hooks once per local clone.

To manually run the hooks:

```bash
lefthook run pre-commit 
lefthook run pre-push
```

## Run the Service

Dev (hot reload):
```bash
make run
```
Direct run:
```bash
LOCAL=true go run main.go
```

## Configuration

- Default config path: `/config/config.yaml`
- Local override: `LOCAL=true` uses `./config/config.yaml`
- Explicit override: `CONFIG_PATH=/path/to/config.yaml`

See `config/config.example.yaml` for all keys.

## Database & Codegen

- `make migrate-up` / `make migrate-down` uses goose against Postgres on `localhost:5432`.
- `make gen-sql` regenerates sqlc models and queries.
- `make gen-api` regenerates Swagger via `swag`.

## Tests

- Unit tests: `make test` or `make test-race`
- API tests: `make test-real` `go test ./tests/...`
- All tests: `go test ./...`

## Makefile Commands

- `make run` - run API with hot reload (reflex)
- `make test` / `make test-race` / `make test-integration`
- `make lint` - run golangci-lint
- `make migrate-up` / `make migrate-down`
- `make seed-up` / `make seed-down`
- `make compose-up` / `make compose-down`
- `make gen-sql` - generate sqlc artifacts
- `make gen-api` - regenerate Swagger

## Troubleshooting

- `failed to init config`: check `CONFIG_PATH` and ensure `config/config.yaml` exists.
- `failed to init redis`: confirm `redis.url` is reachable.
- `authentication required`: missing `Authorization: Bearer <token>` header for protected endpoints.
- Git hooks are not running: run `lefthook install` from the repository root.
- `lefthook: command not found`: ensure the Go bin directory is in your `PATH`.

## Contributing

1) Create a feature branch.
2) Install Lefthook and Git hooks:
    ```bash
    go install github.com/evilmartians/lefthook@latest
    lefthook install
    ```
3) Make your changes.
4) Run `gofmt`, `make lint`, and tests relevant to your change.
5) Commit your changes. Lefthook will run the configured pre-commit checks.
6) Push your branch. Lefthook will run the configured pre-push tests.
7) Open a PR with a concise description and test evidence.
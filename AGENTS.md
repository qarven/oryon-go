# AGENTS.md

## Stack & Entrypoint
- Go `1.27` (`go.mod:3`), module `github.com/qarven/oryon-go`. Single service, not a monorepo.
- Entrypoint `main.go:25` → `internal/app.New()` → `Start()`/`Stop()`. Wiring order in `internal/app/app.go:60`: config → instrument → libraries → JWT → db → cache → mail → middleware → modules → httpServer → closers.
- API is **ConnectRPC** (not plain net/http REST). Proto/handlers from external `github.com/qarven/mono/gen/go/oryon/identity/v1/identityconnect` (`internal/identity/module.go:9`). Swagger is secondary, generated via `swag`.

## Config / Env
- `CONFIG_PATH` overrides everything; else `/config/config.yaml` (prod). `LOCAL=true` switches to `./config/config.yaml` (`internal/app/initiate.go:32`).
- `config/` is gitignored except `config.example.yaml`. Always `cp config/config.example.yaml config/config.yaml` before first run.
- `Makefile:3` does `-include .env` + `export` — `POSTGRES_USER`/`POSTGRES_PASSWORD`/`POSTGRES_DB` must be in `.env` or shell for `migrate-*`/`seed-*`. Example `.env` + `compose.yaml` use `DB=oryon`; `README` still says `gobite` (stale).
- JWT secrets are base64 64-byte values; `config.example.yaml` placeholder is **not** valid base64 — generate with `openssl rand -base64 64` or lint/init will fail.
- Viper watches config file with `fsnotify` and hot-reloads (`internal/pkg/config/viper.go:45`).

## Run & Compose
- Deps: `podman-compose up -d` (not `docker compose`). No app container — run Go locally. Services: Postgres `18-alpine:5432`, Redis `8.10:6379`, Mailpit `1025/8025`, OTEL collector `4317/4318`, Tempo/Prometheus/Loki.
- `make run` uses `reflex` (`Makefile:44`): `reflex -r '\.go$' -s -R 'config|database|deploy|docs' -- sh -c "LOCAL=true go run main.go"`. Requires `reflex` installed.
- `LOCAL=true go run main.go` for direct run.
- `make restart` is **destructive**: `podman-compose down -v` wipes volumes, then `migrate-up`, `seed-up`, `gen-sql`, `gen-api`, `go mod tidy`, `gofmt -w .`.

## Database & Codegen
- Migrations: `goose -dir database/migration` against `postgres://$POSTGRES_USER:$POSTGRES_PASSWORD@localhost:5432/$POSTGRES_DB?sslmode=disable` (`Makefile:63`). Rollback is one step (`down`).
- Seeds: `goose -dir database/seed -table "goose_seed_db_version"` — separate tracking table (`Makefile:74`).
- `make gen-sql` → `sqlc generate` per `sqlc.yaml`: `database/query` + `database/migration` → `internal/pkg/sqlc` with `sql_package: pgx/v5`. Never hand-edit `internal/pkg/sqlc/*`.
- `make gen-api` → `swag init --v3.1 -o api` from `main.go` annotations. Output `api/swagger.{json,yaml}`, `api/docs.go` are generated.

## Make Targets
- `make test` → `go test ./internal/...`
- `make test-race` → `go test -race ./internal/...`
- `make test-real` → `go test -count=1 ./tests/... -parallel 4 -v` (currently no `tests/` dir — will fail if run prematurely)
- `make lint` → `golangci-lint run --fix` (version 2, 5m timeout, `modules-download-mode: readonly`)
- `make compose-up` / `compose-down` wraps `podman-compose`.

## Lint Gotchas (`.golangci.yaml`)
- `tests: false` — test files not linted. `allow-parallel-runners: true`.
- `nolintlint` requires both explanation and specific linter (`require-explanation: true`, `require-specific: true`).
- `tagliatelle` enforces `json: snake` — JSON tags must be snake_case.
- `gosec` excludes `G115` (int conversions). `ireturn` allows `instrument.Instrumentation`, `trace.Tracer`, `metric.Meter`.
- `gocritic`, `wsl_v5`, `cyclop`/`gocyclo`/`gocognit` with max 20 complexity — expect style churn on `make lint --fix`.

## Architecture
- `internal/app/` owns lifecycle; `internal/identity/` follows `domain/`/`application/`/`infrastructure/{cache,persistence}/`/`presentation/connect/` (`internal/identity/module.go:42` → `persistence.NewPostgres` + `cache.NewRedis` → `application.New` → `connect.NewAuthenticationServer/NewUserServer`).
- `internal/pkg/` shared libs: `config`, `instrument` (OTEL), `jwt` (HS512), `hash` (hmac/argon2id/bcrypt), `middleware` (Connect interceptors), `validator` (go-playground), `uid` (snowflake/uuid), `clock`, `goroutine`, `mail`, `sqlc`.
- Interceptor order in `initMiddleware()` matters: `Recovery → Maintenance → Observability → Error → Authentication` (`internal/app/initiate.go:200`).
- Public/maintenance endpoints are exact Connect procedure strings (e.g. `/oryon.identity.v1.AuthenticationService/Login`) from `config.example.yaml:39,46`.

## Tests & Verification
- No `tests/` dir committed; integration suite (`test-real`) needs running Postgres/Redis. Prefer `make test` / `go test ./internal/pkg/...` for focused runs.
- Single package: `go test ./internal/identity/... -run TestName -v` or `go test -run TestFoo ./internal/pkg/jwt -v`.
- Always run `gofmt -w .` and `make lint` before PR (per `README:122`).

## Conventions
- Commit `api/swagger.*` and `internal/pkg/sqlc/*` when you change migrations/queries or `main.go` swagger annotations.
- `config/config.yaml` is local-only — never commit secrets.
- Branch/PR: short description + test evidence per `README:120`.

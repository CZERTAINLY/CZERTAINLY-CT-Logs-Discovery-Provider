# CLAUDE.md

Guidance for agents working in this repository.

## Repo map

| Path                  | Purpose                                                                                   |
|-----------------------|--------------------------------------------------------------------------------------------|
| `cmd`                 | Entry point (`main.go`): loads config, connects to Postgres via GORM, creates/selects the schema, runs migrations, wires the discovery/health/connector-info APIs and their HTTP routes, and runs a daily goroutine that deletes orphaned certificates. |
| `internal/config`     | Environment-variable contract: `Config` and `Get()`.                                       |
| `internal/db`         | GORM Postgres connection setup (schema-scoped naming strategy), the `golang-migrate`-based migration runner, and the discovery repository (CRUD plus orphaned-certificate cleanup). |
| `internal/discovery`  | The `Discovery Provider` / `CT-SSLMate` API: connector-attribute definitions and the service that drives certificate discovery against the SSLMate CT-search API, including retry handling. |
| `internal/health`     | Health-check API.                                                                          |
| `internal/connectorInfo` | Connector info API (function groups, kinds, and endpoint introspection).               |
| `internal/model`      | Generated OpenAPI model DTOs and router plumbing. `attributes_test.go` is the one hand-maintained test in this otherwise-generated package. |
| `internal/sslmate`    | Generated SSLMate (CT search) API client.                                                  |
| `internal/logger`     | zap logger singleton; level is driven by `LOG_LEVEL`.                                       |
| `internal/utils`      | Small helpers (UUID generation for correlation IDs and deterministic endpoint UUIDs).       |
| `migrations`          | SQL migration files consumed by `golang-migrate` (`file://migrations`).                    |

## Commands

- Build: `go build ./...`
- Unit tests: `go test -race ./...` — this repository has no `test/integration` suite or testcontainers harness; all tests run under this one command.
- Format check: `gofmt -l .` (no output means the tree is clean)
- Vet: `go vet ./...`
- Lint: `golangci-lint run --timeout=5m` (config in `.golangci.yml`, v2 format). The checkstyle output formatter writes `golangci-lint-report.xml`, which the Sonar workflows consume — treat a missing report file as a failure, since Sonar would otherwise silently report zero lint issues.
- govulncheck: `go tool govulncheck ./...` (version pinned via the `tool` directive in `go.mod`, verified by `go.sum`).
- Local Sonar analysis: `./scripts/sonar-local.sh` — requires `SONAR_TOKEN` in the environment; runs `go test -race` with coverage and `golangci-lint` first, then `sonar-scanner` against SonarCloud with the quality gate set to block.
- Docker image: `docker build -t ct-logs-discovery-provider .` — the Dockerfile takes no build args; there is no `internal/version`-style package to stamp.

Run every command above from the repo root before considering a change done.

## Conventions

- Every third-party GitHub Action reference is pinned to a full commit SHA
  with the human-readable version as a trailing comment, e.g.
  `owner/action@<full-sha> # vX.Y.Z`. Never reference a third-party action
  by a mutable tag or branch. Org-internal `OmniTrustILM/.github` reusable
  workflows and composite actions are the deliberate exception: they stay on
  the org's release tags or `@main` (org-controlled, kept in sync by the
  org's template-sync process).
- Renovate is the only dependency bot for this repository. It is configured
  org-wide in `OmniTrustILM/.github/renovate.json`. This repository
  deliberately carries no `.github/dependabot.yml`: running both bots opens
  a duplicate pull request for every single update. Don't add one back.
  Dependabot *security* updates are a repository security setting rather
  than a config file, so they are unaffected by that choice.
- `SERVER_PORT`, `LOG_LEVEL`, `DATABASE_HOST`, `DATABASE_PORT`,
  `DATABASE_NAME`, `DATABASE_USER`, `DATABASE_PASSWORD`, `DATABASE_SCHEMA`,
  `DATABASE_SSL_MODE`, `DATABASE_PROPS`, and `SSLMATE_BASE_URL` are a frozen
  deployment contract read by `internal/config`. Never rename, remove, or
  repurpose one; add a new variable instead.
- `internal/model` and `internal/sslmate` are generated from the OpenAPI
  spec (server DTOs and the SSLMate API client, respectively) — don't
  hand-edit their generated files directly; regenerate them instead.
  `internal/model` is excluded from Sonar *coverage* but not from
  *analysis*: it's generated, but edited by hand often enough (see
  `attributes_test.go`) that its smells are worth seeing. `internal/sslmate`
  is excluded from analysis entirely.
- Commit messages are one plain, descriptive line. No co-author trailers
  and no mention of AI assistance or tooling.

## Quality gates

A change is not done until all of these pass:

- **SonarCloud** — `sonar.yml` and `sonar_push.yml` run with
  `sonar.qualitygate.wait=true`, so a failing gate fails the check.
  Coverage, duplication, and new-issue thresholds are whatever quality gate
  is assigned to this project on SonarCloud; check the project directly
  rather than assuming another repository's numbers apply here.
- **CodeQL** (`codeql.yml`) — `go` and `actions` language analysis, no new
  findings.
- **govulncheck** (`go tool govulncheck ./...`, version pinned via the
  go.mod tool directive) — no known vulnerabilities in the module or its
  dependencies.
- **Dependency review** — no newly introduced dependency with a `high`+
  severity advisory.
- **golangci-lint** (`golangci-lint run --timeout=5m`) — zero issues
  against this repo's `.golangci.yml`.

## Local-only paths

These may exist in a checkout but must never be committed (covered by
`.gitignore`):

- `.idea/` — JetBrains IDE project files.
- `.mirrord/` — local mirrord configuration for running against a shared
  cluster.

Check `git status` before staging and make sure none of these are included.

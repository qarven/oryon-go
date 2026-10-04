# Project Instructions

This repository is a Go project. Follow standard Go conventions and keep implementations simple, idiomatic, testable, and maintainable.

## Go Version

- Use the Go version specified in `go.mod`.
- Do not introduce APIs or language features newer than the project's declared Go version without explicit approval.

## Project Structure

Follow the existing repository structure. Do not reorganize packages unless necessary.

```bash
.
├── api
├── config
├── database
│   ├── migration
│   ├── query
│   └── seed
├── deploy
├── docs
└── internal
    ├── app
    ├── identity
    │   ├── application
    │   ├── domain
    │   ├── infrastructure
    │   │   ├── cache
    │   │   │   └── redis
    │   │   ├── event
    │   │   └── persistence
    │   │       └── postgres
    │   └── presentation
    │       └── connect
    ├── notification
    │   ├── application
    │   ├── domain
    │   ├── infrastructure
    │   │   ├── email
    │   │   ├── persistence
    │   │   │   └── postgres
    │   │   └── sms
    │   └── presentation
    │       └── mq
    └── pkg
        ├── clock
        ├── config
        └── ...
```

## Go Style

- Write idiomatic Go.
- Run `gofmt` on changed Go files.
- Prefer short, clear functions.
- Avoid unnecessary abstractions.
- Prefer composition over inheritance.
- Use interfaces only when they provide a concrete benefit.
- Keep interfaces small.
- Return errors explicitly.
- Avoid panic for normal application errors.
- Do not use `interface{}` when a more specific type is appropriate; use `any` when an empty interface is actually required.
- Use meaningful names. Avoid unnecessary abbreviations.
- Follow standard Go naming conventions:
    - MixedCaps for exported identifiers.
    - mixedCaps for unexported identifiers.
    - Initialisms should remain capitalized, e.g. HTTP, URL, ID, API.

## Packages
- Keep packages focused on a single responsibility.
- Avoid circular dependencies.
- Avoid package names such as `utils`, `helpers`, or `common` unless the package has a clear, cohesive purpose.
- Keep implementation details private unless they are part of the package's intended API.

## Formatting and Static Analysis

Before completing a change, run:

- `gofmt -w .`
- `go vet ./...`
- `go test ./...`

If the repository uses additional tooling such as `golangci-lint`, `staticcheck`, or `goimports`, follow the existing project configuration.

Do not introduce a new formatter or linter configuration without a reason.

## Dependencies

- Prefer the standard library when it is sufficient.
- Do not add dependencies for trivial functionality.
- Before adding a dependency, check whether an existing dependency already solves the problem.
- Keep `go.mod` and `go.sum` consistent.
- Avoid upgrading unrelated dependencies.
- Use: `go mod tidy`

only when dependency changes require it or when explicitly requested.

## Generated Code
- Do not manually modify generated files unless explicitly required.
- Follow the repository's generation commands.
- If generated code changes, include the source/configuration changes that caused it when appropriate.

## Before Finishing a Task
- Review the changed files.
- Remove unused code and unnecessary changes.
- Run `gofmt`.
- Run relevant tests.
- Run `go vet ./...` when practical.
- Check for accidental changes to generated files, dependencies, or configuration.
- Ensure no secrets or sensitive data were added.
- Keep the final change focused on the requested task.

## General Principle

Prefer the simplest idiomatic Go solution that satisfies the requirement.

Before introducing abstraction, ask whether a small function, struct, interface, or package is sufficient. Optimize for readability and maintainability first.
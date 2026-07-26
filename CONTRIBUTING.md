# Contributing to Arc Doctor

Arc Doctor is an unofficial, read-only Arc Testnet diagnostic tool. Contributions
should make its conclusions more accurate, explainable, or useful without adding
transaction signing, automatic fixes, or hidden network activity.

## Before opening a change

- Do not include private keys, seed phrases, passwords, authenticated RPC URLs,
  environment files, or private project data.
- Use public or deliberately fabricated evidence in tests.
- Open an issue before introducing a new dependency or changing a diagnostic code.
- Keep diagnostic conclusions deterministic. A model or remote service must not
  decide whether a finding is emitted.
- Do not describe a successful transaction or bytecode match as proof that a
  contract is safe.

## Adding a diagnostic rule

1. Start with a reproducible failure or configuration problem.
2. Record the minimum sanitized evidence required to identify it.
3. Choose the existing diagnostic family that owns the problem.
4. Add a stable code, severity, confidence, explanation, evidence, and suggested
   checks.
5. Keep evidence collection separate from interpretation.
6. Add tests through the central `doctor.Diagnose` seam.
7. Add the new code to `docs/diagnostic-codes.md`.
8. Explain any ambiguity and avoid claiming a unique cause when alternatives
   remain.

Use `certain` only when evidence directly proves the conclusion. Use `likely`
when one explanation is strongly supported but not unique. Use `possible` when
the evidence is compatible with several causes.

## Submitting a diagnostic case

Reviewed cases may later support case lookup. A case submission must follow
[`cases/schema.json`](cases/schema.json) and the process in
[`cases/README.md`](cases/README.md). Submitting a case does not automatically
make it part of a distributed case index.

## Development checks

Run these before opening a pull request:

```bash
test -z "$(gofmt -l .)"
go test -race ./...
go vet ./...
go build ./cmd/arcdoctor
```

When Anvil is installed, `go test ./...` also starts a temporary local node and
exercises successful transactions, standard error strings, panics, custom
errors, historical replay, local-address warnings, and artifact comparison. The
test skips only when Anvil or local listening sockets are unavailable.

Optional read-only live checks use only public Arc Testnet state:

```bash
ARCDOCTOR_LIVE=1 go test -tags=live ./internal/live -count=1
```

The live suite may skip when the public endpoint is temporarily unavailable. A
wrong chain, changed public fixture, or incorrect diagnosis remains a failure.

## Pull requests

Describe the evidence that motivated the change, the confidence assigned to any
new finding, and the commands used to verify it. Keep unrelated formatting or
dependency changes out of the pull request.

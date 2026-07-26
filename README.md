# Arc Doctor

Arc Doctor is an unofficial, read-only diagnostic CLI for Arc Testnet.

It collects evidence from Arc RPC responses and turns common network problems into structured findings with explicit confidence, supporting evidence, and suggested checks.

## Current capabilities

- Verify that an RPC endpoint is reachable
- Confirm the Arc Testnet chain ID
- Read the latest block number and timestamp
- Measure RPC evidence collection latency
- Report a wrong-network configuration
- Produce readable terminal output or machine-readable JSON
- Redact credentials from operational error messages
- Return distinct exit codes for healthy, diagnostic-error, and operational-error outcomes

Arc Doctor never requests a private key, signs a transaction, or changes project configuration.

## Run from source

Requirements:

- Go 1.26 or newer

Run a network check:

```bash
go run ./cmd/arcdoctor check
```

Produce JSON:

```bash
go run ./cmd/arcdoctor check --json
```

Use another RPC endpoint:

```bash
go run ./cmd/arcdoctor check --rpc https://rpc.example
```

Set a timeout:

```bash
go run ./cmd/arcdoctor check --timeout 20s
```

## Example

```text
Arc Doctor

Network:      Arc Testnet
Chain ID:     5042002
Latest block: 53717781
Block time:   2026-07-26T07:06:12Z
Latency:      1.909s

[INFO] ARC-NET-000  Arc Testnet connection confirmed
The RPC endpoint reported the expected Arc Testnet chain ID.
Confidence: certain
Evidence: Expected chain ID: 5042002
Evidence: Observed chain ID: 5042002
```

## Exit codes

- `0`: diagnosis completed without error findings
- `1`: diagnosis completed and found one or more errors
- `2`: Arc Doctor could not complete the diagnosis

## Development

Run the tests:

```bash
go test ./...
```

Run the race detector:

```bash
go test -race ./...
```

Run static checks:

```bash
go vet ./...
```

Build the executable:

```bash
go build -o arcdoctor ./cmd/arcdoctor
```

## Scope

The current implementation focuses on network diagnosis. Address, transaction, ABI-backed error, and deployment diagnostics will be added as their behavior is tested.

Arc Doctor is a community-built tool and is not affiliated with or endorsed by Circle.

## License

MIT

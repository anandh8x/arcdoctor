# Arc Doctor

Arc Doctor is an unofficial, read-only diagnostic CLI for Arc Testnet.

It collects evidence from Arc RPC responses and turns common network problems into structured findings with explicit confidence, supporting evidence, and suggested checks.

## Current capabilities

- Verify that an RPC endpoint is reachable
- Confirm the Arc Testnet chain ID
- Read the latest block number and timestamp
- Measure RPC evidence collection latency
- Report a wrong-network configuration
- Validate EVM addresses before making RPC requests
- Classify addresses by deployed bytecode
- Report raw native-token balance, nonce, bytecode size, and bytecode hash
- Link address evidence to ArcScan
- Distinguish missing, pending, successful, and reverted transactions
- Report sender, destination, value, gas, block, type, and ArcScan evidence
- Decode transaction calldata from supplied Solidity ABIs or artifacts
- Decode `Error(string)`, `Panic(uint256)`, and ABI-backed custom errors
- Replay failed calls against historical state when the RPC endpoint supports it
- Preserve raw revert data and report unavailable or inconclusive replay honestly
- Validate Arc deployment manifests and Foundry broadcast JSON
- Detect wrong chain metadata, malformed and duplicate addresses, missing bytecode,
  failed deployment transactions, and familiar local development addresses
- Compare deployed runtime bytecode with Foundry artifacts
- Normalize declared immutable slots, linked-library slots, and Solidity metadata
  before reporting a bytecode mismatch
- Include schema, collection time, tool version, ruleset version, and per-finding
  rule versions in every real report
- Sanitize known secret patterns and unsafe terminal sequences before serialization
- Re-export existing reports as protected JSON or readable text files
- Produce readable terminal output or machine-readable JSON
- Redact credentials from operational error messages
- Return distinct exit codes for healthy, diagnostic-error, and operational-error outcomes

Arc Doctor never requests a private key, signs a transaction, or changes project configuration.

## Install

Tagged releases provide checksummed archives for Linux, macOS, and Windows.
Download the archive for your platform from
[GitHub Releases](https://github.com/anandh8x/arcdoctor/releases), verify it
against `checksums.txt`, and place the `arcdoctor` executable on your `PATH`.

Install the latest tagged version with Go:

```bash
go install github.com/anandh8x/arcdoctor/cmd/arcdoctor@latest
```

Confirm the installed build:

```bash
arcdoctor --version
```

To build the current source instead, clone the repository and run:

```bash
go build -trimpath -o arcdoctor ./cmd/arcdoctor
```

## Guided terminal interface

Run Arc Doctor without arguments in an interactive terminal:

```bash
go run ./cmd/arcdoctor
```

The guided interface supports environment, address, transaction, and deployment
diagnosis through the same deterministic diagnostic module used by the normal
commands. It provides progress, cancellation, scrollable evidence, responsive
layouts, and sanitized report export.

Keyboard controls are shown on every screen. Use arrow keys to move, `Enter` to
select, `Esc` to go back or cancel, and `Ctrl+C` to quit.

The full-screen interface opens only when both standard input and standard
output are terminals. Running without arguments in a pipe, redirected shell, or
continuous integration environment prints normal command help.

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

Inspect an address:

```bash
go run ./cmd/arcdoctor inspect 0xCe084c9358FBC5200415012885c2F0F0906d400C
```

The balance is reported in raw base units. Arc Doctor does not guess a display
decimal value when the RPC response does not provide token metadata.

Inspect a transaction:

```bash
go run ./cmd/arcdoctor inspect 0x2ae2a47a07856ce9f0f6be62335f558bee7561e5922f53d119c58de66baead17
```

Decode public calldata and custom errors with a local ABI or Foundry artifact:

```bash
go run ./cmd/arcdoctor inspect 0xTRANSACTION_HASH --abi ./out/Contract.sol/Contract.json
```

Repeat `--abi` to provide more than one candidate. If selector matches conflict,
Arc Doctor reports the ambiguity and does not guess.

Validate a deployment manifest:

```bash
go run ./cmd/arcdoctor deployment ./deployments/arc-testnet.json
```

Compare configured contracts with local Foundry artifacts:

```bash
go run ./cmd/arcdoctor deployment ./deployments/arc-testnet.json \
  --artifact InvoiceRegistry=./out/InvoiceRegistry.sol/InvoiceRegistry.json \
  --artifact SealedBidAuction=./out/SealedBidAuction.sol/SealedBidAuction.json
```

The same command accepts a Foundry `run-latest.json` broadcast file. Artifact
overrides use `ContractName=path` and can be repeated.
See the [deployment manifest reference](docs/deployment-manifest.md) for the
supported fields and bytecode comparison rules.

Sanitize and export an existing JSON report:

```bash
go run ./cmd/arcdoctor report report.json --output shared-report.json
```

Use `--format text` for a plain-text export. Arc Doctor redaction is a safety
measure, not a guarantee, so review reports before sharing them. See
[reporting and redaction](docs/reporting.md) and the
[diagnostic code reference](docs/diagnostic-codes.md).

The [public Arc Testnet demonstration](docs/quietpact-demo.md) provides
read-only contract and transaction examples that require no wallet or funds.

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

See [CONTRIBUTING.md](CONTRIBUTING.md) before adding a rule or diagnostic case.

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

The current implementation covers network, address, transaction, ABI-backed
error, deployment, sanitized reports, and a guided terminal interface.

Arc Doctor is a community-built tool and is not affiliated with or endorsed by Circle.

Semantic case retrieval is intentionally not included. It will be considered
only after the repository has enough independently reviewed, non-duplicate cases
to evaluate it against a keyword-search baseline. The core tool does not require
an embedding model, hosted service, or LLM.

## License

MIT

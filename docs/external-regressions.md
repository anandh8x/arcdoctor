# External regression reproductions

Arc Doctor includes sanitized reproductions of three failures reported by Arc
builders. Each reproduction uses fabricated or public input and runs without a
private key.

| Case | Public source | Arc Doctor behavior |
|---|---|---|
| Outdated chain ID `1516` | [arc-node issue 94](https://github.com/circlefin/arc-node/issues/94) | Produces `ARC-NET-002` because the observed identity does not equal Arc Testnet chain ID `5042002` |
| Public RPC request limit `-32011` | [arc-node issue 207](https://github.com/circlefin/arc-node/issues/207) | Recognizes the response as retryable and retries the read-only request once |
| Local Anvil address used with the Arc RPC | [arc-ai-agents deployment record](https://github.com/kenhuangus/arc-ai-agents/blob/master/ARC_TESTNET_DEPLOYMENT_COMPLETE.md) | Produces `ARC-DEP-016` for the familiar local address and `ARC-DEP-006` when Arc has no bytecode there |

The machine-readable inputs are in
[`testdata/external-regressions.json`](../testdata/external-regressions.json).
`internal/regression` reproduces every record through Arc Doctor's public
diagnostic or RPC adapter seam.

These reproductions satisfy the community-release validation target, but they
are not independently reviewed case-library entries. They do not count toward
the twenty reviewed cases required before semantic retrieval can be evaluated.

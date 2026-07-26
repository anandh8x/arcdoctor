# Public Arc Testnet demonstration

This demonstration uses public QuietPact transactions and contracts deployed on
Arc Testnet. It requires no wallet, private key, or testnet funds.

## Confirm the network

```bash
arcdoctor check
```

The expected chain ID is `5042002`. The report also includes the latest block,
block timestamp, request latency, and the evidence behind every finding.

## Inspect a deployed contract

```bash
arcdoctor inspect 0xCe084c9358FBC5200415012885c2F0F0906d400C
```

This public address is the QuietPact `InvoiceRegistry`. Arc Doctor should find
deployed bytecode and show its byte length and Keccak-256 hash.

## Inspect a successful transaction

```bash
arcdoctor inspect 0x2ae2a47a07856ce9f0f6be62335f558bee7561e5922f53d119c58de66baead17
```

The transaction created an invoice record. Without a supplied ABI, Arc Doctor
preserves the input selector and public transaction evidence without guessing a
function name. With the matching public artifact, it decodes the call as:

```text
createInvoice(bytes32,address,address,bytes32,bytes32,bytes32)
```

## Verify the public deployments

The known Arc Testnet deployments are:

- `InvoiceRegistry`: `0xCe084c9358FBC5200415012885c2F0F0906d400C`
- `SealedBidAuction`: `0x0C83623d0abFca5e7ad6E6179bB45A3E70C6C9DA`

Their public deployment transactions and expected bytecode hashes are recorded
in [`testdata/arc-testnet-fixtures.json`](../testdata/arc-testnet-fixtures.json).
The fixture is used by the opt-in live test suite so a changed contract, wrong
network, or regression becomes visible.

## What this demonstrates

The example proves that Arc Doctor can correlate public Arc RPC evidence,
transaction receipts, supplied ABIs, and deployment records. It does not claim
that QuietPact or its contracts are secure.

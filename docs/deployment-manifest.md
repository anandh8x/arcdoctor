# Deployment manifest

Arc Doctor accepts its explicit deployment manifest format and Foundry
`run-latest.json` broadcast output.

## Arc Doctor format

```json
{
  "schemaVersion": 1,
  "network": "Arc Testnet",
  "chainId": 5042002,
  "contracts": {
    "ExampleContract": {
      "address": "0x1111111111111111111111111111111111111111",
      "transactionHash": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "artifact": "../out/ExampleContract.sol/ExampleContract.json"
    }
  }
}
```

`schemaVersion`, `network`, `chainId`, and `contracts` are required. Each
contract needs a name, address, and deployment transaction hash. An artifact is
optional.

Artifact paths in the manifest are resolved relative to the manifest. A command
line override takes precedence:

```bash
arcdoctor deployment ./deployments/arc-testnet.json \
  --artifact ExampleContract=./out/ExampleContract.sol/ExampleContract.json
```

Arc Doctor reads local input only. It does not download source code or artifacts
from an explorer.

## Foundry broadcast format

Pass a Foundry broadcast file directly:

```bash
arcdoctor deployment ./broadcast/Deploy.s.sol/5042002/run-latest.json
```

Only contract-creation transactions are treated as deployments. Arc Doctor
checks each recorded receipt, deployed address, and available bytecode. Supply
artifact overrides when bytecode comparison is required.

## Bytecode comparison

Arc Doctor first compares exact deployed runtime bytecode. If necessary, it
normalizes Solidity metadata and declared immutable or linked-library slots from
the supplied Foundry artifact.

A matching deployment proves only that the observed bytes match the supplied
artifact under those rules. It does not prove source authenticity, contract
security, or official verification.

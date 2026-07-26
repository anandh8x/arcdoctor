# Diagnostic codes

Diagnostic codes remain stable within a ruleset version. Severity describes the
current evidence, while confidence describes how directly that evidence supports
the finding.

## Network and address

| Code | Meaning |
| --- | --- |
| `ARC-NET-000` | Arc Testnet connection confirmed |
| `ARC-NET-002` | RPC endpoint reported the wrong chain ID |
| `ARC-NET-003` | Latest block appeared stale when observed |
| `ARC-ADR-000` | Contract bytecode found |
| `ARC-ADR-001` | Address is malformed |
| `ARC-ADR-002` | No contract bytecode found |

## Transactions

| Code | Meaning |
| --- | --- |
| `ARC-TX-000` | Transaction succeeded |
| `ARC-TX-001` | Transaction hash is malformed |
| `ARC-TX-002` | Transaction was not found |
| `ARC-TX-003` | Transaction is pending |
| `ARC-TX-004` | Transaction reverted |
| `ARC-TX-005` | Calldata decoded with a supplied ABI |
| `ARC-TX-006` | Selector absent from supplied ABIs |
| `ARC-TX-007` | Standard `Error(string)` decoded |
| `ARC-TX-008` | Standard `Panic(uint256)` decoded |
| `ARC-TX-009` | ABI-backed custom error decoded |
| `ARC-TX-010` | Revert data unknown or ambiguous |
| `ARC-TX-011` | Historical replay did not reproduce the revert |
| `ARC-TX-012` | Revert reason remained inconclusive |
| `ARC-TX-013` | Function selector ambiguous across supplied ABIs |
| `ARC-TX-014` | ABI input could not be parsed |
| `ARC-TX-015` | Calldata arguments did not match the ABI |
| `ARC-RPC-001` | Historical replay unavailable from the RPC endpoint |

## Deployments

| Code | Meaning |
| --- | --- |
| `ARC-DEP-000` | Deployment validation completed without error findings |
| `ARC-DEP-001` | Deployment manifest is invalid |
| `ARC-DEP-002` | Manifest schema version is unsupported |
| `ARC-DEP-003` | Manifest targets a different chain |
| `ARC-DEP-004` | Network label is unexpected |
| `ARC-DEP-005` | Contract name, address, or uniqueness validation failed |
| `ARC-DEP-006` | Configured address has no bytecode |
| `ARC-DEP-007` | Configured address has bytecode |
| `ARC-DEP-008` | Deployment transaction is malformed, missing, pending, or failed |
| `ARC-DEP-009` | Deployment transaction succeeded |
| `ARC-DEP-010` | Receipt created a different contract address |
| `ARC-DEP-012` | Artifact comparison was unavailable |
| `ARC-DEP-013` | Runtime bytecode matched exactly |
| `ARC-DEP-014` | Runtime bytecode matched after supported normalization |
| `ARC-DEP-015` | Runtime bytecode did not match |
| `ARC-DEP-016` | Address resembles a familiar local development deployment |
| `ARC-CFG-001` | Manifest records a local RPC endpoint |

Arc Doctor findings do not prove that a contract is safe. They describe the
specific public evidence collected by the selected diagnostic.

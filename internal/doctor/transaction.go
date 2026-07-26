package doctor

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
)

type TransactionState string

const (
	TransactionStateMissing    TransactionState = "missing"
	TransactionStatePending    TransactionState = "pending"
	TransactionStateSuccessful TransactionState = "successful"
	TransactionStateReverted   TransactionState = "reverted"
)

type ReplayStatus string

const (
	ReplayStatusNotAttempted ReplayStatus = "not_attempted"
	ReplayStatusReverted     ReplayStatus = "reverted"
	ReplayStatusSucceeded    ReplayStatus = "succeeded"
	ReplayStatusUnavailable  ReplayStatus = "unavailable"
	ReplayStatusInconclusive ReplayStatus = "inconclusive"
)

type TransactionReceiptSnapshot struct {
	Status          uint64
	GasUsed         uint64
	BlockNumber     uint64
	ContractAddress string
}

type ReplaySnapshot struct {
	Status      ReplayStatus
	BlockNumber uint64
	RevertData  []byte
	Detail      string
}

type TransactionSnapshot struct {
	Found          bool
	From           string
	To             string
	ValueBaseUnits *big.Int
	Input          []byte
	GasLimit       uint64
	Type           uint8
	BlockNumber    *uint64
	Receipt        *TransactionReceiptSnapshot
	Replay         ReplaySnapshot
}

type DecodedArgument struct {
	Name  string `json:"name,omitempty"`
	Type  string `json:"type"`
	Value string `json:"value"`
}

type DecodedCallEvidence struct {
	Signature string            `json:"signature"`
	Source    string            `json:"source"`
	Arguments []DecodedArgument `json:"arguments,omitempty"`
}

type RevertKind string

const (
	RevertKindError   RevertKind = "error_string"
	RevertKindPanic   RevertKind = "panic"
	RevertKindCustom  RevertKind = "custom"
	RevertKindUnknown RevertKind = "unknown"
)

type RevertEvidence struct {
	Kind       RevertKind        `json:"kind"`
	RawData    string            `json:"rawData"`
	Selector   string            `json:"selector,omitempty"`
	Signature  string            `json:"signature,omitempty"`
	Source     string            `json:"source,omitempty"`
	Message    string            `json:"message,omitempty"`
	PanicCode  string            `json:"panicCode,omitempty"`
	Arguments  []DecodedArgument `json:"arguments,omitempty"`
	Ambiguous  bool              `json:"ambiguous,omitempty"`
	Candidates []string          `json:"candidates,omitempty"`
}

type ReplayEvidence struct {
	Status      ReplayStatus `json:"status"`
	BlockNumber uint64       `json:"blockNumber,omitempty"`
	Detail      string       `json:"detail,omitempty"`
}

type TransactionEvidence struct {
	Hash             string               `json:"hash"`
	State            TransactionState     `json:"state"`
	From             string               `json:"from,omitempty"`
	To               string               `json:"to,omitempty"`
	ContractCreation bool                 `json:"contractCreation,omitempty"`
	ValueBaseUnits   string               `json:"valueBaseUnits"`
	InputData        string               `json:"inputData"`
	GasLimit         uint64               `json:"gasLimit"`
	GasUsed          *uint64              `json:"gasUsed,omitempty"`
	Type             uint8                `json:"type"`
	BlockNumber      *uint64              `json:"blockNumber,omitempty"`
	ExplorerURL      string               `json:"explorerUrl"`
	Call             *DecodedCallEvidence `json:"call,omitempty"`
	Revert           *RevertEvidence      `json:"revert,omitempty"`
	Replay           ReplayEvidence       `json:"replay"`
}

func malformedTransactionReport(target string) Report {
	return Report{
		Findings: []Finding{
			{
				Code:        "ARC-TX-001",
				Severity:    SeverityError,
				Confidence:  ConfidenceCertain,
				Title:       "Transaction hash is malformed",
				Explanation: "The supplied target is not a valid 32-byte transaction hash.",
				Evidence: []string{
					fmt.Sprintf("Supplied target: %q", target),
				},
				SuggestedActions: []string{
					"Provide a transaction hash containing 0x followed by 64 hexadecimal characters.",
				},
			},
		},
	}
}

func (d *Doctor) diagnoseTransaction(
	ctx context.Context,
	hash string,
	abiInputs []ABIInput,
) (Report, error) {
	report, err := d.diagnoseNetwork(ctx)
	if err != nil || report.HasErrors() {
		return report, err
	}
	if d.transaction == nil {
		return Report{}, fmt.Errorf("collect transaction evidence: transaction probe is unavailable")
	}

	snapshot, err := d.transaction.TransactionSnapshot(ctx, hash)
	if err != nil {
		return Report{}, fmt.Errorf("collect transaction evidence: %w", err)
	}

	catalog, abiFindings := parseABIs(abiInputs)
	evidence := transactionEvidence(hash, snapshot)
	report.Transaction = &evidence

	if !snapshot.Found {
		report.Findings = append(report.Findings, Finding{
			Code:        "ARC-TX-002",
			Severity:    SeverityError,
			Confidence:  ConfidenceCertain,
			Title:       "Transaction was not found",
			Explanation: "The Arc Testnet RPC endpoint returned no transaction for this hash.",
			Evidence: []string{
				fmt.Sprintf("Transaction hash: %s", hash),
			},
			SuggestedActions: []string{
				"Verify the transaction hash.",
				"Verify that the transaction was submitted to Arc Testnet.",
			},
		})
		report.Findings = append(report.Findings, abiFindings...)
		return report, nil
	}

	switch evidence.State {
	case TransactionStatePending:
		report.Findings = append(report.Findings, Finding{
			Code:        "ARC-TX-003",
			Severity:    SeverityWarning,
			Confidence:  ConfidenceCertain,
			Title:       "Transaction is pending",
			Explanation: "The transaction is known to the RPC endpoint but does not have a receipt yet.",
			Evidence: []string{
				fmt.Sprintf("Transaction hash: %s", hash),
			},
			SuggestedActions: []string{
				"Wait for the transaction to be included or replaced, then inspect it again.",
			},
		})
	case TransactionStateSuccessful:
		report.Findings = append(report.Findings, Finding{
			Code:        "ARC-TX-000",
			Severity:    SeverityInfo,
			Confidence:  ConfidenceCertain,
			Title:       "Transaction succeeded",
			Explanation: "The transaction receipt reports a successful execution status.",
			Evidence: []string{
				fmt.Sprintf("Transaction hash: %s", hash),
				fmt.Sprintf("Receipt status: %d", snapshot.Receipt.Status),
			},
		})
	case TransactionStateReverted:
		report.Findings = append(report.Findings, Finding{
			Code:        "ARC-TX-004",
			Severity:    SeverityError,
			Confidence:  ConfidenceCertain,
			Title:       "Transaction reverted",
			Explanation: "The transaction receipt reports a failed execution status.",
			Evidence: []string{
				fmt.Sprintf("Transaction hash: %s", hash),
				fmt.Sprintf("Receipt status: %d", snapshot.Receipt.Status),
			},
			SuggestedActions: []string{
				"Review the decoded revert evidence and the contract conditions for the called function.",
			},
		})
	}

	report.Findings = append(report.Findings, abiFindings...)
	if len(snapshot.Input) >= 4 {
		call, finding := catalog.decodeCall(snapshot.Input)
		if call != nil {
			report.Transaction.Call = call
		}
		if finding != nil {
			report.Findings = append(report.Findings, *finding)
		}
	}

	if evidence.State == TransactionStateReverted {
		revert, findings := diagnoseReplay(snapshot.Replay, catalog)
		report.Transaction.Revert = revert
		report.Findings = append(report.Findings, findings...)
	}

	return report, nil
}

func transactionEvidence(hash string, snapshot TransactionSnapshot) TransactionEvidence {
	value := "0"
	if snapshot.ValueBaseUnits != nil {
		value = snapshot.ValueBaseUnits.String()
	}

	state := TransactionStateMissing
	if snapshot.Found {
		state = TransactionStatePending
		if snapshot.Receipt != nil {
			if snapshot.Receipt.Status == 1 {
				state = TransactionStateSuccessful
			} else {
				state = TransactionStateReverted
			}
		}
	}

	var gasUsed *uint64
	if snapshot.Receipt != nil {
		used := snapshot.Receipt.GasUsed
		gasUsed = &used
	}

	to := snapshot.To
	if common.IsHexAddress(to) {
		to = common.HexToAddress(to).Hex()
	}
	from := snapshot.From
	if common.IsHexAddress(from) {
		from = common.HexToAddress(from).Hex()
	}

	return TransactionEvidence{
		Hash:             hash,
		State:            state,
		From:             from,
		To:               to,
		ContractCreation: snapshot.Found && snapshot.To == "",
		ValueBaseUnits:   value,
		InputData:        "0x" + hex.EncodeToString(snapshot.Input),
		GasLimit:         snapshot.GasLimit,
		GasUsed:          gasUsed,
		Type:             snapshot.Type,
		BlockNumber:      snapshot.BlockNumber,
		ExplorerURL:      ArcTestnetExplorerURL + "/tx/" + hash,
		Replay: ReplayEvidence{
			Status:      normalizedReplayStatus(snapshot.Replay.Status),
			BlockNumber: snapshot.Replay.BlockNumber,
			Detail:      snapshot.Replay.Detail,
		},
	}
}

func normalizedReplayStatus(status ReplayStatus) ReplayStatus {
	if status == "" {
		return ReplayStatusNotAttempted
	}
	return status
}

func diagnoseReplay(
	replay ReplaySnapshot,
	catalog abiCatalog,
) (*RevertEvidence, []Finding) {
	switch normalizedReplayStatus(replay.Status) {
	case ReplayStatusReverted:
		revert, finding := catalog.decodeRevert(replay.RevertData)
		findings := []Finding{finding}
		return &revert, findings
	case ReplayStatusSucceeded:
		return nil, []Finding{
			{
				Code:        "ARC-TX-011",
				Severity:    SeverityWarning,
				Confidence:  ConfidenceCertain,
				Title:       "Read-only replay did not reproduce the revert",
				Explanation: "The historical eth_call completed successfully, so it did not reproduce the original failed execution.",
				Evidence: []string{
					fmt.Sprintf("Replay block: %d", replay.BlockNumber),
				},
				SuggestedActions: []string{
					"Consider state changes earlier in the original block or transaction-specific execution context.",
				},
			},
		}
	case ReplayStatusUnavailable:
		evidence := []string{"RPC method: eth_call"}
		if replay.Detail != "" {
			evidence = append(evidence, "RPC detail: "+replay.Detail)
		}
		return nil, []Finding{
			{
				Code:        "ARC-RPC-001",
				Severity:    SeverityWarning,
				Confidence:  ConfidenceCertain,
				Title:       "Historical replay is unavailable",
				Explanation: "The transaction evidence remains valid, but the RPC endpoint could not reproduce the call at historical state.",
				Evidence:    evidence,
				SuggestedActions: []string{
					"Try an Arc node that retains the required historical state.",
				},
			},
		}
	case ReplayStatusInconclusive, ReplayStatusNotAttempted:
		evidence := []string{"Replay did not provide revert data"}
		if replay.Detail != "" {
			evidence = append(evidence, "Replay detail: "+replay.Detail)
		}
		return nil, []Finding{
			{
				Code:        "ARC-TX-012",
				Severity:    SeverityWarning,
				Confidence:  ConfidenceCertain,
				Title:       "Revert reason is inconclusive",
				Explanation: "The receipt proves that execution failed, but no decodable revert data was recovered.",
				Evidence:    evidence,
				SuggestedActions: []string{
					"Supply a compatible ABI and retry against an endpoint with historical eth_call support.",
				},
			},
		}
	default:
		return nil, nil
	}
}

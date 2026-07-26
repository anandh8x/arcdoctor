package doctor_test

import (
	"context"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/anandh8x/arcdoctor/internal/doctor"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/crypto"
)

type transactionProbeFunc func(context.Context, string) (doctor.TransactionSnapshot, error)

func (f transactionProbeFunc) TransactionSnapshot(
	ctx context.Context,
	hash string,
) (doctor.TransactionSnapshot, error) {
	return f(ctx, hash)
}

func arcNetworkProbe() networkProbeFunc {
	return func(context.Context) (doctor.NetworkSnapshot, error) {
		return doctor.NetworkSnapshot{
			ChainID:        doctor.ArcTestnetChainID,
			BlockNumber:    54_201_392,
			BlockTimestamp: time.Date(2026, time.July, 26, 12, 0, 0, 0, time.UTC),
			Latency:        42 * time.Millisecond,
		}, nil
	}
}

func TestDiagnoseTransactionRejectsMalformedHashBeforeRPC(t *testing.T) {
	t.Parallel()

	networkCalled := false
	network := networkProbeFunc(func(context.Context) (doctor.NetworkSnapshot, error) {
		networkCalled = true
		return doctor.NetworkSnapshot{}, nil
	})

	report, err := doctor.New(network).Diagnose(context.Background(), doctor.Request{
		Kind:   doctor.TransactionCheck,
		Target: "0x1234",
	})
	if err != nil {
		t.Fatalf("Diagnose() error = %v", err)
	}
	if networkCalled {
		t.Fatal("network probe was called for malformed transaction hash")
	}
	if len(report.Findings) != 1 || report.Findings[0].Code != "ARC-TX-001" {
		t.Fatalf("Findings = %#v, want ARC-TX-001", report.Findings)
	}
}

func TestDiagnoseTransactionReportsExcessivelyNestedABIAsFinding(t *testing.T) {
	t.Parallel()

	const hash = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	transaction := transactionProbeFunc(func(
		context.Context,
		string,
	) (doctor.TransactionSnapshot, error) {
		return doctor.TransactionSnapshot{Found: false}, nil
	})
	nested := []byte(strings.Repeat("[", 65) + strings.Repeat("]", 65))

	report, err := doctor.New(
		arcNetworkProbe(),
		doctor.WithTransactionProbe(transaction),
	).Diagnose(context.Background(), doctor.Request{
		Kind:   doctor.TransactionCheck,
		Target: hash,
		ABIs: []doctor.ABIInput{
			{Name: "nested.json", Data: nested},
		},
	})
	if err != nil {
		t.Fatalf("Diagnose() error = %v", err)
	}
	if !hasFinding(report, "ARC-TX-014") {
		t.Fatalf("Findings = %#v, want ARC-TX-014", report.Findings)
	}
}

func TestDiagnoseTransactionClassifiesSuccessfulTransaction(t *testing.T) {
	t.Parallel()

	const hash = "0x2ae2a47a07856ce9f0f6be62335f558bee7561e5922f53d119c58de66baead17"
	blockNumber := uint64(53_204_900)
	transaction := transactionProbeFunc(func(
		_ context.Context,
		gotHash string,
	) (doctor.TransactionSnapshot, error) {
		if gotHash != hash {
			t.Errorf("TransactionSnapshot() hash = %q, want %q", gotHash, hash)
		}
		return doctor.TransactionSnapshot{
			Found:          true,
			From:           "0x99066fBc97557490fA794F750630bb41733D1004",
			To:             "0xCe084c9358FBC5200415012885c2F0F0906d400C",
			ValueBaseUnits: big.NewInt(0),
			Input:          []byte{0x12, 0x34, 0x56, 0x78},
			GasLimit:       250_000,
			Type:           2,
			BlockNumber:    &blockNumber,
			Receipt: &doctor.TransactionReceiptSnapshot{
				Status:      1,
				GasUsed:     93_421,
				BlockNumber: blockNumber,
			},
		}, nil
	})

	report, err := doctor.New(
		arcNetworkProbe(),
		doctor.WithTransactionProbe(transaction),
	).Diagnose(context.Background(), doctor.Request{
		Kind:   doctor.TransactionCheck,
		Target: hash,
	})
	if err != nil {
		t.Fatalf("Diagnose() error = %v", err)
	}
	if report.Transaction == nil {
		t.Fatal("Transaction evidence is nil")
	}
	if report.Transaction.State != doctor.TransactionStateSuccessful {
		t.Errorf(
			"Transaction.State = %q, want %q",
			report.Transaction.State,
			doctor.TransactionStateSuccessful,
		)
	}
	if report.Transaction.GasUsed == nil || *report.Transaction.GasUsed != 93_421 {
		t.Errorf("Transaction.GasUsed = %v, want 93421", report.Transaction.GasUsed)
	}
	if report.Transaction.ExplorerURL !=
		"https://testnet.arcscan.app/tx/"+hash {
		t.Errorf("Transaction.ExplorerURL = %q", report.Transaction.ExplorerURL)
	}
	if !hasFinding(report, "ARC-TX-000") {
		t.Fatalf("Findings = %#v, want ARC-TX-000", report.Findings)
	}
}

func TestDiagnoseTransactionDecodesCustomErrorFromSuppliedABI(t *testing.T) {
	t.Parallel()

	const hash = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	selector := crypto.Keccak256([]byte("InvalidAuctionData()"))[:4]
	blockNumber := uint64(53_204_880)
	transaction := transactionProbeFunc(func(
		context.Context,
		string,
	) (doctor.TransactionSnapshot, error) {
		return doctor.TransactionSnapshot{
			Found:          true,
			From:           "0x99066fBc97557490fA794F750630bb41733D1004",
			To:             "0x0C83623d0abFca5e7ad6E6179bB45A3E70C6C9DA",
			ValueBaseUnits: big.NewInt(0),
			GasLimit:       250_000,
			Type:           2,
			BlockNumber:    &blockNumber,
			Receipt: &doctor.TransactionReceiptSnapshot{
				Status:      0,
				GasUsed:     31_000,
				BlockNumber: blockNumber,
			},
			Replay: doctor.ReplaySnapshot{
				Status:      doctor.ReplayStatusReverted,
				BlockNumber: blockNumber - 1,
				RevertData:  selector,
			},
		}, nil
	})

	report, err := doctor.New(
		arcNetworkProbe(),
		doctor.WithTransactionProbe(transaction),
	).Diagnose(context.Background(), doctor.Request{
		Kind:   doctor.TransactionCheck,
		Target: hash,
		ABIs: []doctor.ABIInput{
			{
				Name: "SealedBidAuction.json",
				Data: []byte(`[
					{"type":"error","name":"InvalidAuctionData","inputs":[]}
				]`),
			},
		},
	})
	if err != nil {
		t.Fatalf("Diagnose() error = %v", err)
	}
	if report.Transaction == nil || report.Transaction.Revert == nil {
		t.Fatalf("Transaction revert evidence is missing: %#v", report.Transaction)
	}
	if report.Transaction.Revert.Kind != doctor.RevertKindCustom {
		t.Errorf(
			"Revert.Kind = %q, want %q",
			report.Transaction.Revert.Kind,
			doctor.RevertKindCustom,
		)
	}
	if report.Transaction.Revert.Signature != "InvalidAuctionData()" {
		t.Errorf(
			"Revert.Signature = %q, want InvalidAuctionData()",
			report.Transaction.Revert.Signature,
		)
	}
	if !hasFinding(report, "ARC-TX-009") {
		t.Fatalf("Findings = %#v, want ARC-TX-009", report.Findings)
	}
	if !report.HasErrors() {
		t.Fatal("HasErrors() = false for reverted transaction")
	}
}

func TestDiagnoseTransactionReportsUnavailableReplay(t *testing.T) {
	t.Parallel()

	const hash = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	blockNumber := uint64(53_204_880)
	transaction := transactionProbeFunc(func(
		context.Context,
		string,
	) (doctor.TransactionSnapshot, error) {
		return doctor.TransactionSnapshot{
			Found:          true,
			ValueBaseUnits: big.NewInt(0),
			BlockNumber:    &blockNumber,
			Receipt: &doctor.TransactionReceiptSnapshot{
				Status:      0,
				BlockNumber: blockNumber,
			},
			Replay: doctor.ReplaySnapshot{
				Status: doctor.ReplayStatusUnavailable,
				Detail: "historical state unavailable",
			},
		}, nil
	})

	report, err := doctor.New(
		arcNetworkProbe(),
		doctor.WithTransactionProbe(transaction),
	).Diagnose(context.Background(), doctor.Request{
		Kind:   doctor.TransactionCheck,
		Target: hash,
	})
	if err != nil {
		t.Fatalf("Diagnose() error = %v", err)
	}
	if !hasFinding(report, "ARC-RPC-001") {
		t.Fatalf("Findings = %#v, want ARC-RPC-001", report.Findings)
	}
}

func TestDiagnoseTransactionDistinguishesMissingAndPending(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		snapshot doctor.TransactionSnapshot
		state    doctor.TransactionState
		code     string
	}{
		{
			name:     "missing",
			snapshot: doctor.TransactionSnapshot{Found: false},
			state:    doctor.TransactionStateMissing,
			code:     "ARC-TX-002",
		},
		{
			name: "pending",
			snapshot: doctor.TransactionSnapshot{
				Found:          true,
				ValueBaseUnits: big.NewInt(0),
			},
			state: doctor.TransactionStatePending,
			code:  "ARC-TX-003",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			transaction := transactionProbeFunc(func(
				context.Context,
				string,
			) (doctor.TransactionSnapshot, error) {
				return test.snapshot, nil
			})
			report, err := doctor.New(
				arcNetworkProbe(),
				doctor.WithTransactionProbe(transaction),
			).Diagnose(context.Background(), doctor.Request{
				Kind:   doctor.TransactionCheck,
				Target: "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
			})
			if err != nil {
				t.Fatalf("Diagnose() error = %v", err)
			}
			if report.Transaction == nil || report.Transaction.State != test.state {
				t.Fatalf("Transaction = %#v, want state %q", report.Transaction, test.state)
			}
			if !hasFinding(report, test.code) {
				t.Fatalf("Findings = %#v, want %s", report.Findings, test.code)
			}
		})
	}
}

func TestDiagnoseTransactionDecodesStandardSolidityReverts(t *testing.T) {
	t.Parallel()

	stringType, err := abi.NewType("string", "", nil)
	if err != nil {
		t.Fatalf("create string ABI type: %v", err)
	}
	uintType, err := abi.NewType("uint256", "", nil)
	if err != nil {
		t.Fatalf("create uint ABI type: %v", err)
	}
	errorPayload, err := (abi.Arguments{{Type: stringType}}).Pack("auction closed")
	if err != nil {
		t.Fatalf("pack Error(string): %v", err)
	}
	panicPayload, err := (abi.Arguments{{Type: uintType}}).Pack(big.NewInt(0x11))
	if err != nil {
		t.Fatalf("pack Panic(uint256): %v", err)
	}

	tests := []struct {
		name      string
		data      []byte
		kind      doctor.RevertKind
		code      string
		signature string
	}{
		{
			name:      "error string",
			data:      append([]byte{0x08, 0xc3, 0x79, 0xa0}, errorPayload...),
			kind:      doctor.RevertKindError,
			code:      "ARC-TX-007",
			signature: "Error(string)",
		},
		{
			name:      "panic",
			data:      append([]byte{0x4e, 0x48, 0x7b, 0x71}, panicPayload...),
			kind:      doctor.RevertKindPanic,
			code:      "ARC-TX-008",
			signature: "Panic(uint256)",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			blockNumber := uint64(100)
			transaction := transactionProbeFunc(func(
				context.Context,
				string,
			) (doctor.TransactionSnapshot, error) {
				return doctor.TransactionSnapshot{
					Found:          true,
					ValueBaseUnits: big.NewInt(0),
					BlockNumber:    &blockNumber,
					Receipt: &doctor.TransactionReceiptSnapshot{
						Status:      0,
						BlockNumber: blockNumber,
					},
					Replay: doctor.ReplaySnapshot{
						Status:      doctor.ReplayStatusReverted,
						BlockNumber: blockNumber - 1,
						RevertData:  test.data,
					},
				}, nil
			})
			report, diagnoseErr := doctor.New(
				arcNetworkProbe(),
				doctor.WithTransactionProbe(transaction),
			).Diagnose(context.Background(), doctor.Request{
				Kind:   doctor.TransactionCheck,
				Target: "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
			})
			if diagnoseErr != nil {
				t.Fatalf("Diagnose() error = %v", diagnoseErr)
			}
			if report.Transaction == nil || report.Transaction.Revert == nil {
				t.Fatalf("Revert evidence is missing: %#v", report.Transaction)
			}
			if report.Transaction.Revert.Kind != test.kind {
				t.Errorf("Revert.Kind = %q, want %q", report.Transaction.Revert.Kind, test.kind)
			}
			if report.Transaction.Revert.Signature != test.signature {
				t.Errorf(
					"Revert.Signature = %q, want %q",
					report.Transaction.Revert.Signature,
					test.signature,
				)
			}
			if !hasFinding(report, test.code) {
				t.Fatalf("Findings = %#v, want %s", report.Findings, test.code)
			}
		})
	}
}

func hasFinding(report doctor.Report, code string) bool {
	for _, finding := range report.Findings {
		if finding.Code == code {
			return true
		}
	}
	return false
}

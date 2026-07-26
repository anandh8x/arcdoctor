package doctor_test

import (
	"context"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/anandh8x/arcdoctor/internal/doctor"
)

type networkProbeFunc func(context.Context) (doctor.NetworkSnapshot, error)

func (f networkProbeFunc) NetworkSnapshot(ctx context.Context) (doctor.NetworkSnapshot, error) {
	return f(ctx)
}

type addressProbeFunc func(context.Context, string) (doctor.AddressSnapshot, error)

func (f addressProbeFunc) AddressSnapshot(
	ctx context.Context,
	address string,
) (doctor.AddressSnapshot, error) {
	return f(ctx, address)
}

func TestDiagnoseConfirmsArcTestnet(t *testing.T) {
	t.Parallel()

	probe := networkProbeFunc(func(context.Context) (doctor.NetworkSnapshot, error) {
		return doctor.NetworkSnapshot{
			ChainID:        5_042_002,
			BlockNumber:    54_201_392,
			BlockTimestamp: time.Date(2026, time.July, 26, 12, 0, 0, 0, time.UTC),
			Latency:        42 * time.Millisecond,
		}, nil
	})

	report, err := doctor.New(probe).Diagnose(context.Background(), doctor.Request{
		Kind: doctor.NetworkCheck,
	})
	if err != nil {
		t.Fatalf("Diagnose() error = %v", err)
	}

	if report.Network.ObservedChainID != 5_042_002 {
		t.Fatalf("ObservedChainID = %d, want 5042002", report.Network.ObservedChainID)
	}
	if report.Network.LatencyMilliseconds != 42 {
		t.Fatalf("LatencyMilliseconds = %v, want 42", report.Network.LatencyMilliseconds)
	}
	if report.HasErrors() {
		t.Fatalf("HasErrors() = true, findings = %#v", report.Findings)
	}
	if len(report.Findings) != 1 {
		t.Fatalf("len(Findings) = %d, want 1", len(report.Findings))
	}

	finding := report.Findings[0]
	if finding.Code != "ARC-NET-000" {
		t.Errorf("finding.Code = %q, want ARC-NET-000", finding.Code)
	}
	if finding.Severity != doctor.SeverityInfo {
		t.Errorf("finding.Severity = %q, want %q", finding.Severity, doctor.SeverityInfo)
	}
	if finding.Confidence != doctor.ConfidenceCertain {
		t.Errorf("finding.Confidence = %q, want %q", finding.Confidence, doctor.ConfidenceCertain)
	}
}

func TestDiagnoseRejectsUnexpectedChain(t *testing.T) {
	t.Parallel()

	probe := networkProbeFunc(func(context.Context) (doctor.NetworkSnapshot, error) {
		return doctor.NetworkSnapshot{
			ChainID:        31_337,
			BlockNumber:    12,
			BlockTimestamp: time.Date(2026, time.July, 26, 12, 0, 0, 0, time.UTC),
			Latency:        3 * time.Millisecond,
		}, nil
	})

	report, err := doctor.New(probe).Diagnose(context.Background(), doctor.Request{
		Kind: doctor.NetworkCheck,
	})
	if err != nil {
		t.Fatalf("Diagnose() error = %v", err)
	}

	if !report.HasErrors() {
		t.Fatalf("HasErrors() = false, findings = %#v", report.Findings)
	}
	if len(report.Findings) != 1 {
		t.Fatalf("len(Findings) = %d, want 1", len(report.Findings))
	}

	finding := report.Findings[0]
	if finding.Code != "ARC-NET-002" {
		t.Errorf("finding.Code = %q, want ARC-NET-002", finding.Code)
	}
	if finding.Severity != doctor.SeverityError {
		t.Errorf("finding.Severity = %q, want %q", finding.Severity, doctor.SeverityError)
	}
	if finding.Confidence != doctor.ConfidenceCertain {
		t.Errorf("finding.Confidence = %q, want %q", finding.Confidence, doctor.ConfidenceCertain)
	}
	if len(finding.SuggestedActions) == 0 {
		t.Error("finding.SuggestedActions is empty")
	}
}

func TestDiagnosePreservesRPCFailureAsOperationalError(t *testing.T) {
	t.Parallel()

	rpcFailure := errors.New("connection refused")
	probe := networkProbeFunc(func(context.Context) (doctor.NetworkSnapshot, error) {
		return doctor.NetworkSnapshot{}, rpcFailure
	})

	report, err := doctor.New(probe).Diagnose(context.Background(), doctor.Request{
		Kind: doctor.NetworkCheck,
	})

	if !errors.Is(err, rpcFailure) {
		t.Fatalf("Diagnose() error = %v, want wrapped RPC failure", err)
	}
	if len(report.Findings) != 0 {
		t.Fatalf("len(Findings) = %d, want 0 for incomplete diagnosis", len(report.Findings))
	}
}

func TestDiagnoseAddressRejectsMalformedTargetBeforeRPC(t *testing.T) {
	t.Parallel()

	networkCalled := false
	probe := networkProbeFunc(func(context.Context) (doctor.NetworkSnapshot, error) {
		networkCalled = true
		return doctor.NetworkSnapshot{}, nil
	})

	report, err := doctor.New(probe).Diagnose(context.Background(), doctor.Request{
		Kind:   doctor.AddressCheck,
		Target: "not-an-address",
	})
	if err != nil {
		t.Fatalf("Diagnose() error = %v", err)
	}
	if networkCalled {
		t.Fatal("network probe was called for malformed address")
	}
	if !report.HasErrors() {
		t.Fatalf("HasErrors() = false, findings = %#v", report.Findings)
	}
	if len(report.Findings) != 1 {
		t.Fatalf("len(Findings) = %d, want 1", len(report.Findings))
	}
	if report.Findings[0].Code != "ARC-ADR-001" {
		t.Errorf("finding.Code = %q, want ARC-ADR-001", report.Findings[0].Code)
	}
	if report.Findings[0].Confidence != doctor.ConfidenceCertain {
		t.Errorf(
			"finding.Confidence = %q, want %q",
			report.Findings[0].Confidence,
			doctor.ConfidenceCertain,
		)
	}
}

func TestDiagnoseAddressIdentifiesDeployedContract(t *testing.T) {
	t.Parallel()

	network := networkProbeFunc(func(context.Context) (doctor.NetworkSnapshot, error) {
		return doctor.NetworkSnapshot{
			ChainID:        doctor.ArcTestnetChainID,
			BlockNumber:    54_201_392,
			BlockTimestamp: time.Date(2026, time.July, 26, 12, 0, 0, 0, time.UTC),
			Latency:        42 * time.Millisecond,
		}, nil
	})
	address := addressProbeFunc(func(
		_ context.Context,
		gotAddress string,
	) (doctor.AddressSnapshot, error) {
		const wantAddress = "0xCe084c9358FBC5200415012885c2F0F0906d400C"
		if gotAddress != wantAddress {
			t.Errorf("AddressSnapshot() address = %q, want %q", gotAddress, wantAddress)
		}
		return doctor.AddressSnapshot{
			BalanceBaseUnits: big.NewInt(2_000_000_000_000_000_000),
			Nonce:            1,
			Code:             []byte{0x60, 0x00, 0x60, 0x00},
		}, nil
	})

	report, err := doctor.New(
		network,
		doctor.WithAddressProbe(address),
	).Diagnose(context.Background(), doctor.Request{
		Kind:   doctor.AddressCheck,
		Target: "0xce084c9358fbc5200415012885c2f0f0906d400c",
	})
	if err != nil {
		t.Fatalf("Diagnose() error = %v", err)
	}
	if report.HasErrors() {
		t.Fatalf("HasErrors() = true, findings = %#v", report.Findings)
	}
	if report.Address == nil {
		t.Fatal("Address evidence is nil")
	}
	if report.Address.Kind != doctor.AddressKindContract {
		t.Errorf("Address.Kind = %q, want %q", report.Address.Kind, doctor.AddressKindContract)
	}
	if report.Address.CodeSize != 4 {
		t.Errorf("Address.CodeSize = %d, want 4", report.Address.CodeSize)
	}
	if report.Address.CodeHash == "" {
		t.Error("Address.CodeHash is empty")
	}
	if report.Address.BalanceBaseUnits != "2000000000000000000" {
		t.Errorf(
			"Address.BalanceBaseUnits = %q, want 2000000000000000000",
			report.Address.BalanceBaseUnits,
		)
	}
	if report.Address.ExplorerURL !=
		"https://testnet.arcscan.app/address/0xCe084c9358FBC5200415012885c2F0F0906d400C" {
		t.Errorf("Address.ExplorerURL = %q", report.Address.ExplorerURL)
	}
	if len(report.Findings) != 2 {
		t.Fatalf("len(Findings) = %d, want network and address findings", len(report.Findings))
	}
	if report.Findings[1].Code != "ARC-ADR-000" {
		t.Errorf("address finding code = %q, want ARC-ADR-000", report.Findings[1].Code)
	}
}

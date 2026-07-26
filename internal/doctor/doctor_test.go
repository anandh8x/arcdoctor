package doctor_test

import (
	"context"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/anandh8x/arcdoctor/internal/doctor"
	"github.com/ethereum/go-ethereum/common"
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

func TestDiagnoseAddsVersionedSanitizedReportMetadata(t *testing.T) {
	t.Parallel()

	collectedAt := time.Date(2026, time.July, 26, 15, 30, 0, 0, time.UTC)
	probe := networkProbeFunc(func(context.Context) (doctor.NetworkSnapshot, error) {
		return doctor.NetworkSnapshot{
			ChainID:        doctor.ArcTestnetChainID,
			BlockNumber:    54_201_392,
			BlockTimestamp: collectedAt.Add(-time.Second),
			ObservedAt:     collectedAt,
			Latency:        42 * time.Millisecond,
		}, nil
	})

	report, err := doctor.New(
		probe,
		doctor.WithClock(func() time.Time { return collectedAt }),
	).Diagnose(context.Background(), doctor.Request{
		Kind: doctor.NetworkCheck,
	})
	if err != nil {
		t.Fatalf("Diagnose() error = %v", err)
	}
	if report.SchemaVersion != 1 {
		t.Errorf("SchemaVersion = %d, want 1", report.SchemaVersion)
	}
	if !report.CollectedAt.Equal(collectedAt) {
		t.Errorf("CollectedAt = %s, want %s", report.CollectedAt, collectedAt)
	}
	if !report.Sanitized {
		t.Error("Sanitized = false, want true")
	}
	if report.Tool.Name != "Arc Doctor" ||
		report.Tool.Version == "" ||
		report.Tool.RulesetVersion == "" {
		t.Errorf("Tool = %#v, want complete metadata", report.Tool)
	}
	for _, finding := range report.Findings {
		if finding.RuleVersion == "" {
			t.Errorf("finding %s has no rule version", finding.Code)
		}
	}
}

func TestDiagnoseSanitizesFindingEvidenceBeforeSerialization(t *testing.T) {
	t.Parallel()

	privateKey := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	report, err := doctor.New(
		networkProbeFunc(func(context.Context) (doctor.NetworkSnapshot, error) {
			t.Fatal("network probe should not be called")
			return doctor.NetworkSnapshot{}, nil
		}),
	).Diagnose(context.Background(), doctor.Request{
		Kind:   doctor.AddressCheck,
		Target: "private_key=" + privateKey + "\x1b[31m",
	})
	if err != nil {
		t.Fatalf("Diagnose() error = %v", err)
	}
	if len(report.Findings) != 1 {
		t.Fatalf("len(Findings) = %d, want 1", len(report.Findings))
	}
	evidence := strings.Join(report.Findings[0].Evidence, "\n")
	if strings.Contains(evidence, privateKey) || strings.Contains(evidence, "\x1b") {
		t.Errorf("finding evidence was not sanitized: %s", evidence)
	}
	if !strings.Contains(evidence, "[REDACTED]") {
		t.Errorf("finding evidence has no redaction marker: %s", evidence)
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

func TestDiagnoseWarnsWhenLatestArcBlockIsStale(t *testing.T) {
	t.Parallel()

	observedAt := time.Date(2026, time.July, 26, 12, 5, 0, 0, time.UTC)
	probe := networkProbeFunc(func(context.Context) (doctor.NetworkSnapshot, error) {
		return doctor.NetworkSnapshot{
			ChainID:        doctor.ArcTestnetChainID,
			BlockNumber:    54_201_392,
			BlockTimestamp: observedAt.Add(-3 * time.Minute),
			ObservedAt:     observedAt,
			Latency:        42 * time.Millisecond,
		}, nil
	})

	report, err := doctor.New(probe).Diagnose(context.Background(), doctor.Request{
		Kind: doctor.NetworkCheck,
	})
	if err != nil {
		t.Fatalf("Diagnose() error = %v", err)
	}
	if len(report.Findings) != 2 {
		t.Fatalf("len(Findings) = %d, want network and stale findings", len(report.Findings))
	}
	if report.Findings[1].Code != "ARC-NET-003" {
		t.Errorf("stale finding code = %q, want ARC-NET-003", report.Findings[1].Code)
	}
	if report.Findings[1].Severity != doctor.SeverityWarning {
		t.Errorf(
			"stale finding severity = %q, want %q",
			report.Findings[1].Severity,
			doctor.SeverityWarning,
		)
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

func TestDiagnoseEnvironmentCollectsOptionalWalletEvidence(t *testing.T) {
	t.Parallel()

	const wallet = "0x99066fBc97557490fA794F750630bb41733D1004"
	address := addressProbeFunc(func(
		_ context.Context,
		got string,
	) (doctor.AddressSnapshot, error) {
		if got != wallet {
			t.Fatalf("wallet address = %q, want %q", got, wallet)
		}
		return doctor.AddressSnapshot{
			BalanceBaseUnits: big.NewInt(42),
			Nonce:            7,
		}, nil
	})

	report, err := doctor.New(
		arcNetworkProbe(),
		doctor.WithAddressProbe(address),
	).Diagnose(context.Background(), doctor.Request{
		Kind:          doctor.NetworkCheck,
		WalletAddress: wallet,
	})
	if err != nil {
		t.Fatalf("Diagnose() error = %v", err)
	}
	if report.Address == nil {
		t.Fatal("Address evidence is nil")
	}
	if report.Address.BalanceBaseUnits != "42" || report.Address.Nonce != 7 {
		t.Errorf("Address = %#v, want wallet balance and nonce", report.Address)
	}
	if !hasFinding(report, "ARC-WAL-000") {
		t.Fatalf("Findings = %#v, want ARC-WAL-000", report.Findings)
	}
}

func TestDiagnoseEnvironmentReportsMalformedOptionalWalletAfterNetworkCheck(t *testing.T) {
	t.Parallel()

	report, err := doctor.New(arcNetworkProbe()).Diagnose(
		context.Background(),
		doctor.Request{
			Kind:          doctor.NetworkCheck,
			WalletAddress: "not-an-address",
		},
	)
	if err != nil {
		t.Fatalf("Diagnose() error = %v", err)
	}
	if report.Network.ObservedChainID != doctor.ArcTestnetChainID {
		t.Fatalf("network evidence was not collected: %#v", report.Network)
	}
	if !hasFinding(report, "ARC-WAL-001") {
		t.Fatalf("Findings = %#v, want ARC-WAL-001", report.Findings)
	}
}

func TestDiagnoseAddressDetectsEIP1167MinimalProxy(t *testing.T) {
	t.Parallel()

	const (
		proxyAddress          = "0x1111111111111111111111111111111111111111"
		implementationAddress = "0x2222222222222222222222222222222222222222"
	)
	code, err := hex.DecodeString(
		"363d3d373d3d3d363d73" +
			strings.TrimPrefix(implementationAddress, "0x") +
			"5af43d82803e903d91602b57fd5bf3",
	)
	if err != nil {
		t.Fatalf("decode minimal proxy fixture: %v", err)
	}
	address := addressProbeFunc(func(
		context.Context,
		string,
	) (doctor.AddressSnapshot, error) {
		return doctor.AddressSnapshot{
			BalanceBaseUnits: big.NewInt(0),
			Code:             code,
		}, nil
	})

	report, err := doctor.New(
		arcNetworkProbe(),
		doctor.WithAddressProbe(address),
	).Diagnose(context.Background(), doctor.Request{
		Kind:   doctor.AddressCheck,
		Target: proxyAddress,
	})
	if err != nil {
		t.Fatalf("Diagnose() error = %v", err)
	}
	if report.Address == nil || report.Address.Proxy == nil {
		t.Fatalf("Address = %#v, want proxy evidence", report.Address)
	}
	if report.Address.Proxy.Standard != doctor.ProxyStandardEIP1167 ||
		report.Address.Proxy.Implementation != implementationAddress {
		t.Errorf("Proxy = %#v, want EIP-1167 implementation", report.Address.Proxy)
	}
	if report.Address.Proxy.Confidence != doctor.ConfidenceCertain {
		t.Errorf(
			"Proxy confidence = %q, want certain",
			report.Address.Proxy.Confidence,
		)
	}
	if !hasFinding(report, "ARC-ADR-003") {
		t.Fatalf("Findings = %#v, want ARC-ADR-003", report.Findings)
	}
}

func TestDiagnoseAddressDetectsEIP1967ImplementationSlot(t *testing.T) {
	t.Parallel()

	const (
		proxyAddress          = "0x1111111111111111111111111111111111111111"
		implementationAddress = "0x2222222222222222222222222222222222222222"
	)
	slot := make([]byte, 32)
	copy(slot[12:], common.HexToAddress(implementationAddress).Bytes())
	address := addressProbeFunc(func(
		context.Context,
		string,
	) (doctor.AddressSnapshot, error) {
		return doctor.AddressSnapshot{
			BalanceBaseUnits:      big.NewInt(0),
			Code:                  []byte{0x60, 0x00},
			EIP1967Implementation: slot,
		}, nil
	})

	report, err := doctor.New(
		arcNetworkProbe(),
		doctor.WithAddressProbe(address),
	).Diagnose(context.Background(), doctor.Request{
		Kind:   doctor.AddressCheck,
		Target: proxyAddress,
	})
	if err != nil {
		t.Fatalf("Diagnose() error = %v", err)
	}
	if report.Address == nil || report.Address.Proxy == nil {
		t.Fatalf("Address = %#v, want proxy evidence", report.Address)
	}
	if report.Address.Proxy.Standard != doctor.ProxyStandardEIP1967 ||
		report.Address.Proxy.Implementation != implementationAddress {
		t.Errorf("Proxy = %#v, want EIP-1967 implementation", report.Address.Proxy)
	}
	if !hasFinding(report, "ARC-ADR-004") {
		t.Fatalf("Findings = %#v, want ARC-ADR-004", report.Findings)
	}
}

func TestDiagnoseAddressDistinguishesUnsupportedProxyStorageMethod(t *testing.T) {
	t.Parallel()

	address := addressProbeFunc(func(
		context.Context,
		string,
	) (doctor.AddressSnapshot, error) {
		return doctor.AddressSnapshot{
			BalanceBaseUnits:        big.NewInt(0),
			Code:                    []byte{0x60, 0x00},
			ProxyStorageUnsupported: true,
			ProxyStorageError:       "method not found",
		}, nil
	})
	report, err := doctor.New(
		arcNetworkProbe(),
		doctor.WithAddressProbe(address),
	).Diagnose(context.Background(), doctor.Request{
		Kind:   doctor.AddressCheck,
		Target: "0x1111111111111111111111111111111111111111",
	})
	if err != nil {
		t.Fatalf("Diagnose() error = %v", err)
	}
	if !hasFinding(report, "ARC-RPC-002") {
		t.Fatalf("Findings = %#v, want ARC-RPC-002", report.Findings)
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

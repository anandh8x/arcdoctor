package doctor_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/anandh8x/arcdoctor/internal/doctor"
)

type networkProbeFunc func(context.Context) (doctor.NetworkSnapshot, error)

func (f networkProbeFunc) NetworkSnapshot(ctx context.Context) (doctor.NetworkSnapshot, error) {
	return f(ctx)
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

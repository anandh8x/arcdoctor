package cli_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/anandh8x/arcdoctor/internal/cli"
	"github.com/anandh8x/arcdoctor/internal/doctor"
)

type diagnoserFunc func(context.Context, doctor.Request) (doctor.Report, error)

func (f diagnoserFunc) Diagnose(
	ctx context.Context,
	request doctor.Request,
) (doctor.Report, error) {
	return f(ctx, request)
}

func healthyFactory() cli.DiagnoserFactory {
	return func(string) cli.Diagnoser {
		return diagnoserFunc(func(context.Context, doctor.Request) (doctor.Report, error) {
			return doctor.Report{
				Network: doctor.NetworkEvidence{
					ExpectedChainID:     5_042_002,
					ObservedChainID:     5_042_002,
					BlockNumber:         54_201_392,
					BlockTimestamp:      time.Date(2026, time.July, 26, 12, 0, 0, 0, time.UTC),
					Latency:             42 * time.Millisecond,
					LatencyMilliseconds: 42,
				},
				Findings: []doctor.Finding{
					{
						Code:       "ARC-NET-000",
						Severity:   doctor.SeverityInfo,
						Confidence: doctor.ConfidenceCertain,
						Title:      "Arc Testnet connection confirmed",
					},
				},
			}, nil
		})
	}
}

func TestCheckWritesMachineReadableJSON(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command := cli.NewRootCommand(healthyFactory())
	command.SetOut(&stdout)
	command.SetErr(&stderr)
	command.SetArgs([]string{"check", "--json"})

	if err := command.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("ExecuteContext() error = %v, stderr = %q", err, stderr.String())
	}

	var report doctor.Report
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("decode JSON output: %v\noutput: %s", err, stdout.String())
	}
	if report.Network.ObservedChainID != 5_042_002 {
		t.Errorf("ObservedChainID = %d, want 5042002", report.Network.ObservedChainID)
	}
	if report.Network.LatencyMilliseconds != 42 {
		t.Errorf("LatencyMilliseconds = %v, want 42", report.Network.LatencyMilliseconds)
	}
	if len(report.Findings) != 1 || report.Findings[0].Code != "ARC-NET-000" {
		t.Errorf("Findings = %#v, want ARC-NET-000", report.Findings)
	}
	if stderr.Len() != 0 {
		t.Errorf("stderr = %q, want empty", stderr.String())
	}
}

func TestCheckWritesReadableTerminalReport(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command := cli.NewRootCommand(healthyFactory())
	command.SetOut(&stdout)
	command.SetErr(&stderr)
	command.SetArgs([]string{"check"})

	if err := command.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("ExecuteContext() error = %v, stderr = %q", err, stderr.String())
	}

	for _, expected := range []string{
		"Arc Testnet",
		"5042002",
		"54201392",
		"ARC-NET-000",
		"Arc Testnet connection confirmed",
	} {
		if !strings.Contains(stdout.String(), expected) {
			t.Errorf("terminal output does not contain %q\noutput:\n%s", expected, stdout.String())
		}
	}
	if stderr.Len() != 0 {
		t.Errorf("stderr = %q, want empty", stderr.String())
	}
}

func TestCheckReturnsDiagnosticExitAfterWritingErrorFinding(t *testing.T) {
	t.Parallel()

	factory := func(string) cli.Diagnoser {
		return diagnoserFunc(func(context.Context, doctor.Request) (doctor.Report, error) {
			return doctor.Report{
				Network: doctor.NetworkEvidence{
					ExpectedChainID: 5_042_002,
					ObservedChainID: 31_337,
				},
				Findings: []doctor.Finding{
					{
						Code:       "ARC-NET-002",
						Severity:   doctor.SeverityError,
						Confidence: doctor.ConfidenceCertain,
						Title:      "RPC is connected to the wrong network",
					},
				},
			}, nil
		})
	}

	var stdout bytes.Buffer
	command := cli.NewRootCommand(factory)
	command.SetOut(&stdout)
	command.SetArgs([]string{"check"})

	err := command.ExecuteContext(context.Background())
	if !errors.Is(err, cli.ErrDiagnosticFindings) {
		t.Fatalf("ExecuteContext() error = %v, want ErrDiagnosticFindings", err)
	}
	if !strings.Contains(stdout.String(), "ARC-NET-002") {
		t.Errorf("terminal output does not contain finding\noutput:\n%s", stdout.String())
	}
}

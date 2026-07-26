package cli_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
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

func TestCheckForwardsOptionalWalletAddress(t *testing.T) {
	t.Parallel()

	const wallet = "0x99066fBc97557490fA794F750630bb41733D1004"
	factory := func(string) cli.Diagnoser {
		return diagnoserFunc(func(
			_ context.Context,
			request doctor.Request,
		) (doctor.Report, error) {
			if request.Kind != doctor.NetworkCheck {
				t.Errorf("request.Kind = %q, want network", request.Kind)
			}
			if request.WalletAddress != wallet {
				t.Errorf(
					"request.WalletAddress = %q, want %q",
					request.WalletAddress,
					wallet,
				)
			}
			return doctor.Report{
				Findings: []doctor.Finding{
					{
						Code:       "ARC-NET-000",
						Severity:   doctor.SeverityInfo,
						Confidence: doctor.ConfidenceCertain,
					},
				},
			}, nil
		})
	}

	command := cli.NewRootCommand(factory)
	command.SetOut(&bytes.Buffer{})
	command.SetArgs([]string{"check", "--address", wallet})
	if err := command.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("ExecuteContext() error = %v", err)
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

func TestInspectAddressWritesJSONReport(t *testing.T) {
	t.Parallel()

	const target = "0xCe084c9358FBC5200415012885c2F0F0906d400C"
	factory := func(string) cli.Diagnoser {
		return diagnoserFunc(func(
			_ context.Context,
			request doctor.Request,
		) (doctor.Report, error) {
			if request.Kind != doctor.AddressCheck {
				t.Errorf("request.Kind = %q, want %q", request.Kind, doctor.AddressCheck)
			}
			if request.Target != target {
				t.Errorf("request.Target = %q, want %q", request.Target, target)
			}
			return doctor.Report{
				Address: &doctor.AddressEvidence{
					Address:          target,
					Kind:             doctor.AddressKindContract,
					BalanceBaseUnits: "2000000000000000000",
					Nonce:            1,
					CodeSize:         4,
					CodeHash:         "0xabc",
					ExplorerURL:      "https://testnet.arcscan.app/address/" + target,
				},
				Findings: []doctor.Finding{
					{
						Code:       "ARC-ADR-000",
						Severity:   doctor.SeverityInfo,
						Confidence: doctor.ConfidenceCertain,
						Title:      "Contract bytecode found",
					},
				},
			}, nil
		})
	}

	var stdout bytes.Buffer
	command := cli.NewRootCommand(factory)
	command.SetOut(&stdout)
	command.SetArgs([]string{"inspect", target, "--json"})

	if err := command.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("ExecuteContext() error = %v", err)
	}

	var report doctor.Report
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("decode JSON output: %v\noutput: %s", err, stdout.String())
	}
	if report.Address == nil {
		t.Fatal("Address report is nil")
	}
	if report.Address.Kind != doctor.AddressKindContract {
		t.Errorf("Address.Kind = %q, want %q", report.Address.Kind, doctor.AddressKindContract)
	}
}

func TestInspectTransactionLoadsABIAndWritesJSONReport(t *testing.T) {
	t.Parallel()

	const target = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	abiPath := filepath.Join(t.TempDir(), "Auction.json")
	if err := os.WriteFile(
		abiPath,
		[]byte(`[{"type":"error","name":"InvalidAuctionData","inputs":[]}]`),
		0o600,
	); err != nil {
		t.Fatalf("write ABI fixture: %v", err)
	}

	factory := func(string) cli.Diagnoser {
		return diagnoserFunc(func(
			_ context.Context,
			request doctor.Request,
		) (doctor.Report, error) {
			if request.Kind != doctor.TransactionCheck {
				t.Errorf("request.Kind = %q, want %q", request.Kind, doctor.TransactionCheck)
			}
			if len(request.ABIs) != 1 {
				t.Fatalf("len(request.ABIs) = %d, want 1", len(request.ABIs))
			}
			if request.ABIs[0].Name != "Auction.json" {
				t.Errorf("ABI name = %q, want Auction.json", request.ABIs[0].Name)
			}
			return doctor.Report{
				Transaction: &doctor.TransactionEvidence{
					Hash:           target,
					State:          doctor.TransactionStateReverted,
					ValueBaseUnits: "0",
					InputData:      "0x",
					ExplorerURL:    "https://testnet.arcscan.app/tx/" + target,
				},
				Findings: []doctor.Finding{
					{
						Code:       "ARC-TX-004",
						Severity:   doctor.SeverityError,
						Confidence: doctor.ConfidenceCertain,
						Title:      "Transaction reverted",
					},
				},
			}, nil
		})
	}

	var stdout bytes.Buffer
	command := cli.NewRootCommand(factory)
	command.SetOut(&stdout)
	command.SetArgs([]string{"inspect", target, "--abi", abiPath, "--json"})

	err := command.ExecuteContext(context.Background())
	if !errors.Is(err, cli.ErrDiagnosticFindings) {
		t.Fatalf("ExecuteContext() error = %v, want ErrDiagnosticFindings", err)
	}

	var report doctor.Report
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("decode JSON output: %v\noutput: %s", err, stdout.String())
	}
	if report.Transaction == nil ||
		report.Transaction.State != doctor.TransactionStateReverted {
		t.Fatalf("Transaction = %#v, want reverted evidence", report.Transaction)
	}
}

func TestDeploymentCommandLoadsManifestAndArtifactOverrides(t *testing.T) {
	t.Parallel()

	manifestPath := filepath.Join(t.TempDir(), "arc-testnet.json")
	if err := os.WriteFile(
		manifestPath,
		[]byte(`{
			"schemaVersion": 1,
			"network": "Arc Testnet",
			"chainId": 5042002,
			"contracts": {
				"Counter": {
					"address": "0x1111111111111111111111111111111111111111"
				}
			}
		}`),
		0o600,
	); err != nil {
		t.Fatalf("write manifest fixture: %v", err)
	}

	factory := func(string) cli.Diagnoser {
		return diagnoserFunc(func(
			_ context.Context,
			request doctor.Request,
		) (doctor.Report, error) {
			if request.Kind != doctor.DeploymentCheck {
				t.Errorf("request.Kind = %q, want %q", request.Kind, doctor.DeploymentCheck)
			}
			if request.Deployment == nil {
				t.Fatal("request.Deployment is nil")
			}
			if request.Deployment.Name != "arc-testnet.json" {
				t.Errorf(
					"Deployment.Name = %q, want arc-testnet.json",
					request.Deployment.Name,
				)
			}
			artifactPath := request.Deployment.Artifacts["Counter"]
			if !filepath.IsAbs(artifactPath) ||
				filepath.Base(artifactPath) != "Counter.json" {
				t.Errorf(
					"artifact override = %q, want absolute Counter.json path",
					artifactPath,
				)
			}
			return doctor.Report{
				Deployment: &doctor.DeploymentEvidence{
					ManifestName:  "arc-testnet.json",
					Format:        "arcdoctor",
					SchemaVersion: 1,
					Network:       "Arc Testnet",
					ChainID:       doctor.ArcTestnetChainID,
				},
				Findings: []doctor.Finding{
					{
						Code:       "ARC-DEP-000",
						Severity:   doctor.SeverityInfo,
						Confidence: doctor.ConfidenceCertain,
						Title:      "Deployment validation completed",
					},
				},
			}, nil
		})
	}

	var stdout bytes.Buffer
	command := cli.NewRootCommand(factory)
	command.SetOut(&stdout)
	command.SetArgs([]string{
		"deployment",
		manifestPath,
		"--artifact",
		"Counter=./out/Counter.json",
		"--json",
	})

	if err := command.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("ExecuteContext() error = %v", err)
	}
	var report doctor.Report
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("decode JSON output: %v\noutput: %s", err, stdout.String())
	}
	if report.Deployment == nil || report.Deployment.Format != "arcdoctor" {
		t.Fatalf("Deployment = %#v, want arcdoctor format", report.Deployment)
	}
}

func TestReportCommandSanitizesExistingJSONReport(t *testing.T) {
	t.Parallel()

	const transactionHash = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	const privateKey = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	inputPath := filepath.Join(t.TempDir(), "unsafe-report.json")
	input := doctor.Report{
		SchemaVersion: 1,
		CollectedAt:   time.Date(2026, time.July, 26, 12, 0, 0, 0, time.UTC),
		Sanitized:     false,
		Tool: doctor.ToolEvidence{
			Name:           "Arc Doctor",
			Version:        "dev",
			RulesetVersion: "1.0.0",
		},
		Transaction: &doctor.TransactionEvidence{
			Hash:           transactionHash,
			State:          doctor.TransactionStateReverted,
			ValueBaseUnits: "0",
			InputData:      "0x",
			ExplorerURL:    "https://testnet.arcscan.app/tx/" + transactionHash,
		},
		Findings: []doctor.Finding{
			{
				Code:        "ARC-TX-004",
				Severity:    doctor.SeverityError,
				Confidence:  doctor.ConfidenceCertain,
				Title:       "Transaction reverted",
				Explanation: "private_key=" + privateKey,
				Evidence: []string{
					"https://alice:password@rpc.example?token=secret",
				},
				RuleVersion: "1.0.0",
			},
		},
	}
	data, err := json.Marshal(input)
	if err != nil {
		t.Fatalf("marshal report fixture: %v", err)
	}
	if err := os.WriteFile(inputPath, data, 0o600); err != nil {
		t.Fatalf("write report fixture: %v", err)
	}

	var stdout bytes.Buffer
	command := cli.NewRootCommand(healthyFactory())
	command.SetOut(&stdout)
	command.SetArgs([]string{"report", inputPath})
	if err := command.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("ExecuteContext() error = %v", err)
	}

	var output doctor.Report
	if err := json.Unmarshal(stdout.Bytes(), &output); err != nil {
		t.Fatalf("decode report output: %v\noutput: %s", err, stdout.String())
	}
	if !output.Sanitized {
		t.Error("Sanitized = false, want true")
	}
	if strings.Contains(stdout.String(), privateKey) ||
		strings.Contains(stdout.String(), "alice") ||
		strings.Contains(stdout.String(), "password") ||
		strings.Contains(stdout.String(), "secret") {
		t.Errorf("output contains a secret:\n%s", stdout.String())
	}
	if output.Transaction == nil || output.Transaction.Hash != transactionHash {
		t.Errorf("public transaction hash was not preserved: %#v", output.Transaction)
	}
}

func TestReportCommandRejectsExcessiveJSONNesting(t *testing.T) {
	t.Parallel()

	inputPath := filepath.Join(t.TempDir(), "nested.json")
	input := []byte(strings.Repeat("[", 65) + strings.Repeat("]", 65))
	if err := os.WriteFile(inputPath, input, 0o600); err != nil {
		t.Fatalf("write nested fixture: %v", err)
	}

	command := cli.NewRootCommand(healthyFactory())
	command.SetOut(&bytes.Buffer{})
	command.SetArgs([]string{"report", inputPath})
	err := command.ExecuteContext(context.Background())
	if err == nil || !strings.Contains(err.Error(), "nesting depth exceeds") {
		t.Fatalf("ExecuteContext() error = %v, want nesting error", err)
	}
}

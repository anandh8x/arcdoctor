package tui

import (
	"context"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/anandh8x/arcdoctor/internal/doctor"
)

type diagnoserFunc func(context.Context, doctor.Request) (doctor.Report, error)

func (f diagnoserFunc) Diagnose(
	ctx context.Context,
	request doctor.Request,
) (doctor.Report, error) {
	return f(ctx, request)
}

func TestModelGuidesUserFromHomeToAddressForm(t *testing.T) {
	t.Parallel()

	model := NewModel(nil, nil, nil)
	if content := model.View().Content; !strings.Contains(content, "Environment check") ||
		!strings.Contains(content, "Transaction inspection") {
		t.Fatalf("home view is missing diagnosis choices:\n%s", content)
	}

	updated, _ := model.Update(keyMessage(tea.KeyDown, ""))
	model = updated.(Model)
	updated, _ = model.Update(keyMessage(tea.KeyEnter, ""))
	model = updated.(Model)

	if model.screen != formScreen {
		t.Fatalf("screen = %d, want formScreen", model.screen)
	}
	if model.selected.kind != doctor.AddressCheck {
		t.Errorf("selected kind = %q, want address", model.selected.kind)
	}
	if len(model.fields) != 2 ||
		model.fields[0].label != "Address" ||
		model.fields[1].label != "RPC URL" {
		t.Errorf("fields = %#v, want address and RPC", model.fields)
	}
}

func TestEnvironmentFormIncludesOptionalWalletAndBuildsEquivalentRequest(t *testing.T) {
	t.Parallel()

	const wallet = "0x99066fBc97557490fA794F750630bb41733D1004"
	model := NewModel(nil, nil, nil)
	model.selected = diagnosisChoices[0]
	model.configureForm()

	if len(model.fields) != 2 ||
		model.fields[0].label != "Wallet address" ||
		model.fields[1].label != "RPC URL" {
		t.Fatalf("fields = %#v, want optional wallet and RPC", model.fields)
	}
	model.fields[0].input.SetValue(wallet)

	request, rpcURL, err := model.buildRequest()
	if err != nil {
		t.Fatalf("buildRequest() error = %v", err)
	}
	if request.Kind != doctor.NetworkCheck || request.WalletAddress != wallet {
		t.Errorf("request = %#v, want network check with wallet", request)
	}
	if rpcURL != doctor.DefaultArcTestnetRPC {
		t.Errorf("RPC URL = %q, want default", rpcURL)
	}
}

func TestModelUsesDeterministicDiagnoserAndShowsFindings(t *testing.T) {
	t.Parallel()

	const target = "0xCe084c9358FBC5200415012885c2F0F0906d400C"
	collectedAt := time.Date(2026, time.July, 26, 12, 0, 0, 0, time.UTC)
	var received doctor.Request
	factory := func(rpcURL string) Diagnoser {
		if rpcURL != "https://rpc.testnet.arc.network" {
			t.Errorf("RPC URL = %q", rpcURL)
		}
		return diagnoserFunc(func(
			_ context.Context,
			request doctor.Request,
		) (doctor.Report, error) {
			received = request
			return doctor.Report{
				SchemaVersion: 1,
				CollectedAt:   collectedAt,
				Sanitized:     true,
				Tool: doctor.ToolEvidence{
					Name:           "Arc Doctor",
					Version:        "test",
					RulesetVersion: "1.0.0",
				},
				Address: &doctor.AddressEvidence{
					Address:          target,
					Kind:             doctor.AddressKindContract,
					BalanceBaseUnits: "0",
					CodeSize:         100,
				},
				Findings: []doctor.Finding{
					{
						Code:        "ARC-ADR-000",
						Severity:    doctor.SeverityInfo,
						Confidence:  doctor.ConfidenceCertain,
						Title:       "Contract bytecode found",
						Explanation: "Public bytecode exists.",
						Evidence:    []string{"Bytecode size: 100 bytes"},
						RuleVersion: "1.0.0",
					},
				},
			}, nil
		})
	}

	model := NewModel(factory, nil, nil)
	model.selected = diagnosisChoices[1]
	model.configureForm()
	model.fields[0].input.SetValue(target)

	request, rpcURL, err := model.buildRequest()
	if err != nil {
		t.Fatalf("buildRequest() error = %v", err)
	}
	message := diagnoseCommand(
		context.Background(),
		factory,
		rpcURL,
		request,
	)().(diagnosisMsg)
	updated, _ := model.Update(message)
	model = updated.(Model)

	if received.Kind != doctor.AddressCheck || received.Target != target {
		t.Errorf("received request = %#v", received)
	}
	if model.screen != resultScreen {
		t.Fatalf("screen = %d, want resultScreen", model.screen)
	}
	content := model.View().Content
	for _, expected := range []string{
		"ARC-ADR-000",
		"Contract bytecode found",
		"Bytecode size: 100 bytes",
	} {
		if !strings.Contains(content, expected) {
			t.Errorf("result view does not contain %q:\n%s", expected, content)
		}
	}
}

func TestModelHandlesNarrowTerminalAndExportStatus(t *testing.T) {
	t.Parallel()

	report := doctor.Report{
		SchemaVersion: 1,
		CollectedAt:   time.Date(2026, time.July, 26, 12, 0, 0, 0, time.UTC),
		Sanitized:     true,
		Tool: doctor.ToolEvidence{
			Name:           "Arc Doctor",
			Version:        "test",
			RulesetVersion: "1.0.0",
		},
	}
	exporter := func(got doctor.Report) (string, error) {
		if !got.Sanitized {
			t.Error("exported report is not sanitized")
		}
		return "arcdoctor-report.json", nil
	}
	model := NewModel(nil, nil, exporter)
	model.screen = resultScreen
	model.report = report
	model.viewport.SetContent("No findings")

	updated, _ := model.Update(tea.WindowSizeMsg{Width: 20, Height: 8})
	model = updated.(Model)
	if content := model.View().Content; !strings.Contains(content, "ARC DOCTOR") {
		t.Fatalf("narrow result view is invalid:\n%s", content)
	}

	updated, command := model.Update(keyMessage('e', "e"))
	model = updated.(Model)
	if command == nil {
		t.Fatal("export command is nil")
	}
	message := command().(exportMsg)
	updated, _ = model.Update(message)
	model = updated.(Model)
	if !strings.Contains(model.status, "Saved sanitized report") {
		t.Errorf("status = %q", model.status)
	}
}

func TestRunningScreenCancelsSharedContext(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	model := NewModel(nil, nil, nil)
	model.screen = runningScreen
	model.cancel = cancel

	updated, _ := model.Update(keyMessage(tea.KeyEscape, ""))
	model = updated.(Model)
	if ctx.Err() != context.Canceled {
		t.Fatalf("context error = %v, want canceled", ctx.Err())
	}
	if !strings.Contains(model.status, "Cancelling") {
		t.Errorf("status = %q, want cancellation progress", model.status)
	}
}

func TestResultScreenPreservesPartialEvidenceAfterCancellation(t *testing.T) {
	t.Parallel()

	partial := doctor.Report{
		SchemaVersion: 1,
		CollectedAt:   time.Date(2026, time.July, 26, 12, 0, 0, 0, time.UTC),
		Sanitized:     true,
		Tool: doctor.ToolEvidence{
			Name:           "Arc Doctor",
			Version:        "test",
			RulesetVersion: "1.0.0",
		},
		Network: doctor.NetworkEvidence{
			ExpectedChainID:     doctor.ArcTestnetChainID,
			ObservedChainID:     doctor.ArcTestnetChainID,
			BlockNumber:         123,
			LatencyMilliseconds: 12,
		},
		Findings: []doctor.Finding{
			{
				Code:        "ARC-NET-000",
				Severity:    doctor.SeverityInfo,
				Confidence:  doctor.ConfidenceCertain,
				Title:       "Partial public evidence",
				Explanation: "Evidence collected before cancellation.",
				Evidence:    []string{"Latest block: 123"},
				RuleVersion: "1.0.0",
			},
		},
	}
	model := NewModel(nil, nil, nil)
	updated, _ := model.Update(diagnosisMsg{
		report: partial,
		err:    context.Canceled,
	})
	model = updated.(Model)

	content := model.View().Content
	for _, expected := range []string{
		"could not complete every check",
		"observed chain 5042002",
		"Latest block: 123",
	} {
		if !strings.Contains(content, expected) {
			t.Errorf("result view does not contain %q:\n%s", expected, content)
		}
	}
}

func keyMessage(code rune, text string) tea.KeyPressMsg {
	return tea.KeyPressMsg(tea.Key{
		Code: code,
		Text: text,
	})
}

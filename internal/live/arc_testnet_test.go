//go:build live

package live_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/anandh8x/arcdoctor/internal/chain"
	"github.com/anandh8x/arcdoctor/internal/doctor"
)

type fixtures struct {
	SchemaVersion int `json:"schemaVersion"`
	Network       struct {
		Name    string `json:"name"`
		ChainID uint64 `json:"chainId"`
		RPCURL  string `json:"rpcUrl"`
	} `json:"network"`
	Wallet struct {
		Address string `json:"address"`
	} `json:"wallet"`
	Contracts map[string]struct {
		Address               string `json:"address"`
		DeploymentTransaction string `json:"deploymentTransaction"`
		RuntimeBytecodeHash   string `json:"runtimeBytecodeHash"`
	} `json:"contracts"`
	Transactions struct {
		SuccessfulInvoiceCreation string `json:"successfulInvoiceCreation"`
	} `json:"transactions"`
}

func TestPublicArcTestnetFixtures(t *testing.T) {
	if os.Getenv("ARCDOCTOR_LIVE") != "1" {
		t.Skip("set ARCDOCTOR_LIVE=1 to run public Arc Testnet checks")
	}

	fixture := loadFixtures(t)
	probe := chain.NewRPCProbe(fixture.Network.RPCURL)
	instance := doctor.New(
		probe,
		doctor.WithAddressProbe(probe),
		doctor.WithBytecodeProbe(probe),
		doctor.WithTransactionProbe(probe),
	)

	t.Run("network", func(t *testing.T) {
		report := diagnoseLive(t, instance, doctor.Request{Kind: doctor.NetworkCheck})
		if report.Network.ObservedChainID != fixture.Network.ChainID {
			t.Fatalf(
				"observed chain ID = %d, want %d",
				report.Network.ObservedChainID,
				fixture.Network.ChainID,
			)
		}
		if report.Network.BlockNumber == 0 {
			t.Fatal("latest Arc Testnet block number is zero")
		}
		if report.HasErrors() {
			t.Fatalf("network report contains errors: %#v", report.Findings)
		}
	})

	t.Run("wallet", func(t *testing.T) {
		report := diagnoseLive(t, instance, doctor.Request{
			Kind:   doctor.AddressCheck,
			Target: fixture.Wallet.Address,
		})
		if report.Address == nil {
			t.Fatal("wallet report has no address evidence")
		}
		if report.Address.Address != fixture.Wallet.Address {
			t.Fatalf(
				"wallet address = %q, want %q",
				report.Address.Address,
				fixture.Wallet.Address,
			)
		}
		if report.Address.CodeSize != 0 {
			t.Fatalf("wallet code size = %d, want 0", report.Address.CodeSize)
		}
	})

	for name, contract := range fixture.Contracts {
		contract := contract
		t.Run("contract/"+name, func(t *testing.T) {
			report := diagnoseLive(t, instance, doctor.Request{
				Kind:   doctor.AddressCheck,
				Target: contract.Address,
			})
			if report.Address == nil {
				t.Fatal("contract report has no address evidence")
			}
			if report.Address.CodeSize == 0 {
				t.Fatal("known deployed contract has no bytecode")
			}
			if !strings.EqualFold(
				report.Address.CodeHash,
				contract.RuntimeBytecodeHash,
			) {
				t.Fatalf(
					"runtime bytecode hash = %s, want %s",
					report.Address.CodeHash,
					contract.RuntimeBytecodeHash,
				)
			}
		})
	}

	t.Run("successful transaction", func(t *testing.T) {
		report := diagnoseLive(t, instance, doctor.Request{
			Kind:   doctor.TransactionCheck,
			Target: fixture.Transactions.SuccessfulInvoiceCreation,
		})
		if report.Transaction == nil {
			t.Fatal("transaction report has no transaction evidence")
		}
		if report.Transaction.State != doctor.TransactionStateSuccessful {
			t.Fatalf(
				"transaction state = %q, want %q",
				report.Transaction.State,
				doctor.TransactionStateSuccessful,
			)
		}
	})
}

func diagnoseLive(
	t *testing.T,
	instance *doctor.Doctor,
	request doctor.Request,
) doctor.Report {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	report, err := instance.Diagnose(ctx, request)
	if err == nil {
		if temporaryReportFailure(report) {
			t.Skip("Arc Testnet endpoint is temporarily unavailable")
		}
		return report
	}
	if temporaryEndpointError(err) {
		t.Skipf("Arc Testnet endpoint is temporarily unavailable: %v", err)
	}
	t.Fatalf("Diagnose() error = %v", err)
	return doctor.Report{}
}

func temporaryEndpointError(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, context.Canceled) {
		return true
	}
	return temporaryEndpointText(err.Error())
}

func temporaryReportFailure(report doctor.Report) bool {
	for _, finding := range report.Findings {
		if finding.Code != "ARC-NET-001" &&
			finding.Code != "ARC-RPC-005" {
			continue
		}
		text := finding.Explanation + " " + strings.Join(finding.Evidence, " ")
		if temporaryEndpointText(text) {
			return true
		}
	}
	return false
}

func temporaryEndpointText(value string) bool {
	message := strings.ToLower(value)
	for _, fragment := range []string{
		"connection refused",
		"connection reset",
		"connection timed out",
		"deadline exceeded",
		"network is unreachable",
		"no such host",
		"temporary failure",
		"tls handshake timeout",
		"unexpected eof",
		"status code 429",
		"status code 502",
		"status code 503",
		"status code 504",
		"rate limit",
		"request limit",
		"too many requests",
	} {
		if strings.Contains(message, fragment) {
			return true
		}
	}
	return false
}

func TestTemporaryReportFailure(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		report doctor.Report
		want   bool
	}{
		{
			name: "temporary unavailable finding",
			report: doctor.Report{Findings: []doctor.Finding{{
				Code:     "ARC-NET-001",
				Evidence: []string{"RPC detail: dial tcp: connection refused"},
			}}},
			want: true,
		},
		{
			name: "temporary request failure",
			report: doctor.Report{Findings: []doctor.Finding{{
				Code:     "ARC-RPC-005",
				Evidence: []string{"RPC detail: status code 503"},
			}}},
			want: true,
		},
		{
			name: "unsupported method is a regression",
			report: doctor.Report{Findings: []doctor.Finding{{
				Code:     "ARC-RPC-004",
				Evidence: []string{"RPC detail: method not found"},
			}}},
			want: false,
		},
		{
			name: "malformed response is a regression",
			report: doctor.Report{Findings: []doctor.Finding{{
				Code:     "ARC-RPC-005",
				Evidence: []string{"RPC detail: invalid JSON response"},
			}}},
			want: false,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := temporaryReportFailure(test.report); got != test.want {
				t.Fatalf("temporaryReportFailure() = %v, want %v", got, test.want)
			}
		})
	}
}

func loadFixtures(t *testing.T) fixtures {
	t.Helper()

	path := filepath.Join("..", "..", "testdata", "arc-testnet-fixtures.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixtures: %v", err)
	}
	var fixture fixtures
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatalf("decode fixtures: %v", err)
	}
	if fixture.SchemaVersion != 1 {
		t.Fatalf("fixture schema version = %d, want 1", fixture.SchemaVersion)
	}
	if fixture.Network.ChainID != doctor.ArcTestnetChainID {
		t.Fatalf(
			"fixture chain ID = %d, want %d",
			fixture.Network.ChainID,
			doctor.ArcTestnetChainID,
		)
	}
	return fixture
}

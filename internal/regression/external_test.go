package regression_test

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/anandh8x/arcdoctor/internal/chain"
	"github.com/anandh8x/arcdoctor/internal/doctor"
)

type fixtureSet struct {
	SchemaVersion int               `json:"schemaVersion"`
	Cases         []externalFixture `json:"cases"`
}

type externalFixture struct {
	ID               string   `json:"id"`
	Kind             string   `json:"kind"`
	Source           string   `json:"source"`
	ObservedChainID  uint64   `json:"observedChainId,omitempty"`
	RPCErrorCode     int      `json:"rpcErrorCode,omitempty"`
	RPCErrorMessage  string   `json:"rpcErrorMessage,omitempty"`
	ExpectedAttempts int      `json:"expectedAttempts,omitempty"`
	Address          string   `json:"address,omitempty"`
	ExpectedCodes    []string `json:"expectedCodes,omitempty"`
}

func TestExternalArcRegressions(t *testing.T) {
	t.Parallel()

	fixtures := loadFixtures(t)
	if len(fixtures.Cases) < 3 {
		t.Fatalf("external regression count = %d, want at least 3", len(fixtures.Cases))
	}

	for _, fixture := range fixtures.Cases {
		fixture := fixture
		t.Run(fixture.ID, func(t *testing.T) {
			t.Parallel()
			if fixture.Source == "" {
				t.Fatal("external regression has no public source")
			}
			switch fixture.Kind {
			case "unexpected-chain":
				reproduceUnexpectedChain(t, fixture)
			case "request-limit":
				reproduceRequestLimit(t, fixture)
			case "local-address":
				reproduceLocalAddress(t, fixture)
			default:
				t.Fatalf("unsupported external regression kind %q", fixture.Kind)
			}
		})
	}
}

func reproduceUnexpectedChain(t *testing.T, fixture externalFixture) {
	t.Helper()

	instance := doctor.New(networkProbeFunc(func(context.Context) (doctor.NetworkSnapshot, error) {
		now := time.Now().UTC()
		return doctor.NetworkSnapshot{
			ChainID:        fixture.ObservedChainID,
			BlockNumber:    1,
			BlockTimestamp: now,
			ObservedAt:     now,
			Latency:        time.Millisecond,
		}, nil
	}))
	report, err := instance.Diagnose(context.Background(), doctor.Request{
		Kind: doctor.NetworkCheck,
	})
	if err != nil {
		t.Fatalf("Diagnose() error = %v", err)
	}
	assertFindingCodes(t, report, fixture.ExpectedCodes)
}

func reproduceRequestLimit(t *testing.T, fixture externalFixture) {
	t.Helper()

	var mu sync.Mutex
	attempts := 0
	client := &http.Client{Transport: roundTripFunc(func(
		request *http.Request,
	) (*http.Response, error) {
		var rpcRequest struct {
			ID json.RawMessage `json:"id"`
		}
		if err := json.NewDecoder(request.Body).Decode(&rpcRequest); err != nil {
			t.Fatalf("decode request: %v", err)
		}

		mu.Lock()
		attempts++
		attempt := attempts
		mu.Unlock()

		recorder := httptest.NewRecorder()
		recorder.Header().Set("Content-Type", "application/json")
		if attempt == 1 {
			fmt.Fprintf(
				recorder,
				`{"jsonrpc":"2.0","id":%s,"error":{"code":%d,"message":%q}}`,
				rpcRequest.ID,
				fixture.RPCErrorCode,
				fixture.RPCErrorMessage,
			)
		} else {
			fmt.Fprintf(
				recorder,
				`{"jsonrpc":"2.0","id":%s,"result":"0x6001"}`,
				rpcRequest.ID,
			)
		}
		return recorder.Result(), nil
	})}

	code, err := chain.NewRPCProbe(
		"http://arcdoctor.invalid",
		chain.WithHTTPClient(client),
	).Bytecode(
		context.Background(),
		"0x1111111111111111111111111111111111111111",
	)
	if err != nil {
		t.Fatalf("Bytecode() error = %v", err)
	}
	if got := fmt.Sprintf("%x", code); got != "6001" {
		t.Fatalf("bytecode = %s, want 6001", got)
	}
	mu.Lock()
	gotAttempts := attempts
	mu.Unlock()
	if gotAttempts != fixture.ExpectedAttempts {
		t.Fatalf("request attempts = %d, want %d", gotAttempts, fixture.ExpectedAttempts)
	}
}

func reproduceLocalAddress(t *testing.T, fixture externalFixture) {
	t.Helper()

	manifest := []byte(fmt.Sprintf(`{
		"schemaVersion": 1,
		"network": "Arc Testnet",
		"chainId": 5042002,
		"contracts": {
			"ConfiguredContract": {
				"address": %q
			}
		}
	}`, fixture.Address))
	instance := doctor.New(
		networkProbeFunc(func(context.Context) (doctor.NetworkSnapshot, error) {
			now := time.Now().UTC()
			return doctor.NetworkSnapshot{
				ChainID:        doctor.ArcTestnetChainID,
				BlockNumber:    1,
				BlockTimestamp: now,
				ObservedAt:     now,
				Latency:        time.Millisecond,
			}, nil
		}),
		doctor.WithAddressProbe(addressProbeFunc(func(
			_ context.Context,
			address string,
		) (doctor.AddressSnapshot, error) {
			if address != fixture.Address {
				t.Fatalf("address = %q, want %q", address, fixture.Address)
			}
			return doctor.AddressSnapshot{
				BalanceBaseUnits: big.NewInt(0),
			}, nil
		})),
	)
	report, err := instance.Diagnose(context.Background(), doctor.Request{
		Kind: doctor.DeploymentCheck,
		Deployment: &doctor.DeploymentInput{
			Name: "external-regression.json",
			Data: manifest,
		},
	})
	if err != nil {
		t.Fatalf("Diagnose() error = %v", err)
	}
	assertFindingCodes(t, report, fixture.ExpectedCodes)
}

func assertFindingCodes(t *testing.T, report doctor.Report, expected []string) {
	t.Helper()

	observed := make(map[string]struct{}, len(report.Findings))
	for _, finding := range report.Findings {
		observed[finding.Code] = struct{}{}
	}
	for _, code := range expected {
		if _, ok := observed[code]; !ok {
			t.Errorf("findings = %#v, want code %s", report.Findings, code)
		}
	}
}

func loadFixtures(t *testing.T) fixtureSet {
	t.Helper()

	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "external-regressions.json"))
	if err != nil {
		t.Fatalf("read external regressions: %v", err)
	}
	var fixtures fixtureSet
	if err := json.Unmarshal(data, &fixtures); err != nil {
		t.Fatalf("decode external regressions: %v", err)
	}
	if fixtures.SchemaVersion != 1 {
		t.Fatalf("schema version = %d, want 1", fixtures.SchemaVersion)
	}
	return fixtures
}

type networkProbeFunc func(context.Context) (doctor.NetworkSnapshot, error)

func (probe networkProbeFunc) NetworkSnapshot(
	ctx context.Context,
) (doctor.NetworkSnapshot, error) {
	return probe(ctx)
}

type addressProbeFunc func(context.Context, string) (doctor.AddressSnapshot, error)

func (probe addressProbeFunc) AddressSnapshot(
	ctx context.Context,
	address string,
) (doctor.AddressSnapshot, error) {
	return probe(ctx, address)
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

package chain_test

import (
	"context"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/anandh8x/arcdoctor/internal/chain"
)

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result"`
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func rpcHTTPClient(t *testing.T, results map[string]any) *http.Client {
	t.Helper()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request rpcRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Errorf("decode request: %v", err)
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}

		result, ok := results[request.Method]
		if !ok {
			t.Errorf("unexpected RPC method %q", request.Method)
			http.Error(w, "unexpected method", http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(rpcResponse{
			JSONRPC: "2.0",
			ID:      request.ID,
			Result:  result,
		}); err != nil {
			t.Errorf("encode response: %v", err)
		}
	})

	return &http.Client{
		Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			return recorder.Result(), nil
		}),
	}
}

func TestRPCProbeCollectsArcNetworkEvidence(t *testing.T) {
	t.Parallel()

	httpClient := rpcHTTPClient(t, map[string]any{
		"eth_chainId":     "0x4cef52",
		"eth_blockNumber": "0x33b1cb0",
		"eth_getBlockByNumber": map[string]any{
			"timestamp": "0x6975f7b0",
		},
	})

	snapshot, err := chain.NewRPCProbe(
		"http://arcdoctor.test",
		chain.WithHTTPClient(httpClient),
	).NetworkSnapshot(context.Background())
	if err != nil {
		t.Fatalf("NetworkSnapshot() error = %v", err)
	}

	if snapshot.ChainID != 5_042_002 {
		t.Errorf("ChainID = %d, want 5042002", snapshot.ChainID)
	}
	if snapshot.BlockNumber != 54_205_616 {
		t.Errorf("BlockNumber = %d, want 54205616", snapshot.BlockNumber)
	}
	wantTimestamp := time.Unix(1_769_338_800, 0).UTC()
	if !snapshot.BlockTimestamp.Equal(wantTimestamp) {
		t.Errorf("BlockTimestamp = %s, want %s", snapshot.BlockTimestamp, wantTimestamp)
	}
	if snapshot.Latency <= 0 {
		t.Errorf("Latency = %s, want positive duration", snapshot.Latency)
	}
}

func TestRPCProbeCollectsAddressEvidence(t *testing.T) {
	t.Parallel()

	httpClient := rpcHTTPClient(t, map[string]any{
		"eth_getBalance":          "0x1bc16d674ec80000",
		"eth_getTransactionCount": "0x1",
		"eth_getCode":             "0x60006000",
	})
	probe := chain.NewRPCProbe(
		"http://arcdoctor.test",
		chain.WithHTTPClient(httpClient),
	)

	snapshot, err := probe.AddressSnapshot(
		context.Background(),
		"0xCe084c9358FBC5200415012885c2F0F0906d400C",
	)
	if err != nil {
		t.Fatalf("AddressSnapshot() error = %v", err)
	}

	if snapshot.BalanceBaseUnits.Cmp(big.NewInt(2_000_000_000_000_000_000)) != 0 {
		t.Errorf("BalanceBaseUnits = %s, want 2000000000000000000", snapshot.BalanceBaseUnits)
	}
	if snapshot.Nonce != 1 {
		t.Errorf("Nonce = %d, want 1", snapshot.Nonce)
	}
	if got, want := string(snapshot.Code), string([]byte{0x60, 0x00, 0x60, 0x00}); got != want {
		t.Errorf("Code = %x, want %x", snapshot.Code, []byte(want))
	}
}

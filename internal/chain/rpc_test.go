package chain_test

import (
	"context"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/anandh8x/arcdoctor/internal/chain"
	"github.com/anandh8x/arcdoctor/internal/doctor"
	"github.com/ethereum/go-ethereum/common"
)

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   any             `json:"error,omitempty"`
}

type rpcFailure struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
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
		response := rpcResponse{
			JSONRPC: "2.0",
			ID:      request.ID,
		}
		if failure, failed := result.(rpcFailure); failed {
			response.Error = failure
		} else {
			response.Result = result
		}
		if err := json.NewEncoder(w).Encode(response); err != nil {
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
	if snapshot.ObservedAt.IsZero() {
		t.Error("ObservedAt is zero")
	}
}

func TestRPCProbeClassifiesUnsupportedRequiredMethodAndKeepsChainID(t *testing.T) {
	t.Parallel()

	httpClient := rpcHTTPClient(t, map[string]any{
		"eth_chainId": "0x4cef52",
		"eth_blockNumber": rpcFailure{
			Code:    -32601,
			Message: "method not found",
		},
	})

	snapshot, err := chain.NewRPCProbe(
		"http://arcdoctor.test",
		chain.WithHTTPClient(httpClient),
	).NetworkSnapshot(context.Background())
	if err == nil {
		t.Fatal("NetworkSnapshot() error = nil")
	}
	var operationError *doctor.RPCOperationError
	if !errors.As(err, &operationError) {
		t.Fatalf("error = %T %v, want RPCOperationError", err, err)
	}
	if operationError.Kind != doctor.RPCErrorUnsupported ||
		operationError.Method != "eth_blockNumber" {
		t.Errorf("RPC operation error = %#v", operationError)
	}
	if snapshot.ChainID != doctor.ArcTestnetChainID {
		t.Errorf("partial ChainID = %d, want %d", snapshot.ChainID, doctor.ArcTestnetChainID)
	}
	if snapshot.ObservedAt.IsZero() || snapshot.Latency <= 0 {
		t.Errorf("partial timing evidence = %#v", snapshot)
	}
}

func TestRPCProbeCollectsAddressEvidence(t *testing.T) {
	t.Parallel()

	httpClient := rpcHTTPClient(t, map[string]any{
		"eth_getBalance":          "0x1bc16d674ec80000",
		"eth_getTransactionCount": "0x1",
		"eth_getCode":             "0x60006000",
		"eth_getStorageAt":        "0x0000000000000000000000002222222222222222222222222222222222222222",
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
	if got := common.BytesToAddress(snapshot.EIP1967Implementation).Hex(); got !=
		"0x2222222222222222222222222222222222222222" {
		t.Errorf("EIP-1967 implementation = %s", got)
	}
}

func TestRPCProbeKeepsCoreAddressEvidenceWhenProxyStorageIsUnsupported(t *testing.T) {
	t.Parallel()

	httpClient := rpcHTTPClient(t, map[string]any{
		"eth_getBalance":          "0x0",
		"eth_getTransactionCount": "0x0",
		"eth_getCode":             "0x60006000",
		"eth_getStorageAt": rpcFailure{
			Code:    -32601,
			Message: "method not found",
		},
	})
	snapshot, err := chain.NewRPCProbe(
		"http://arcdoctor.test",
		chain.WithHTTPClient(httpClient),
	).AddressSnapshot(
		context.Background(),
		"0x1111111111111111111111111111111111111111",
	)
	if err != nil {
		t.Fatalf("AddressSnapshot() error = %v", err)
	}
	if len(snapshot.Code) == 0 {
		t.Fatal("core bytecode evidence was discarded")
	}
	if !strings.Contains(snapshot.ProxyStorageError, "method not found") {
		t.Errorf("ProxyStorageError = %q", snapshot.ProxyStorageError)
	}
}

func TestRPCProbeCollectsBytecodeWithoutOtherAddressCalls(t *testing.T) {
	t.Parallel()

	httpClient := rpcHTTPClient(t, map[string]any{
		"eth_getCode": "0x60006000",
	})
	probe := chain.NewRPCProbe(
		"http://arcdoctor.test",
		chain.WithHTTPClient(httpClient),
	)

	code, err := probe.Bytecode(
		context.Background(),
		"0xCe084c9358FBC5200415012885c2F0F0906d400C",
	)
	if err != nil {
		t.Fatalf("Bytecode() error = %v", err)
	}
	if got, want := string(code), string([]byte{0x60, 0x00, 0x60, 0x00}); got != want {
		t.Errorf("Code = %x, want %x", code, []byte(want))
	}
}

func TestRPCProbeCollectsSuccessfulTransactionEvidence(t *testing.T) {
	t.Parallel()

	const hash = "0x2ae2a47a07856ce9f0f6be62335f558bee7561e5922f53d119c58de66baead17"
	httpClient := rpcHTTPClient(t, map[string]any{
		"eth_getTransactionByHash": map[string]any{
			"hash":        hash,
			"from":        "0x99066fBc97557490fA794F750630bb41733D1004",
			"to":          "0xCe084c9358FBC5200415012885c2F0F0906d400C",
			"value":       "0x0",
			"input":       "0x12345678",
			"gas":         "0x3d090",
			"type":        "0x2",
			"blockNumber": "0x32beabc",
		},
		"eth_getTransactionReceipt": map[string]any{
			"status":          "0x1",
			"gasUsed":         "0x16ced",
			"blockNumber":     "0x32beabc",
			"contractAddress": nil,
		},
	})
	probe := chain.NewRPCProbe(
		"http://arcdoctor.test",
		chain.WithHTTPClient(httpClient),
	)

	snapshot, err := probe.TransactionSnapshot(context.Background(), hash)
	if err != nil {
		t.Fatalf("TransactionSnapshot() error = %v", err)
	}
	if !snapshot.Found {
		t.Fatal("Found = false, want true")
	}
	if snapshot.To != "0xCe084c9358FBC5200415012885c2F0F0906d400C" {
		t.Errorf("To = %q", snapshot.To)
	}
	if snapshot.Receipt == nil {
		t.Fatal("Receipt is nil")
	}
	if snapshot.Receipt.Status != 1 {
		t.Errorf("Receipt.Status = %d, want 1", snapshot.Receipt.Status)
	}
	if snapshot.Receipt.GasUsed != 93_421 {
		t.Errorf("Receipt.GasUsed = %d, want 93421", snapshot.Receipt.GasUsed)
	}
	if snapshot.Replay.Status != "" {
		t.Errorf("Replay.Status = %q, want empty for successful transaction", snapshot.Replay.Status)
	}
}

func TestRPCProbeReplaysRevertedTransactionAtParentBlock(t *testing.T) {
	t.Parallel()

	const hash = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	httpClient := rpcHTTPClient(t, map[string]any{
		"eth_getTransactionByHash": map[string]any{
			"hash":        hash,
			"from":        "0x99066fBc97557490fA794F750630bb41733D1004",
			"to":          "0x0C83623d0abFca5e7ad6E6179bB45A3E70C6C9DA",
			"value":       "0x0",
			"input":       "0x12345678",
			"gas":         "0x3d090",
			"type":        "0x2",
			"blockNumber": "0x10",
		},
		"eth_getTransactionReceipt": map[string]any{
			"status":          "0x0",
			"gasUsed":         "0x7918",
			"blockNumber":     "0x10",
			"contractAddress": nil,
		},
		"eth_call": rpcFailure{
			Code:    3,
			Message: "execution reverted",
			Data:    "0xdc776dc4",
		},
	})
	probe := chain.NewRPCProbe(
		"http://arcdoctor.test",
		chain.WithHTTPClient(httpClient),
	)

	snapshot, err := probe.TransactionSnapshot(context.Background(), hash)
	if err != nil {
		t.Fatalf("TransactionSnapshot() error = %v", err)
	}
	if snapshot.Receipt == nil || snapshot.Receipt.Status != 0 {
		t.Fatalf("Receipt = %#v, want reverted", snapshot.Receipt)
	}
	if snapshot.Replay.Status != "reverted" {
		t.Errorf("Replay.Status = %q, want reverted", snapshot.Replay.Status)
	}
	if snapshot.Replay.BlockNumber != 15 {
		t.Errorf("Replay.BlockNumber = %d, want 15", snapshot.Replay.BlockNumber)
	}
	if got := string(snapshot.Replay.RevertData); got != string([]byte{0xdc, 0x77, 0x6d, 0xc4}) {
		t.Errorf("Replay.RevertData = %x, want dc776dc4", snapshot.Replay.RevertData)
	}
}

func TestRPCProbeRetriesArcRequestLimitResponses(t *testing.T) {
	t.Parallel()

	attempts := 0
	client := &http.Client{
		Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			attempts++
			var rpcRequestValue rpcRequest
			if err := json.NewDecoder(request.Body).Decode(&rpcRequestValue); err != nil {
				t.Fatalf("decode request: %v", err)
			}

			recorder := httptest.NewRecorder()
			recorder.Header().Set("Content-Type", "application/json")
			response := rpcResponse{
				JSONRPC: "2.0",
				ID:      rpcRequestValue.ID,
			}
			if attempts == 1 {
				response.Error = rpcFailure{
					Code:    -32011,
					Message: "request limit reached",
				}
			} else {
				response.Result = "0x6001"
			}
			if err := json.NewEncoder(recorder).Encode(response); err != nil {
				t.Fatalf("encode response: %v", err)
			}
			return recorder.Result(), nil
		}),
	}

	code, err := chain.NewRPCProbe(
		"http://arcdoctor.test",
		chain.WithHTTPClient(client),
	).Bytecode(
		context.Background(),
		"0x1111111111111111111111111111111111111111",
	)
	if err != nil {
		t.Fatalf("Bytecode() error = %v", err)
	}
	if attempts != 2 {
		t.Errorf("attempts = %d, want 2", attempts)
	}
	if got := string(code); got != string([]byte{0x60, 0x01}) {
		t.Errorf("code = %x, want 6001", code)
	}
}

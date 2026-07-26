package integration_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/anandh8x/arcdoctor/internal/chain"
	"github.com/anandh8x/arcdoctor/internal/doctor"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rpc"
)

const customErrorABI = `[
  {
    "type": "error",
    "name": "CustomFailure",
    "inputs": [{"name": "code", "type": "uint256"}]
  }
]`

type rpcReceipt struct {
	Status          hexutil.Uint64 `json:"status"`
	ContractAddress string         `json:"contractAddress"`
}

type deployedContract struct {
	address string
	txHash  string
	runtime []byte
}

func TestAnvilDiagnosticWorkflow(t *testing.T) {
	rpcURL := startAnvil(t)
	client, err := rpc.DialContext(context.Background(), rpcURL)
	if err != nil {
		t.Fatalf("connect to Anvil: %v", err)
	}
	t.Cleanup(client.Close)

	var accounts []string
	if err := client.CallContext(context.Background(), &accounts, "eth_accounts"); err != nil {
		t.Fatalf("read Anvil accounts: %v", err)
	}
	if len(accounts) == 0 {
		t.Fatal("Anvil returned no unlocked test accounts")
	}
	from := accounts[0]

	success := deployRuntime(t, client, from, successRuntime())
	reason := deployRuntime(t, client, from, revertRuntime(errorStringData(t, "boom")))
	panicContract := deployRuntime(t, client, from, revertRuntime(panicData(0x01)))
	custom := deployRuntime(t, client, from, revertRuntime(customErrorData(42)))

	successHash := sendCall(t, client, from, success.address)
	reasonHash := sendCall(t, client, from, reason.address)
	panicHash := sendCall(t, client, from, panicContract.address)
	customHash := sendCall(t, client, from, custom.address)

	probe := chain.NewRPCProbe(rpcURL)
	instance := doctor.New(
		probe,
		doctor.WithAddressProbe(probe),
		doctor.WithBytecodeProbe(probe),
		doctor.WithTransactionProbe(probe),
		doctor.WithArtifactLoader(func(path string) ([]byte, error) {
			if path != "Harness.json" {
				return nil, fmt.Errorf("unexpected artifact path %q", path)
			}
			return artifactJSON(success.runtime), nil
		}),
	)

	t.Run("address", func(t *testing.T) {
		report := diagnose(t, instance, doctor.Request{
			Kind:   doctor.AddressCheck,
			Target: success.address,
		})
		if report.Address == nil || report.Address.CodeSize == 0 {
			t.Fatalf("Address = %#v, want deployed bytecode", report.Address)
		}
		if !hasFinding(report, "ARC-ADR-000") {
			t.Fatalf("Findings = %#v, want ARC-ADR-000", report.Findings)
		}
	})

	t.Run("successful transaction", func(t *testing.T) {
		report := diagnose(t, instance, doctor.Request{
			Kind:   doctor.TransactionCheck,
			Target: successHash,
		})
		if report.Transaction == nil ||
			report.Transaction.State != doctor.TransactionStateSuccessful {
			t.Fatalf("Transaction = %#v, want successful", report.Transaction)
		}
	})

	t.Run("Error string and replay", func(t *testing.T) {
		report := diagnose(t, instance, doctor.Request{
			Kind:   doctor.TransactionCheck,
			Target: reasonHash,
		})
		assertRevertedFinding(t, report, "ARC-TX-007", "Error(string)")
	})

	t.Run("panic and replay", func(t *testing.T) {
		report := diagnose(t, instance, doctor.Request{
			Kind:   doctor.TransactionCheck,
			Target: panicHash,
		})
		assertRevertedFinding(t, report, "ARC-TX-008", "Panic(uint256)")
	})

	t.Run("custom error and replay", func(t *testing.T) {
		report := diagnose(t, instance, doctor.Request{
			Kind:   doctor.TransactionCheck,
			Target: customHash,
			ABIs: []doctor.ABIInput{
				{Name: "Harness.json", Data: []byte(customErrorABI)},
			},
		})
		assertRevertedFinding(t, report, "ARC-TX-009", "CustomFailure(uint256)")
	})

	t.Run("deployment and artifact", func(t *testing.T) {
		manifest := []byte(fmt.Sprintf(`{
		  "schemaVersion": 1,
		  "network": "Arc Testnet",
		  "chainId": 5042002,
		  "contracts": {
		    "Harness": {
		      "address": %q,
		      "transactionHash": %q,
		      "artifact": "Harness.json"
		    }
		  }
		}`, success.address, success.txHash))
		report := diagnose(t, instance, doctor.Request{
			Kind: doctor.DeploymentCheck,
			Deployment: &doctor.DeploymentInput{
				Name: "anvil.json",
				Data: manifest,
			},
		})
		if report.HasErrors() {
			t.Fatalf("Findings = %#v, want no deployment errors", report.Findings)
		}
		for _, code := range []string{"ARC-DEP-013", "ARC-DEP-016", "ARC-DEP-000"} {
			if !hasFinding(report, code) {
				t.Errorf("Findings = %#v, want %s", report.Findings, code)
			}
		}
	})
}

func startAnvil(t *testing.T) string {
	t.Helper()

	path, err := exec.LookPath("anvil")
	if err != nil {
		t.Skip("Anvil is not installed; skipping local EVM integration test")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			t.Skipf("local sandbox does not permit a listening socket: %v", err)
		}
		t.Fatalf("reserve Anvil port: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatalf("release Anvil port: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	var output bytes.Buffer
	command := exec.CommandContext(
		ctx,
		path,
		"--host", "127.0.0.1",
		"--port", strconv.Itoa(port),
		"--chain-id", strconv.FormatUint(doctor.ArcTestnetChainID, 10),
		"--silent",
	)
	command.Stdout = &output
	command.Stderr = &output
	if err := command.Start(); err != nil {
		cancel()
		t.Fatalf("start Anvil: %v", err)
	}
	t.Cleanup(func() {
		cancel()
		_ = command.Wait()
	})

	rpcURL := "http://127.0.0.1:" + strconv.Itoa(port)
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		probe := chain.NewRPCProbe(rpcURL)
		probeContext, probeCancel := context.WithTimeout(
			context.Background(),
			250*time.Millisecond,
		)
		snapshot, probeErr := probe.NetworkSnapshot(probeContext)
		probeCancel()
		if probeErr == nil && snapshot.ChainID == doctor.ArcTestnetChainID {
			return rpcURL
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("Anvil did not become ready:\n%s", output.String())
	return ""
}

func deployRuntime(
	t *testing.T,
	client *rpc.Client,
	from string,
	runtime []byte,
) deployedContract {
	t.Helper()

	initCode := creationCode(runtime)
	hash := sendTransaction(t, client, map[string]any{
		"from": from,
		"data": hexutil.Encode(initCode),
		"gas":  hexutil.EncodeUint64(2_000_000),
	})
	receipt := waitReceipt(t, client, hash)
	if uint64(receipt.Status) != 1 || receipt.ContractAddress == "" {
		t.Fatalf("deployment receipt = %#v", receipt)
	}
	return deployedContract{
		address: receipt.ContractAddress,
		txHash:  hash,
		runtime: append([]byte(nil), runtime...),
	}
}

func sendCall(t *testing.T, client *rpc.Client, from, to string) string {
	t.Helper()
	return sendTransaction(t, client, map[string]any{
		"from": from,
		"to":   to,
		"gas":  hexutil.EncodeUint64(500_000),
	})
}

func sendTransaction(
	t *testing.T,
	client *rpc.Client,
	transaction map[string]any,
) string {
	t.Helper()

	var hash string
	if err := client.CallContext(
		context.Background(),
		&hash,
		"eth_sendTransaction",
		transaction,
	); err != nil {
		t.Fatalf("send Anvil transaction: %v", err)
	}
	if len(hash) != 66 {
		t.Fatalf("transaction hash = %q", hash)
	}
	receipt := waitReceipt(t, client, hash)
	if receipt.ContractAddress == "" && transaction["to"] != nil {
		return hash
	}
	return hash
}

func waitReceipt(t *testing.T, client *rpc.Client, hash string) rpcReceipt {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var receipt *rpcReceipt
		if err := client.CallContext(
			context.Background(),
			&receipt,
			"eth_getTransactionReceipt",
			hash,
		); err != nil {
			t.Fatalf("read Anvil receipt: %v", err)
		}
		if receipt != nil {
			return *receipt
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("receipt %s was not mined", hash)
	return rpcReceipt{}
}

func diagnose(
	t *testing.T,
	instance *doctor.Doctor,
	request doctor.Request,
) doctor.Report {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	report, err := instance.Diagnose(ctx, request)
	if err != nil {
		t.Fatalf("Diagnose() error = %v", err)
	}
	return report
}

func assertRevertedFinding(
	t *testing.T,
	report doctor.Report,
	code string,
	signature string,
) {
	t.Helper()

	if report.Transaction == nil ||
		report.Transaction.State != doctor.TransactionStateReverted {
		t.Fatalf("Transaction = %#v, want reverted", report.Transaction)
	}
	if report.Transaction.Replay.Status != doctor.ReplayStatusReverted {
		t.Fatalf("Replay = %#v, want reproduced revert", report.Transaction.Replay)
	}
	if report.Transaction.Revert == nil ||
		report.Transaction.Revert.Signature != signature {
		t.Fatalf("Revert = %#v, want %s", report.Transaction.Revert, signature)
	}
	if !hasFinding(report, code) {
		t.Fatalf("Findings = %#v, want %s", report.Findings, code)
	}
}

func hasFinding(report doctor.Report, code string) bool {
	for _, finding := range report.Findings {
		if finding.Code == code {
			return true
		}
	}
	return false
}

func creationCode(runtime []byte) []byte {
	length := uint16(len(runtime))
	prefix := []byte{
		0x61, 0x00, 0x00,
		0x61, 0x00, 0x0f,
		0x60, 0x00,
		0x39,
		0x61, 0x00, 0x00,
		0x60, 0x00,
		0xf3,
	}
	binary.BigEndian.PutUint16(prefix[1:3], length)
	binary.BigEndian.PutUint16(prefix[10:12], length)
	return append(prefix, runtime...)
}

func successRuntime() []byte {
	return []byte{
		0x60, 0x01,
		0x60, 0x00,
		0x52,
		0x60, 0x20,
		0x60, 0x00,
		0xf3,
	}
}

func revertRuntime(data []byte) []byte {
	length := uint16(len(data))
	prefix := []byte{
		0x61, 0x00, 0x00,
		0x61, 0x00, 0x0f,
		0x60, 0x00,
		0x39,
		0x61, 0x00, 0x00,
		0x60, 0x00,
		0xfd,
	}
	binary.BigEndian.PutUint16(prefix[1:3], length)
	binary.BigEndian.PutUint16(prefix[10:12], length)
	return append(prefix, data...)
}

func errorStringData(t *testing.T, message string) []byte {
	t.Helper()

	stringType, err := abi.NewType("string", "", nil)
	if err != nil {
		t.Fatalf("create ABI string type: %v", err)
	}
	encoded, err := (abi.Arguments{{Type: stringType}}).Pack(message)
	if err != nil {
		t.Fatalf("encode Error(string): %v", err)
	}
	return append(
		append([]byte(nil), crypto.Keccak256([]byte("Error(string)"))[:4]...),
		encoded...,
	)
}

func panicData(code byte) []byte {
	data := make([]byte, 36)
	copy(data[:4], crypto.Keccak256([]byte("Panic(uint256)"))[:4])
	data[35] = code
	return data
}

func customErrorData(code int64) []byte {
	data := make([]byte, 36)
	copy(data[:4], crypto.Keccak256([]byte("CustomFailure(uint256)"))[:4])
	new(big.Int).SetInt64(code).FillBytes(data[4:])
	return data
}

func artifactJSON(runtime []byte) []byte {
	value := map[string]any{
		"deployedBytecode": map[string]any{
			"object":              hex.EncodeToString(runtime),
			"immutableReferences": map[string]any{},
			"linkReferences":      map[string]any{},
		},
	}
	data, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return data
}

func TestRuntimeFixturesAreBoundedAndDeterministic(t *testing.T) {
	t.Parallel()

	runtimes := [][]byte{
		successRuntime(),
		revertRuntime(panicData(0x01)),
		revertRuntime(customErrorData(42)),
	}
	for _, runtime := range runtimes {
		if len(runtime) == 0 || len(runtime) > 512 {
			t.Fatalf("runtime length = %d", len(runtime))
		}
		if strings.Contains(hex.EncodeToString(runtime), " ") {
			t.Fatalf("runtime contains non-hex formatting: %x", runtime)
		}
	}
}

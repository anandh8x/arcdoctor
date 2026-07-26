package chain

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/anandh8x/arcdoctor/internal/doctor"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/rpc"
)

type RPCProbe struct {
	url        string
	httpClient *http.Client
}

const (
	eip1967ImplementationSlot = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
	eip1967BeaconSlot         = "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50"
)

type RPCProbeOption func(*RPCProbe)

func WithHTTPClient(client *http.Client) RPCProbeOption {
	return func(probe *RPCProbe) {
		probe.httpClient = client
	}
}

func NewRPCProbe(url string, options ...RPCProbeOption) *RPCProbe {
	probe := &RPCProbe{
		url:        url,
		httpClient: http.DefaultClient,
	}
	for _, option := range options {
		option(probe)
	}
	return probe
}

func (p *RPCProbe) NetworkSnapshot(ctx context.Context) (doctor.NetworkSnapshot, error) {
	startedAt := time.Now()

	client, err := rpc.DialOptions(ctx, p.url, rpc.WithHTTPClient(p.httpClient))
	if err != nil {
		return doctor.NetworkSnapshot{}, fmt.Errorf("connect to RPC endpoint: %w", err)
	}
	defer client.Close()

	var chainID hexutil.Uint64
	if err := callContext(ctx, client, &chainID, "eth_chainId"); err != nil {
		return doctor.NetworkSnapshot{}, fmt.Errorf("read chain ID: %w", err)
	}

	var blockNumber hexutil.Uint64
	if err := callContext(ctx, client, &blockNumber, "eth_blockNumber"); err != nil {
		return doctor.NetworkSnapshot{}, fmt.Errorf("read latest block number: %w", err)
	}

	var block *struct {
		Timestamp hexutil.Uint64 `json:"timestamp"`
	}
	if err := callContext(
		ctx,
		client,
		&block,
		"eth_getBlockByNumber",
		hexutil.EncodeUint64(uint64(blockNumber)),
		false,
	); err != nil {
		return doctor.NetworkSnapshot{}, fmt.Errorf("read latest block: %w", err)
	}
	if block == nil {
		return doctor.NetworkSnapshot{}, fmt.Errorf("read latest block: RPC returned null")
	}

	return doctor.NetworkSnapshot{
		ChainID:        uint64(chainID),
		BlockNumber:    uint64(blockNumber),
		BlockTimestamp: time.Unix(int64(block.Timestamp), 0).UTC(),
		ObservedAt:     time.Now().UTC(),
		Latency:        time.Since(startedAt),
	}, nil
}

func (p *RPCProbe) AddressSnapshot(
	ctx context.Context,
	address string,
) (doctor.AddressSnapshot, error) {
	client, err := rpc.DialOptions(ctx, p.url, rpc.WithHTTPClient(p.httpClient))
	if err != nil {
		return doctor.AddressSnapshot{}, fmt.Errorf("connect to RPC endpoint: %w", err)
	}
	defer client.Close()

	var balance hexutil.Big
	if err := callContext(ctx, client, &balance, "eth_getBalance", address, "latest"); err != nil {
		return doctor.AddressSnapshot{}, fmt.Errorf("read address balance: %w", err)
	}

	var nonce hexutil.Uint64
	if err := callContext(
		ctx,
		client,
		&nonce,
		"eth_getTransactionCount",
		address,
		"latest",
	); err != nil {
		return doctor.AddressSnapshot{}, fmt.Errorf("read address nonce: %w", err)
	}

	var code hexutil.Bytes
	if err := callContext(ctx, client, &code, "eth_getCode", address, "latest"); err != nil {
		return doctor.AddressSnapshot{}, fmt.Errorf("read address bytecode: %w", err)
	}

	snapshot := doctor.AddressSnapshot{
		BalanceBaseUnits: new(big.Int).Set((*big.Int)(&balance)),
		Nonce:            uint64(nonce),
		Code:             append([]byte(nil), code...),
	}
	if len(code) == 0 {
		return snapshot, nil
	}

	var implementation hexutil.Bytes
	if err := callContext(
		ctx,
		client,
		&implementation,
		"eth_getStorageAt",
		address,
		eip1967ImplementationSlot,
		"latest",
	); err != nil {
		snapshot.ProxyStorageUnsupported = isMethodNotFoundError(err)
		snapshot.ProxyStorageError = "read EIP-1967 implementation slot: " + err.Error()
		return snapshot, nil
	}
	snapshot.EIP1967Implementation = leftPadHash(implementation)

	var beacon hexutil.Bytes
	if err := callContext(
		ctx,
		client,
		&beacon,
		"eth_getStorageAt",
		address,
		eip1967BeaconSlot,
		"latest",
	); err != nil {
		snapshot.ProxyStorageUnsupported = isMethodNotFoundError(err)
		snapshot.ProxyStorageError = "read EIP-1967 beacon slot: " + err.Error()
		return snapshot, nil
	}
	snapshot.EIP1967Beacon = leftPadHash(beacon)
	return snapshot, nil
}

func (p *RPCProbe) Bytecode(ctx context.Context, address string) ([]byte, error) {
	client, err := rpc.DialOptions(ctx, p.url, rpc.WithHTTPClient(p.httpClient))
	if err != nil {
		return nil, fmt.Errorf("connect to RPC endpoint: %w", err)
	}
	defer client.Close()

	var code hexutil.Bytes
	if err := callContext(ctx, client, &code, "eth_getCode", address, "latest"); err != nil {
		return nil, fmt.Errorf("read address bytecode: %w", err)
	}
	return append([]byte(nil), code...), nil
}

type rpcTransaction struct {
	Hash        common.Hash     `json:"hash"`
	From        common.Address  `json:"from"`
	To          *common.Address `json:"to"`
	Value       *hexutil.Big    `json:"value"`
	Input       hexutil.Bytes   `json:"input"`
	Gas         hexutil.Uint64  `json:"gas"`
	Type        hexutil.Uint64  `json:"type"`
	BlockNumber *hexutil.Uint64 `json:"blockNumber"`
}

type rpcReceipt struct {
	Status          hexutil.Uint64  `json:"status"`
	GasUsed         hexutil.Uint64  `json:"gasUsed"`
	BlockNumber     hexutil.Uint64  `json:"blockNumber"`
	ContractAddress *common.Address `json:"contractAddress"`
}

func (p *RPCProbe) TransactionSnapshot(
	ctx context.Context,
	hash string,
) (doctor.TransactionSnapshot, error) {
	client, err := rpc.DialOptions(ctx, p.url, rpc.WithHTTPClient(p.httpClient))
	if err != nil {
		return doctor.TransactionSnapshot{}, fmt.Errorf("connect to RPC endpoint: %w", err)
	}
	defer client.Close()

	var transaction *rpcTransaction
	if err := callContext(
		ctx,
		client,
		&transaction,
		"eth_getTransactionByHash",
		hash,
	); err != nil {
		return doctor.TransactionSnapshot{}, fmt.Errorf("read transaction: %w", err)
	}
	if transaction == nil {
		return doctor.TransactionSnapshot{Found: false}, nil
	}

	snapshot := doctor.TransactionSnapshot{
		Found:    true,
		From:     transaction.From.Hex(),
		Input:    append([]byte(nil), transaction.Input...),
		GasLimit: uint64(transaction.Gas),
		Type:     uint8(transaction.Type),
	}
	if transaction.To != nil {
		snapshot.To = transaction.To.Hex()
	}
	if transaction.Value != nil {
		snapshot.ValueBaseUnits = new(big.Int).Set((*big.Int)(transaction.Value))
	} else {
		snapshot.ValueBaseUnits = new(big.Int)
	}
	if transaction.BlockNumber != nil {
		blockNumber := uint64(*transaction.BlockNumber)
		snapshot.BlockNumber = &blockNumber
	}

	var receipt *rpcReceipt
	if err := callContext(
		ctx,
		client,
		&receipt,
		"eth_getTransactionReceipt",
		hash,
	); err != nil {
		return doctor.TransactionSnapshot{}, fmt.Errorf("read transaction receipt: %w", err)
	}
	if receipt == nil {
		return snapshot, nil
	}

	snapshot.Receipt = &doctor.TransactionReceiptSnapshot{
		Status:          uint64(receipt.Status),
		GasUsed:         uint64(receipt.GasUsed),
		BlockNumber:     uint64(receipt.BlockNumber),
		ContractAddress: addressPointerString(receipt.ContractAddress),
	}
	if snapshot.BlockNumber == nil {
		blockNumber := uint64(receipt.BlockNumber)
		snapshot.BlockNumber = &blockNumber
	}
	if uint64(receipt.Status) == 0 {
		snapshot.Replay = replayTransaction(ctx, client, transaction, uint64(receipt.BlockNumber))
	}

	return snapshot, nil
}

func replayTransaction(
	ctx context.Context,
	client *rpc.Client,
	transaction *rpcTransaction,
	blockNumber uint64,
) doctor.ReplaySnapshot {
	if blockNumber == 0 {
		return doctor.ReplaySnapshot{
			Status: doctor.ReplayStatusInconclusive,
			Detail: "transaction was included in block zero",
		}
	}

	call := map[string]any{
		"from":  transaction.From.Hex(),
		"gas":   hexutil.EncodeUint64(uint64(transaction.Gas)),
		"value": hexutil.EncodeBig(transactionValue(transaction)),
		"data":  hexutil.Encode(transaction.Input),
	}
	if transaction.To != nil {
		call["to"] = transaction.To.Hex()
	}

	replayBlock := blockNumber - 1
	var result hexutil.Bytes
	err := callContext(
		ctx,
		client,
		&result,
		"eth_call",
		call,
		hexutil.EncodeUint64(replayBlock),
	)
	if err == nil {
		return doctor.ReplaySnapshot{
			Status:      doctor.ReplayStatusSucceeded,
			BlockNumber: replayBlock,
		}
	}
	if data, ok := revertErrorData(err); ok {
		return doctor.ReplaySnapshot{
			Status:      doctor.ReplayStatusReverted,
			BlockNumber: replayBlock,
			RevertData:  append([]byte(nil), data...),
		}
	}
	return doctor.ReplaySnapshot{
		Status:      doctor.ReplayStatusUnavailable,
		BlockNumber: replayBlock,
		Detail:      err.Error(),
	}
}

func revertErrorData(err error) ([]byte, bool) {
	var dataError rpc.DataError
	if !errors.As(err, &dataError) {
		return nil, false
	}
	data, ok := dataError.ErrorData().(string)
	if !ok {
		return nil, false
	}
	decoded, decodeErr := hexutil.Decode(data)
	if decodeErr != nil {
		return nil, false
	}
	return decoded, true
}

func callContext(
	ctx context.Context,
	client *rpc.Client,
	result any,
	method string,
	args ...any,
) error {
	delays := [...]time.Duration{
		300 * time.Millisecond,
		750 * time.Millisecond,
		1500 * time.Millisecond,
	}
	var err error
	for attempt := 0; ; attempt++ {
		err = client.CallContext(ctx, result, method, args...)
		if err == nil || !isRateLimitError(err) || attempt == len(delays) {
			return err
		}
		timer := time.NewTimer(delays[attempt])
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func isRateLimitError(err error) bool {
	var rpcError rpc.Error
	if errors.As(err, &rpcError) {
		if rpcError.ErrorCode() == -32011 || rpcError.ErrorCode() == -32005 {
			return true
		}
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "rate limit") ||
		strings.Contains(message, "request limit") ||
		strings.Contains(message, "too many requests")
}

func isMethodNotFoundError(err error) bool {
	var rpcError rpc.Error
	return errors.As(err, &rpcError) && rpcError.ErrorCode() == -32601
}

func leftPadHash(value []byte) []byte {
	if len(value) > common.HashLength {
		return append([]byte(nil), value[len(value)-common.HashLength:]...)
	}
	result := make([]byte, common.HashLength)
	copy(result[common.HashLength-len(value):], value)
	return result
}

func transactionValue(transaction *rpcTransaction) *big.Int {
	if transaction.Value == nil {
		return new(big.Int)
	}
	return (*big.Int)(transaction.Value)
}

func addressPointerString(address *common.Address) string {
	if address == nil || *address == (common.Address{}) {
		return ""
	}
	return address.Hex()
}

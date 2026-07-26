package chain

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/anandh8x/arcdoctor/internal/doctor"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/rpc"
)

type RPCProbe struct {
	url        string
	httpClient *http.Client
}

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
	if err := client.CallContext(ctx, &chainID, "eth_chainId"); err != nil {
		return doctor.NetworkSnapshot{}, fmt.Errorf("read chain ID: %w", err)
	}

	var blockNumber hexutil.Uint64
	if err := client.CallContext(ctx, &blockNumber, "eth_blockNumber"); err != nil {
		return doctor.NetworkSnapshot{}, fmt.Errorf("read latest block number: %w", err)
	}

	var block *struct {
		Timestamp hexutil.Uint64 `json:"timestamp"`
	}
	if err := client.CallContext(
		ctx,
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
		Latency:        time.Since(startedAt),
	}, nil
}

package doctor

import (
	"context"
	"fmt"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

const ArcTestnetChainID uint64 = 5_042_002

const ArcTestnetExplorerURL = "https://testnet.arcscan.app"

const ArcTestnetStaleBlockThreshold = 2 * time.Minute

type RequestKind string

const (
	NetworkCheck     RequestKind = "network"
	AddressCheck     RequestKind = "address"
	TransactionCheck RequestKind = "transaction"
	DeploymentCheck  RequestKind = "deployment"
)

type ABIInput struct {
	Name string
	Data []byte
}

type Request struct {
	Kind       RequestKind
	Target     string
	ABIs       []ABIInput
	Deployment *DeploymentInput
}

type NetworkSnapshot struct {
	ChainID        uint64
	BlockNumber    uint64
	BlockTimestamp time.Time
	ObservedAt     time.Time
	Latency        time.Duration
}

type NetworkEvidence struct {
	ExpectedChainID     uint64        `json:"expectedChainId"`
	ObservedChainID     uint64        `json:"observedChainId"`
	BlockNumber         uint64        `json:"blockNumber"`
	BlockTimestamp      time.Time     `json:"blockTimestamp"`
	Latency             time.Duration `json:"-"`
	LatencyMilliseconds float64       `json:"latencyMs"`
}

type AddressSnapshot struct {
	BalanceBaseUnits *big.Int
	Nonce            uint64
	Code             []byte
}

type AddressKind string

const (
	AddressKindContract        AddressKind = "contract"
	AddressKindExternallyOwned AddressKind = "externally_owned_or_empty"
)

type AddressEvidence struct {
	Address          string      `json:"address"`
	Kind             AddressKind `json:"kind"`
	BalanceBaseUnits string      `json:"balanceBaseUnits"`
	Nonce            uint64      `json:"nonce"`
	CodeSize         int         `json:"codeSize"`
	CodeHash         string      `json:"codeHash,omitempty"`
	ExplorerURL      string      `json:"explorerUrl"`
}

type Severity string

const (
	SeverityError   Severity = "error"
	SeverityWarning Severity = "warning"
	SeverityInfo    Severity = "info"
)

type Confidence string

const (
	ConfidenceCertain  Confidence = "certain"
	ConfidenceLikely   Confidence = "likely"
	ConfidencePossible Confidence = "possible"
)

type Finding struct {
	Code             string     `json:"code"`
	Severity         Severity   `json:"severity"`
	Confidence       Confidence `json:"confidence"`
	Title            string     `json:"title"`
	Explanation      string     `json:"explanation"`
	Evidence         []string   `json:"evidence"`
	SuggestedActions []string   `json:"suggestedActions,omitempty"`
}

type Report struct {
	Network     NetworkEvidence      `json:"network"`
	Address     *AddressEvidence     `json:"address,omitempty"`
	Transaction *TransactionEvidence `json:"transaction,omitempty"`
	Deployment  *DeploymentEvidence  `json:"deployment,omitempty"`
	Findings    []Finding            `json:"findings"`
}

func (r Report) HasErrors() bool {
	for _, finding := range r.Findings {
		if finding.Severity == SeverityError {
			return true
		}
	}
	return false
}

type NetworkProbe interface {
	NetworkSnapshot(context.Context) (NetworkSnapshot, error)
}

type AddressProbe interface {
	AddressSnapshot(context.Context, string) (AddressSnapshot, error)
}

type BytecodeProbe interface {
	Bytecode(context.Context, string) ([]byte, error)
}

type TransactionProbe interface {
	TransactionSnapshot(context.Context, string) (TransactionSnapshot, error)
}

type ArtifactLoader func(string) ([]byte, error)

type Doctor struct {
	network      NetworkProbe
	address      AddressProbe
	bytecode     BytecodeProbe
	transaction  TransactionProbe
	loadArtifact ArtifactLoader
}

type Option func(*Doctor)

func WithAddressProbe(address AddressProbe) Option {
	return func(instance *Doctor) {
		instance.address = address
	}
}

func WithBytecodeProbe(bytecode BytecodeProbe) Option {
	return func(instance *Doctor) {
		instance.bytecode = bytecode
	}
}

func WithTransactionProbe(transaction TransactionProbe) Option {
	return func(instance *Doctor) {
		instance.transaction = transaction
	}
}

func WithArtifactLoader(loader ArtifactLoader) Option {
	return func(instance *Doctor) {
		instance.loadArtifact = loader
	}
}

func New(network NetworkProbe, options ...Option) *Doctor {
	instance := &Doctor{network: network}
	for _, option := range options {
		option(instance)
	}
	return instance
}

func (d *Doctor) Diagnose(ctx context.Context, request Request) (Report, error) {
	switch request.Kind {
	case NetworkCheck:
		return d.diagnoseNetwork(ctx)
	case AddressCheck:
		if !common.IsHexAddress(request.Target) {
			return Report{
				Findings: []Finding{
					{
						Code:        "ARC-ADR-001",
						Severity:    SeverityError,
						Confidence:  ConfidenceCertain,
						Title:       "Address is malformed",
						Explanation: "The supplied target is not a valid 20-byte EVM address.",
						Evidence: []string{
							fmt.Sprintf("Supplied target: %q", request.Target),
						},
						SuggestedActions: []string{
							"Provide an address containing 0x followed by 40 hexadecimal characters.",
						},
					},
				},
			}, nil
		}
		return d.diagnoseAddress(ctx, common.HexToAddress(request.Target).Hex())
	case TransactionCheck:
		if len(request.Target) != 66 || !common.IsHexHash(request.Target) {
			return malformedTransactionReport(request.Target), nil
		}
		return d.diagnoseTransaction(
			ctx,
			common.HexToHash(request.Target).Hex(),
			request.ABIs,
		)
	case DeploymentCheck:
		if request.Deployment == nil {
			return Report{}, fmt.Errorf("deployment input is required")
		}
		return d.diagnoseDeployment(ctx, *request.Deployment)
	default:
		return Report{}, fmt.Errorf("unsupported diagnostic request kind %q", request.Kind)
	}
}

func (d *Doctor) diagnoseAddress(ctx context.Context, address string) (Report, error) {
	report, err := d.diagnoseNetwork(ctx)
	if err != nil || report.HasErrors() {
		return report, err
	}

	if d.address == nil {
		return Report{}, fmt.Errorf("collect address evidence: address probe is unavailable")
	}
	snapshot, err := d.address.AddressSnapshot(ctx, address)
	if err != nil {
		return Report{}, fmt.Errorf("collect address evidence: %w", err)
	}

	balance := "0"
	if snapshot.BalanceBaseUnits != nil {
		balance = snapshot.BalanceBaseUnits.String()
	}

	kind := AddressKindExternallyOwned
	codeHash := ""
	finding := Finding{
		Code:        "ARC-ADR-002",
		Severity:    SeverityInfo,
		Confidence:  ConfidenceCertain,
		Title:       "No contract bytecode found",
		Explanation: "The address has no deployed bytecode at the latest Arc Testnet block.",
		Evidence: []string{
			fmt.Sprintf("Address: %s", address),
			"Bytecode size: 0 bytes",
		},
	}
	if len(snapshot.Code) > 0 {
		kind = AddressKindContract
		codeHash = crypto.Keccak256Hash(snapshot.Code).Hex()
		finding = Finding{
			Code:        "ARC-ADR-000",
			Severity:    SeverityInfo,
			Confidence:  ConfidenceCertain,
			Title:       "Contract bytecode found",
			Explanation: "The address contains deployed bytecode at the latest Arc Testnet block.",
			Evidence: []string{
				fmt.Sprintf("Address: %s", address),
				fmt.Sprintf("Bytecode size: %d bytes", len(snapshot.Code)),
				fmt.Sprintf("Bytecode hash: %s", codeHash),
			},
		}
	}

	report.Address = &AddressEvidence{
		Address:          address,
		Kind:             kind,
		BalanceBaseUnits: balance,
		Nonce:            snapshot.Nonce,
		CodeSize:         len(snapshot.Code),
		CodeHash:         codeHash,
		ExplorerURL:      ArcTestnetExplorerURL + "/address/" + address,
	}
	report.Findings = append(report.Findings, finding)
	return report, nil
}

func (d *Doctor) diagnoseNetwork(ctx context.Context) (Report, error) {
	snapshot, err := d.network.NetworkSnapshot(ctx)
	if err != nil {
		return Report{}, fmt.Errorf("collect network evidence: %w", err)
	}

	finding := Finding{
		Code:        "ARC-NET-000",
		Severity:    SeverityInfo,
		Confidence:  ConfidenceCertain,
		Title:       "Arc Testnet connection confirmed",
		Explanation: "The RPC endpoint reported the expected Arc Testnet chain ID.",
		Evidence: []string{
			fmt.Sprintf("Expected chain ID: %d", ArcTestnetChainID),
			fmt.Sprintf("Observed chain ID: %d", snapshot.ChainID),
		},
	}

	if snapshot.ChainID != ArcTestnetChainID {
		finding = Finding{
			Code:        "ARC-NET-002",
			Severity:    SeverityError,
			Confidence:  ConfidenceCertain,
			Title:       "RPC is connected to the wrong network",
			Explanation: "The RPC endpoint reported a chain ID that does not match Arc Testnet.",
			Evidence: []string{
				fmt.Sprintf("Expected chain ID: %d", ArcTestnetChainID),
				fmt.Sprintf("Observed chain ID: %d", snapshot.ChainID),
			},
			SuggestedActions: []string{
				"Verify that the RPC URL points to Arc Testnet.",
				"Check the network configuration used by the application.",
			},
		}
	}

	findings := []Finding{finding}
	if snapshot.ChainID == ArcTestnetChainID &&
		!snapshot.ObservedAt.IsZero() &&
		snapshot.ObservedAt.Sub(snapshot.BlockTimestamp) > ArcTestnetStaleBlockThreshold {
		findings = append(findings, Finding{
			Code:        "ARC-NET-003",
			Severity:    SeverityWarning,
			Confidence:  ConfidenceCertain,
			Title:       "Latest block appears stale",
			Explanation: "The latest block timestamp is older than Arc Doctor's freshness threshold at the time of observation.",
			Evidence: []string{
				fmt.Sprintf("Latest block timestamp: %s", snapshot.BlockTimestamp.Format(time.RFC3339)),
				fmt.Sprintf("Observed at: %s", snapshot.ObservedAt.Format(time.RFC3339)),
				fmt.Sprintf("Freshness threshold: %s", ArcTestnetStaleBlockThreshold),
			},
			SuggestedActions: []string{
				"Compare the endpoint with another Arc Testnet RPC endpoint.",
				"Check the Arc Testnet service status before retrying.",
			},
		})
	}

	report := Report{
		Network: NetworkEvidence{
			ExpectedChainID:     ArcTestnetChainID,
			ObservedChainID:     snapshot.ChainID,
			BlockNumber:         snapshot.BlockNumber,
			BlockTimestamp:      snapshot.BlockTimestamp,
			Latency:             snapshot.Latency,
			LatencyMilliseconds: float64(snapshot.Latency) / float64(time.Millisecond),
		},
		Findings: findings,
	}

	return report, nil
}

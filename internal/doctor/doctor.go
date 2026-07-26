package doctor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/anandh8x/arcdoctor/internal/buildinfo"
	"github.com/anandh8x/arcdoctor/internal/redact"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

const ArcTestnetChainID uint64 = 5_042_002

const ArcTestnetExplorerURL = "https://testnet.arcscan.app"

const DefaultArcTestnetRPC = "https://rpc.testnet.arc.network"

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
	Kind          RequestKind
	Target        string
	WalletAddress string
	ABIs          []ABIInput
	Deployment    *DeploymentInput
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
	BalanceBaseUnits        *big.Int
	Nonce                   uint64
	Code                    []byte
	EIP1967Implementation   []byte
	EIP1967Beacon           []byte
	ProxyStorageUnsupported bool
	ProxyStorageError       string
}

type AddressKind string

const (
	AddressKindContract        AddressKind = "contract"
	AddressKindExternallyOwned AddressKind = "externally_owned_or_empty"
)

type AddressEvidence struct {
	Address          string         `json:"address"`
	Kind             AddressKind    `json:"kind"`
	BalanceBaseUnits string         `json:"balanceBaseUnits"`
	Nonce            uint64         `json:"nonce"`
	CodeSize         int            `json:"codeSize"`
	CodeHash         string         `json:"codeHash,omitempty"`
	ExplorerURL      string         `json:"explorerUrl"`
	Proxy            *ProxyEvidence `json:"proxy,omitempty"`
}

type ProxyStandard string

const (
	ProxyStandardEIP1167 ProxyStandard = "eip_1167"
	ProxyStandardEIP1967 ProxyStandard = "eip_1967"
)

type ProxyEvidence struct {
	Standard       ProxyStandard `json:"standard"`
	Implementation string        `json:"implementation,omitempty"`
	Beacon         string        `json:"beacon,omitempty"`
	Confidence     Confidence    `json:"confidence"`
	Basis          string        `json:"basis"`
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
	RuleVersion      string     `json:"ruleVersion"`
	Related          string     `json:"related,omitempty"`
}

type ToolEvidence struct {
	Name           string `json:"name"`
	Version        string `json:"version"`
	Commit         string `json:"commit,omitempty"`
	RulesetVersion string `json:"rulesetVersion"`
}

type Report struct {
	SchemaVersion int                  `json:"schemaVersion"`
	CollectedAt   time.Time            `json:"collectedAt"`
	Sanitized     bool                 `json:"sanitized"`
	Tool          ToolEvidence         `json:"tool"`
	Network       NetworkEvidence      `json:"network"`
	Address       *AddressEvidence     `json:"address,omitempty"`
	Transaction   *TransactionEvidence `json:"transaction,omitempty"`
	Deployment    *DeploymentEvidence  `json:"deployment,omitempty"`
	Findings      []Finding            `json:"findings"`
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
	clock        func() time.Time
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

func WithClock(clock func() time.Time) Option {
	return func(instance *Doctor) {
		instance.clock = clock
	}
}

func New(network NetworkProbe, options ...Option) *Doctor {
	instance := &Doctor{
		network: network,
		clock:   time.Now,
	}
	for _, option := range options {
		option(instance)
	}
	return instance
}

func (d *Doctor) Diagnose(ctx context.Context, request Request) (Report, error) {
	var report Report
	var err error
	switch request.Kind {
	case NetworkCheck:
		if request.WalletAddress == "" {
			report, err = d.diagnoseNetwork(ctx)
		} else {
			report, err = d.diagnoseEnvironment(ctx, request.WalletAddress)
		}
	case AddressCheck:
		address, validation := validateAddress(request.Target)
		if validation == addressMalformed {
			report = Report{
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
			}
			break
		}
		if validation == addressChecksumInvalid {
			report = Report{
				Findings: []Finding{
					{
						Code:        "ARC-ADR-005",
						Severity:    SeverityError,
						Confidence:  ConfidenceCertain,
						Title:       "Address checksum is invalid",
						Explanation: "The supplied mixed-case address does not match its EIP-55 checksum.",
						Evidence: []string{
							fmt.Sprintf("Supplied address: %q", request.Target),
							"Expected checksum: " + address,
						},
						SuggestedActions: []string{
							"Copy the checksummed address from the deployment output or ArcScan.",
						},
					},
				},
			}
			break
		}
		report, err = d.diagnoseAddress(ctx, address)
	case TransactionCheck:
		if len(request.Target) != 66 || !common.IsHexHash(request.Target) {
			report = malformedTransactionReport(request.Target)
			break
		}
		report, err = d.diagnoseTransaction(
			ctx,
			common.HexToHash(request.Target).Hex(),
			request.ABIs,
		)
	case DeploymentCheck:
		if request.Deployment == nil {
			err = fmt.Errorf("deployment input is required")
			break
		}
		report, err = d.diagnoseDeployment(ctx, *request.Deployment)
	default:
		err = fmt.Errorf("unsupported diagnostic request kind %q", request.Kind)
	}
	return d.finalizeReport(report), err
}

func (d *Doctor) finalizeReport(report Report) Report {
	report.SchemaVersion = buildinfo.ReportSchemaVersion
	report.CollectedAt = d.clock().UTC()
	report.Sanitized = true
	report.Tool = ToolEvidence{
		Name:           "Arc Doctor",
		Version:        buildinfo.Version,
		Commit:         buildinfo.Commit,
		RulesetVersion: buildinfo.RulesetVersion,
	}
	for index := range report.Findings {
		if report.Findings[index].RuleVersion == "" {
			report.Findings[index].RuleVersion = buildinfo.RulesetVersion
		}
	}
	return SanitizeReport(report)
}

func SanitizeReport(report Report) Report {
	report.Sanitized = true
	redact.Strings(&report)
	return report
}

func (d *Doctor) diagnoseAddress(ctx context.Context, address string) (Report, error) {
	report, err := d.diagnoseNetwork(ctx)
	if err != nil || report.HasErrors() {
		return report, err
	}

	evidence, findings, err := d.collectAddressEvidence(ctx, address)
	if err != nil {
		return Report{}, err
	}
	report.Address = &evidence
	report.Findings = append(report.Findings, findings...)
	return report, nil
}

func (d *Doctor) diagnoseEnvironment(
	ctx context.Context,
	walletAddress string,
) (Report, error) {
	report, err := d.diagnoseNetwork(ctx)
	if err != nil || report.HasErrors() {
		return report, err
	}
	address, validation := validateAddress(walletAddress)
	if validation == addressMalformed {
		report.Findings = append(report.Findings, Finding{
			Code:        "ARC-WAL-001",
			Severity:    SeverityError,
			Confidence:  ConfidenceCertain,
			Title:       "Wallet address is malformed",
			Explanation: "The optional wallet target is not a valid 20-byte EVM address.",
			Evidence: []string{
				fmt.Sprintf("Supplied wallet: %q", walletAddress),
			},
			SuggestedActions: []string{
				"Provide a public wallet address containing 0x followed by 40 hexadecimal characters.",
			},
		})
		return report, nil
	}
	if validation == addressChecksumInvalid {
		report.Findings = append(report.Findings, Finding{
			Code:        "ARC-WAL-003",
			Severity:    SeverityError,
			Confidence:  ConfidenceCertain,
			Title:       "Wallet checksum is invalid",
			Explanation: "The supplied mixed-case wallet address does not match its EIP-55 checksum.",
			Evidence: []string{
				fmt.Sprintf("Supplied wallet: %q", walletAddress),
				"Expected checksum: " + address,
			},
			SuggestedActions: []string{
				"Copy the checksummed public wallet address from the wallet or ArcScan.",
			},
		})
		return report, nil
	}

	evidence, addressFindings, err := d.collectAddressEvidence(ctx, address)
	if err != nil {
		return report, err
	}
	report.Address = &evidence
	report.Findings = append(report.Findings, Finding{
		Code:        "ARC-WAL-000",
		Severity:    SeverityInfo,
		Confidence:  ConfidenceCertain,
		Title:       "Wallet evidence collected",
		Explanation: "Arc Doctor read the public balance and nonce without requesting signing access.",
		Evidence: []string{
			fmt.Sprintf("Address: %s", evidence.Address),
			fmt.Sprintf("Raw native balance: %s base units", evidence.BalanceBaseUnits),
			fmt.Sprintf("Nonce: %d", evidence.Nonce),
		},
		SuggestedActions: []string{
			"Compare this raw balance with the estimated cost of the specific operation before deciding whether it is sufficient.",
		},
	})
	if evidence.CodeSize > 0 {
		report.Findings = append(report.Findings, Finding{
			Code:        "ARC-WAL-002",
			Severity:    SeverityWarning,
			Confidence:  ConfidenceCertain,
			Title:       "Wallet target contains contract bytecode",
			Explanation: "The supplied wallet target is a contract address. This may be intentional for a smart account.",
			Evidence: []string{
				fmt.Sprintf("Address: %s", evidence.Address),
				fmt.Sprintf("Bytecode size: %d bytes", evidence.CodeSize),
			},
			SuggestedActions: []string{
				"Confirm that the application is intended to use this contract-based account.",
			},
		})
	}
	report.Findings = append(report.Findings, addressFindings...)
	return report, nil
}

func (d *Doctor) collectAddressEvidence(
	ctx context.Context,
	address string,
) (AddressEvidence, []Finding, error) {
	if d.address == nil {
		return AddressEvidence{}, nil, fmt.Errorf(
			"collect address evidence: address probe is unavailable",
		)
	}
	snapshot, err := d.address.AddressSnapshot(ctx, address)
	if err != nil {
		return AddressEvidence{}, nil, fmt.Errorf("collect address evidence: %w", err)
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

	evidence := AddressEvidence{
		Address:          address,
		Kind:             kind,
		BalanceBaseUnits: balance,
		Nonce:            snapshot.Nonce,
		CodeSize:         len(snapshot.Code),
		CodeHash:         codeHash,
		ExplorerURL:      ArcTestnetExplorerURL + "/address/" + address,
	}
	findings := []Finding{finding}
	proxy, proxyFindings := detectProxy(snapshot)
	evidence.Proxy = proxy
	findings = append(findings, proxyFindings...)
	return evidence, findings, nil
}

func detectProxy(snapshot AddressSnapshot) (*ProxyEvidence, []Finding) {
	if implementation, ok := eip1167Implementation(snapshot.Code); ok {
		evidence := &ProxyEvidence{
			Standard:       ProxyStandardEIP1167,
			Implementation: implementation,
			Confidence:     ConfidenceCertain,
			Basis:          "Exact EIP-1167 minimal proxy runtime bytecode",
		}
		return evidence, []Finding{
			{
				Code:        "ARC-ADR-003",
				Severity:    SeverityInfo,
				Confidence:  ConfidenceCertain,
				Title:       "EIP-1167 minimal proxy detected",
				Explanation: "The runtime bytecode exactly matches the standard minimal proxy form and contains an implementation address.",
				Evidence: []string{
					"Proxy standard: EIP-1167",
					"Implementation address: " + implementation,
				},
				SuggestedActions: []string{
					"Inspect the implementation contract separately before drawing conclusions about behavior.",
				},
			},
		}
	}

	implementation := addressFromStorageSlot(snapshot.EIP1967Implementation)
	beacon := addressFromStorageSlot(snapshot.EIP1967Beacon)
	if implementation != "" || beacon != "" {
		evidence := &ProxyEvidence{
			Standard:       ProxyStandardEIP1967,
			Implementation: implementation,
			Beacon:         beacon,
			Confidence:     ConfidenceCertain,
			Basis:          "Non-zero standard EIP-1967 proxy storage slot",
		}
		values := []string{"Proxy standard: EIP-1967"}
		if implementation != "" {
			values = append(values, "Implementation address: "+implementation)
		}
		if beacon != "" {
			values = append(values, "Beacon address: "+beacon)
		}
		return evidence, []Finding{
			{
				Code:        "ARC-ADR-004",
				Severity:    SeverityInfo,
				Confidence:  ConfidenceCertain,
				Title:       "EIP-1967 proxy storage detected",
				Explanation: "A standard EIP-1967 implementation or beacon slot contains a non-zero address.",
				Evidence:    values,
				SuggestedActions: []string{
					"Inspect the implementation or beacon contract separately before drawing conclusions about behavior.",
				},
			},
		}
	}

	if snapshot.ProxyStorageError != "" {
		code := "ARC-RPC-003"
		title := "Proxy storage inspection failed"
		explanation := "Arc Doctor retained the core address evidence, but the optional proxy storage request failed."
		if snapshot.ProxyStorageUnsupported {
			code = "ARC-RPC-002"
			title = "RPC does not support proxy storage inspection"
			explanation = "Arc Doctor retained the core address evidence, but the endpoint reported that the optional storage method is unsupported."
		}
		return nil, []Finding{
			{
				Code:        code,
				Severity:    SeverityWarning,
				Confidence:  ConfidenceCertain,
				Title:       title,
				Explanation: explanation,
				Evidence: []string{
					"RPC detail: " + snapshot.ProxyStorageError,
				},
				SuggestedActions: []string{
					"Use another Arc Testnet RPC endpoint if proxy storage evidence is required.",
				},
			},
		}
	}
	return nil, nil
}

func eip1167Implementation(code []byte) (string, bool) {
	prefix := []byte{
		0x36, 0x3d, 0x3d, 0x37, 0x3d, 0x3d, 0x3d, 0x36, 0x3d, 0x73,
	}
	suffix := []byte{
		0x5a, 0xf4, 0x3d, 0x82, 0x80, 0x3e, 0x90, 0x3d,
		0x91, 0x60, 0x2b, 0x57, 0xfd, 0x5b, 0xf3,
	}
	if len(code) != len(prefix)+common.AddressLength+len(suffix) ||
		!bytes.Equal(code[:len(prefix)], prefix) ||
		!bytes.Equal(code[len(prefix)+common.AddressLength:], suffix) {
		return "", false
	}
	implementation := common.BytesToAddress(
		code[len(prefix) : len(prefix)+common.AddressLength],
	)
	if implementation == (common.Address{}) {
		return "", false
	}
	return implementation.Hex(), true
}

func addressFromStorageSlot(slot []byte) string {
	if len(slot) != common.HashLength {
		return ""
	}
	address := common.BytesToAddress(slot[common.HashLength-common.AddressLength:])
	if address == (common.Address{}) {
		return ""
	}
	return address.Hex()
}

func (d *Doctor) diagnoseNetwork(ctx context.Context) (Report, error) {
	snapshot, err := d.network.NetworkSnapshot(ctx)
	if err != nil {
		report := Report{
			Network: networkEvidence(snapshot),
		}
		if errors.Is(err, context.Canceled) &&
			!errors.Is(err, context.DeadlineExceeded) {
			return report, fmt.Errorf("collect network evidence: %w", err)
		}
		report.Findings = []Finding{rpcFailureFinding(err)}
		return report, nil
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
		Network:  networkEvidence(snapshot),
		Findings: findings,
	}

	return report, nil
}

func networkEvidence(snapshot NetworkSnapshot) NetworkEvidence {
	return NetworkEvidence{
		ExpectedChainID:     ArcTestnetChainID,
		ObservedChainID:     snapshot.ChainID,
		BlockNumber:         snapshot.BlockNumber,
		BlockTimestamp:      snapshot.BlockTimestamp,
		Latency:             snapshot.Latency,
		LatencyMilliseconds: float64(snapshot.Latency) / float64(time.Millisecond),
	}
}

func rpcFailureFinding(err error) Finding {
	code := "ARC-NET-001"
	title := "Arc Testnet RPC is unavailable"
	explanation := "Arc Doctor could not collect the required Arc Testnet evidence from the endpoint."
	method := "unknown"

	var operationError *RPCOperationError
	if errors.As(err, &operationError) {
		if operationError.Method != "" {
			method = operationError.Method
		}
		switch operationError.Kind {
		case RPCErrorUnsupported:
			code = "ARC-RPC-004"
			title = "Required RPC method is unsupported"
			explanation = "The endpoint reported that a method required for this diagnosis is unsupported."
		case RPCErrorRequestFailed:
			code = "ARC-RPC-005"
			title = "Required RPC request failed"
			explanation = "The endpoint responded, but Arc Doctor could not collect all required network evidence."
		}
	}

	return Finding{
		Code:        code,
		Severity:    SeverityError,
		Confidence:  ConfidenceCertain,
		Title:       title,
		Explanation: explanation,
		Evidence: []string{
			"RPC method: " + method,
			"RPC detail: " + err.Error(),
		},
		SuggestedActions: []string{
			"Verify the RPC URL and retry the read-only check.",
			"Compare the endpoint with another Arc Testnet RPC endpoint.",
		},
	}
}

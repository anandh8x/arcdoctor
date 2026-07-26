package doctor

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

const (
	maxManifestBytes = 1 << 20
	maxArtifactBytes = 10 << 20
)

type DeploymentInput struct {
	Name      string
	BaseDir   string
	Data      []byte
	Artifacts map[string]string
}

type ArtifactComparison string

const (
	ArtifactComparisonNotProvided ArtifactComparison = "not_provided"
	ArtifactComparisonExact       ArtifactComparison = "exact"
	ArtifactComparisonNormalized  ArtifactComparison = "normalized_match"
	ArtifactComparisonMismatch    ArtifactComparison = "mismatch"
	ArtifactComparisonUnavailable ArtifactComparison = "unavailable"
)

type DeploymentContractEvidence struct {
	Name                    string             `json:"name"`
	Address                 string             `json:"address,omitempty"`
	TransactionHash         string             `json:"transactionHash,omitempty"`
	AddressExplorerURL      string             `json:"addressExplorerUrl,omitempty"`
	TransactionExplorerURL  string             `json:"transactionExplorerUrl,omitempty"`
	CodeSize                int                `json:"codeSize"`
	CodeHash                string             `json:"codeHash,omitempty"`
	Artifact                string             `json:"artifact,omitempty"`
	ArtifactComparison      ArtifactComparison `json:"artifactComparison"`
	ArtifactRuntimeCodeHash string             `json:"artifactRuntimeCodeHash,omitempty"`
}

type DeploymentEvidence struct {
	ManifestName  string                       `json:"manifestName"`
	Format        string                       `json:"format"`
	SchemaVersion int                          `json:"schemaVersion"`
	Network       string                       `json:"network"`
	ChainID       uint64                       `json:"chainId"`
	Contracts     []DeploymentContractEvidence `json:"contracts"`
}

type deploymentContract struct {
	Name            string
	Address         string
	TransactionHash string
	Artifact        string
}

type deploymentManifest struct {
	Format        string
	SchemaVersion int
	Network       string
	ChainID       uint64
	RPCURL        string
	Contracts     []deploymentContract
}

type arcDoctorManifest struct {
	SchemaVersion int                         `json:"schemaVersion"`
	Network       string                      `json:"network"`
	ChainID       uint64                      `json:"chainId"`
	RPCURL        string                      `json:"rpcUrl"`
	Contracts     map[string]manifestContract `json:"contracts"`
}

type manifestContract struct {
	Address         string `json:"address"`
	TransactionHash string `json:"transactionHash"`
	Artifact        string `json:"artifact"`
}

type foundryBroadcast struct {
	Chain        json.RawMessage      `json:"chain"`
	Transactions []foundryTransaction `json:"transactions"`
}

type foundryTransaction struct {
	Hash            string `json:"hash"`
	TransactionType string `json:"transactionType"`
	ContractName    string `json:"contractName"`
	ContractAddress string `json:"contractAddress"`
}

var contractNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]{0,127}$`)

var familiarLocalAddresses = map[string]struct{}{
	"0x5fbdb2315678afecb367f032d93f642f64180aa3": {},
	"0xe7f1725e7734ce288f8367e1bb143e90bb3f0512": {},
	"0x9fe46736679d2d9a65f0992f2272de9f3c7fa6e0": {},
	"0xcf7ed3acca5a467e9e704c703e8d87f634fb0fc9": {},
	"0xdc64a140aa3e981100a9beca4e685f962f0cf6c9": {},
}

func (d *Doctor) diagnoseDeployment(
	ctx context.Context,
	input DeploymentInput,
) (Report, error) {
	manifest, manifestFindings := parseDeploymentManifest(input)
	if manifest == nil {
		return Report{Findings: manifestFindings}, nil
	}

	report, err := d.diagnoseNetwork(ctx)
	if err != nil || report.HasErrors() {
		return report, err
	}
	report.Deployment = &DeploymentEvidence{
		ManifestName:  input.Name,
		Format:        manifest.Format,
		SchemaVersion: manifest.SchemaVersion,
		Network:       manifest.Network,
		ChainID:       manifest.ChainID,
		Contracts:     make([]DeploymentContractEvidence, 0, len(manifest.Contracts)),
	}
	report.Findings = append(report.Findings, manifestFindings...)

	if manifest.SchemaVersion != 1 {
		report.Findings = append(report.Findings, Finding{
			Code:        "ARC-DEP-002",
			Severity:    SeverityError,
			Confidence:  ConfidenceCertain,
			Title:       "Deployment schema version is unsupported",
			Explanation: "Arc Doctor supports deployment schema version 1.",
			Evidence: []string{
				fmt.Sprintf("Manifest schema version: %d", manifest.SchemaVersion),
			},
			SuggestedActions: []string{
				"Convert the deployment manifest to schema version 1.",
			},
		})
	}
	if manifest.ChainID != ArcTestnetChainID {
		report.Findings = append(report.Findings, Finding{
			Code:        "ARC-DEP-003",
			Severity:    SeverityError,
			Confidence:  ConfidenceCertain,
			Title:       "Deployment manifest targets a different chain",
			Explanation: "The manifest chain ID does not match Arc Testnet.",
			Evidence: []string{
				fmt.Sprintf("Expected chain ID: %d", ArcTestnetChainID),
				fmt.Sprintf("Manifest chain ID: %d", manifest.ChainID),
			},
			SuggestedActions: []string{
				"Use the Arc Testnet deployment output rather than a local Anvil deployment.",
			},
		})
	}
	if manifest.Network != "" && !strings.EqualFold(manifest.Network, "Arc Testnet") {
		report.Findings = append(report.Findings, Finding{
			Code:        "ARC-DEP-004",
			Severity:    SeverityWarning,
			Confidence:  ConfidenceCertain,
			Title:       "Deployment network label is unexpected",
			Explanation: "The label differs from Arc Testnet, although the chain ID remains the authoritative network evidence.",
			Evidence: []string{
				"Manifest network label: " + manifest.Network,
			},
			SuggestedActions: []string{
				"Verify that the manifest was generated for Arc Testnet.",
			},
		})
	}
	if looksLocalRPC(manifest.RPCURL) {
		report.Findings = append(report.Findings, Finding{
			Code:        "ARC-CFG-001",
			Severity:    SeverityWarning,
			Confidence:  ConfidenceCertain,
			Title:       "Manifest contains a local RPC URL",
			Explanation: "The active RPC is Arc Testnet, but the deployment manifest records a local endpoint.",
			Evidence: []string{
				"Manifest RPC host is local",
			},
			SuggestedActions: []string{
				"Regenerate or update the manifest from the Arc Testnet deployment.",
			},
		})
	}

	seenAddresses := make(map[string]string)
	for _, contract := range manifest.Contracts {
		evidence, findings, diagnoseErr := d.diagnoseDeploymentContract(
			ctx,
			input,
			contract,
			seenAddresses,
		)
		if diagnoseErr != nil {
			return report, diagnoseErr
		}
		report.Deployment.Contracts = append(report.Deployment.Contracts, evidence)
		report.Findings = append(report.Findings, findings...)
	}

	if !report.HasErrors() {
		report.Findings = append(report.Findings, Finding{
			Code:        "ARC-DEP-000",
			Severity:    SeverityInfo,
			Confidence:  ConfidenceCertain,
			Title:       "Deployment validation completed",
			Explanation: "The manifest chain metadata and all configured contract addresses passed the requested checks.",
			Evidence: []string{
				fmt.Sprintf("Validated contracts: %d", len(report.Deployment.Contracts)),
				fmt.Sprintf("Manifest format: %s", manifest.Format),
			},
		})
	}
	return report, nil
}

func (d *Doctor) diagnoseDeploymentContract(
	ctx context.Context,
	input DeploymentInput,
	contract deploymentContract,
	seenAddresses map[string]string,
) (DeploymentContractEvidence, []Finding, error) {
	evidence := DeploymentContractEvidence{
		Name:               contract.Name,
		Address:            contract.Address,
		TransactionHash:    contract.TransactionHash,
		Artifact:           contract.Artifact,
		ArtifactComparison: ArtifactComparisonNotProvided,
	}
	findings := make([]Finding, 0)

	if !contractNamePattern.MatchString(contract.Name) {
		findings = append(findings, Finding{
			Code:        "ARC-DEP-005",
			Severity:    SeverityError,
			Confidence:  ConfidenceCertain,
			Title:       "Contract name is invalid",
			Explanation: "Contract names must be non-empty identifiers suitable for deterministic reporting.",
			Evidence: []string{
				fmt.Sprintf("Contract name: %q", contract.Name),
			},
		})
	}
	if !common.IsHexAddress(contract.Address) {
		findings = append(findings, Finding{
			Code:        "ARC-DEP-005",
			Severity:    SeverityError,
			Confidence:  ConfidenceCertain,
			Title:       "Deployment contract address is malformed",
			Explanation: "The configured address is not a valid 20-byte EVM address.",
			Evidence: []string{
				fmt.Sprintf("Contract: %s", contract.Name),
				fmt.Sprintf("Configured address: %q", contract.Address),
			},
		})
		return evidence, findings, nil
	}

	address := common.HexToAddress(contract.Address).Hex()
	evidence.Address = address
	evidence.AddressExplorerURL = ArcTestnetExplorerURL + "/address/" + address
	lowerAddress := strings.ToLower(address)
	if previous, exists := seenAddresses[lowerAddress]; exists {
		findings = append(findings, Finding{
			Code:        "ARC-DEP-005",
			Severity:    SeverityError,
			Confidence:  ConfidenceCertain,
			Title:       "Deployment manifest contains a duplicate address",
			Explanation: "Two contract entries resolve to the same EVM address.",
			Evidence: []string{
				fmt.Sprintf("Address: %s", address),
				fmt.Sprintf("First contract: %s", previous),
				fmt.Sprintf("Duplicate contract: %s", contract.Name),
			},
			SuggestedActions: []string{
				"Verify each contract address in the deployment output.",
			},
		})
	} else {
		seenAddresses[lowerAddress] = contract.Name
	}
	if _, suspicious := familiarLocalAddresses[lowerAddress]; suspicious {
		findings = append(findings, Finding{
			Code:        "ARC-DEP-016",
			Severity:    SeverityWarning,
			Confidence:  ConfidenceLikely,
			Title:       "Address resembles a familiar local deployment",
			Explanation: "This address is commonly produced by deterministic Anvil or Hardhat development deployments. The address is not automatically invalid.",
			Evidence: []string{
				fmt.Sprintf("Contract: %s", contract.Name),
				fmt.Sprintf("Address: %s", address),
			},
			SuggestedActions: []string{
				"Confirm that this address came from an Arc Testnet deployment.",
			},
		})
	}

	if d.bytecode == nil && d.address == nil {
		return evidence, findings, fmt.Errorf(
			"validate deployment contract %s: bytecode probe is unavailable",
			contract.Name,
		)
	}
	var code []byte
	var err error
	if d.bytecode != nil {
		code, err = d.bytecode.Bytecode(ctx, address)
	} else {
		var snapshot AddressSnapshot
		snapshot, err = d.address.AddressSnapshot(ctx, address)
		code = snapshot.Code
	}
	if err != nil {
		return evidence, findings, fmt.Errorf(
			"validate deployment contract %s: %w",
			contract.Name,
			err,
		)
	}
	evidence.CodeSize = len(code)
	if len(code) == 0 {
		findings = append(findings, Finding{
			Code:        "ARC-DEP-006",
			Severity:    SeverityError,
			Confidence:  ConfidenceCertain,
			Title:       "Configured contract address has no bytecode",
			Explanation: "Arc Testnet returned empty runtime bytecode for the configured address.",
			Evidence: []string{
				fmt.Sprintf("Contract: %s", contract.Name),
				fmt.Sprintf("Address: %s", address),
				"Bytecode size: 0 bytes",
			},
			SuggestedActions: []string{
				"Verify that the contract was deployed on Arc Testnet.",
				"Check whether this address came from a local Anvil deployment.",
			},
		})
	} else {
		evidence.CodeHash = crypto.Keccak256Hash(code).Hex()
		findings = append(findings, Finding{
			Code:        "ARC-DEP-007",
			Severity:    SeverityInfo,
			Confidence:  ConfidenceCertain,
			Title:       "Configured contract bytecode found",
			Explanation: "Arc Testnet returned non-empty runtime bytecode at the configured address.",
			Evidence: []string{
				fmt.Sprintf("Contract: %s", contract.Name),
				fmt.Sprintf("Bytecode size: %d bytes", len(code)),
				fmt.Sprintf("Bytecode hash: %s", evidence.CodeHash),
			},
		})
	}

	transactionFindings, transactionErr := d.validateDeploymentTransaction(
		ctx,
		contract,
		address,
		&evidence,
	)
	if transactionErr != nil {
		return evidence, findings, transactionErr
	}
	findings = append(findings, transactionFindings...)

	artifactFindings := d.compareDeploymentArtifact(
		input,
		contract,
		code,
		&evidence,
	)
	findings = append(findings, artifactFindings...)
	return evidence, findings, nil
}

func (d *Doctor) validateDeploymentTransaction(
	ctx context.Context,
	contract deploymentContract,
	address string,
	evidence *DeploymentContractEvidence,
) ([]Finding, error) {
	if contract.TransactionHash == "" {
		return nil, nil
	}
	if len(contract.TransactionHash) != 66 || !common.IsHexHash(contract.TransactionHash) {
		return []Finding{
			{
				Code:        "ARC-DEP-008",
				Severity:    SeverityError,
				Confidence:  ConfidenceCertain,
				Title:       "Deployment transaction hash is malformed",
				Explanation: "The configured deployment transaction is not a valid 32-byte hash.",
				Evidence: []string{
					fmt.Sprintf("Contract: %s", contract.Name),
					fmt.Sprintf("Transaction hash: %q", contract.TransactionHash),
				},
			},
		}, nil
	}
	hash := common.HexToHash(contract.TransactionHash).Hex()
	evidence.TransactionHash = hash
	evidence.TransactionExplorerURL = ArcTestnetExplorerURL + "/tx/" + hash
	if d.transaction == nil {
		return nil, fmt.Errorf(
			"validate deployment transaction %s: transaction probe is unavailable",
			contract.Name,
		)
	}
	snapshot, err := d.transaction.TransactionSnapshot(ctx, hash)
	if err != nil {
		return nil, fmt.Errorf(
			"validate deployment transaction %s: %w",
			contract.Name,
			err,
		)
	}
	if !snapshot.Found {
		return []Finding{
			{
				Code:        "ARC-DEP-008",
				Severity:    SeverityError,
				Confidence:  ConfidenceCertain,
				Title:       "Deployment transaction was not found",
				Explanation: "Arc Testnet returned no transaction for the configured deployment hash.",
				Evidence: []string{
					fmt.Sprintf("Contract: %s", contract.Name),
					fmt.Sprintf("Transaction hash: %s", hash),
				},
			},
		}, nil
	}
	if snapshot.Receipt == nil {
		return []Finding{
			{
				Code:        "ARC-DEP-008",
				Severity:    SeverityWarning,
				Confidence:  ConfidenceCertain,
				Title:       "Deployment transaction is pending",
				Explanation: "The configured transaction does not have a receipt yet.",
				Evidence: []string{
					fmt.Sprintf("Contract: %s", contract.Name),
					fmt.Sprintf("Transaction hash: %s", hash),
				},
			},
		}, nil
	}
	if snapshot.Receipt.Status != 1 {
		return []Finding{
			{
				Code:        "ARC-DEP-008",
				Severity:    SeverityError,
				Confidence:  ConfidenceCertain,
				Title:       "Deployment transaction reverted",
				Explanation: "The configured transaction receipt reports a failed execution status.",
				Evidence: []string{
					fmt.Sprintf("Contract: %s", contract.Name),
					fmt.Sprintf("Transaction hash: %s", hash),
				},
			},
		}, nil
	}

	findings := []Finding{
		{
			Code:        "ARC-DEP-009",
			Severity:    SeverityInfo,
			Confidence:  ConfidenceCertain,
			Title:       "Deployment transaction succeeded",
			Explanation: "The configured transaction receipt reports successful execution.",
			Evidence: []string{
				fmt.Sprintf("Contract: %s", contract.Name),
				fmt.Sprintf("Transaction hash: %s", hash),
			},
		},
	}
	if snapshot.Receipt.ContractAddress != "" &&
		!strings.EqualFold(snapshot.Receipt.ContractAddress, address) {
		findings = append(findings, Finding{
			Code:        "ARC-DEP-010",
			Severity:    SeverityError,
			Confidence:  ConfidenceCertain,
			Title:       "Deployment receipt created a different address",
			Explanation: "The contract address in the receipt does not match the manifest.",
			Evidence: []string{
				fmt.Sprintf("Contract: %s", contract.Name),
				fmt.Sprintf("Manifest address: %s", address),
				fmt.Sprintf("Receipt address: %s", snapshot.Receipt.ContractAddress),
			},
			SuggestedActions: []string{
				"Update the manifest from the deployment receipt.",
			},
		})
	}
	return findings, nil
}

func (d *Doctor) compareDeploymentArtifact(
	input DeploymentInput,
	contract deploymentContract,
	deployedCode []byte,
	evidence *DeploymentContractEvidence,
) []Finding {
	artifactRef := contract.Artifact
	if override, ok := input.Artifacts[contract.Name]; ok {
		artifactRef = override
		evidence.Artifact = filepath.Base(override)
	}
	if artifactRef == "" {
		return nil
	}
	if evidence.Artifact == "" {
		evidence.Artifact = artifactRef
	}
	if d.loadArtifact == nil {
		evidence.ArtifactComparison = ArtifactComparisonUnavailable
		return []Finding{artifactUnavailableFinding(
			contract.Name,
			evidence.Artifact,
			"artifact loader is unavailable",
		)}
	}

	path := artifactRef
	if !filepath.IsAbs(path) {
		path = filepath.Join(input.BaseDir, path)
	}
	data, err := d.loadArtifact(filepath.Clean(path))
	if err != nil {
		evidence.ArtifactComparison = ArtifactComparisonUnavailable
		return []Finding{artifactUnavailableFinding(
			contract.Name,
			evidence.Artifact,
			"referenced file could not be read",
		)}
	}
	if len(data) > maxArtifactBytes {
		evidence.ArtifactComparison = ArtifactComparisonUnavailable
		return []Finding{artifactUnavailableFinding(
			contract.Name,
			evidence.Artifact,
			fmt.Sprintf("artifact exceeds %d bytes", maxArtifactBytes),
		)}
	}

	artifact, err := parseRuntimeArtifact(data)
	if err != nil {
		evidence.ArtifactComparison = ArtifactComparisonUnavailable
		return []Finding{artifactUnavailableFinding(
			contract.Name,
			evidence.Artifact,
			err.Error(),
		)}
	}
	evidence.ArtifactRuntimeCodeHash = crypto.Keccak256Hash(artifact.Code).Hex()
	comparison := compareRuntimeBytecode(artifact, deployedCode)
	evidence.ArtifactComparison = comparison

	switch comparison {
	case ArtifactComparisonExact:
		return []Finding{
			{
				Code:        "ARC-DEP-013",
				Severity:    SeverityInfo,
				Confidence:  ConfidenceCertain,
				Title:       "Artifact runtime bytecode matches exactly",
				Explanation: "The artifact and Arc Testnet runtime bytecode are byte-for-byte identical.",
				Evidence: []string{
					fmt.Sprintf("Contract: %s", contract.Name),
					fmt.Sprintf("Artifact: %s", evidence.Artifact),
					fmt.Sprintf("Runtime bytecode hash: %s", evidence.CodeHash),
				},
			},
		}
	case ArtifactComparisonNormalized:
		return []Finding{
			{
				Code:        "ARC-DEP-014",
				Severity:    SeverityInfo,
				Confidence:  ConfidenceLikely,
				Title:       "Artifact runtime bytecode matches after normalization",
				Explanation: "The executable portions match after excluding Solidity metadata and declared immutable or library slots.",
				Evidence: []string{
					fmt.Sprintf("Contract: %s", contract.Name),
					fmt.Sprintf("Artifact: %s", evidence.Artifact),
				},
			},
		}
	default:
		return []Finding{
			{
				Code:        "ARC-DEP-015",
				Severity:    SeverityError,
				Confidence:  ConfidenceCertain,
				Title:       "Artifact runtime bytecode does not match",
				Explanation: "The deployed and artifact runtime bytecode differ after supported normalization.",
				Evidence: []string{
					fmt.Sprintf("Contract: %s", contract.Name),
					fmt.Sprintf("Artifact runtime hash: %s", evidence.ArtifactRuntimeCodeHash),
					fmt.Sprintf("Deployed runtime hash: %s", evidence.CodeHash),
				},
				SuggestedActions: []string{
					"Verify the compiler settings, linked libraries, constructor immutables, and deployment address.",
				},
			},
		}
	}
}

func artifactUnavailableFinding(contractName, artifactRef, detail string) Finding {
	return Finding{
		Code:        "ARC-DEP-012",
		Severity:    SeverityWarning,
		Confidence:  ConfidenceCertain,
		Title:       "Artifact could not be compared",
		Explanation: "Deployment validation continued without an artifact bytecode comparison.",
		Evidence: []string{
			fmt.Sprintf("Contract: %s", contractName),
			fmt.Sprintf("Artifact: %s", artifactRef),
			fmt.Sprintf("Detail: %s", detail),
		},
		SuggestedActions: []string{
			"Provide a readable Foundry artifact containing deployedBytecode.object.",
		},
	}
}

func parseDeploymentManifest(input DeploymentInput) (*deploymentManifest, []Finding) {
	if len(input.Data) == 0 {
		return nil, []Finding{invalidManifestFinding(input.Name, "manifest is empty")}
	}
	if len(input.Data) > maxManifestBytes {
		return nil, []Finding{invalidManifestFinding(
			input.Name,
			fmt.Sprintf("manifest exceeds %d bytes", maxManifestBytes),
		)}
	}

	var shape map[string]json.RawMessage
	if err := json.Unmarshal(input.Data, &shape); err != nil {
		return nil, []Finding{invalidManifestFinding(
			input.Name,
			"invalid JSON: "+err.Error(),
		)}
	}
	if _, isFoundry := shape["transactions"]; isFoundry {
		manifest, err := parseFoundryBroadcast(input.Data)
		if err != nil {
			return nil, []Finding{invalidManifestFinding(input.Name, err.Error())}
		}
		applyArtifactOverrides(manifest, input.Artifacts)
		return manifest, nil
	}

	var source arcDoctorManifest
	if err := json.Unmarshal(input.Data, &source); err != nil {
		return nil, []Finding{invalidManifestFinding(input.Name, err.Error())}
	}
	if len(source.Contracts) == 0 {
		return nil, []Finding{invalidManifestFinding(
			input.Name,
			"manifest contains no contracts",
		)}
	}
	names := make([]string, 0, len(source.Contracts))
	for name := range source.Contracts {
		names = append(names, name)
	}
	sort.Strings(names)
	contracts := make([]deploymentContract, 0, len(names))
	for _, name := range names {
		sourceContract := source.Contracts[name]
		contracts = append(contracts, deploymentContract{
			Name:            name,
			Address:         sourceContract.Address,
			TransactionHash: sourceContract.TransactionHash,
			Artifact:        sourceContract.Artifact,
		})
	}
	manifest := &deploymentManifest{
		Format:        "arcdoctor",
		SchemaVersion: source.SchemaVersion,
		Network:       source.Network,
		ChainID:       source.ChainID,
		RPCURL:        source.RPCURL,
		Contracts:     contracts,
	}
	applyArtifactOverrides(manifest, input.Artifacts)
	return manifest, nil
}

func parseFoundryBroadcast(data []byte) (*deploymentManifest, error) {
	var source foundryBroadcast
	if err := json.Unmarshal(data, &source); err != nil {
		return nil, fmt.Errorf("decode Foundry broadcast: %w", err)
	}
	chainID, err := parseFlexibleUint(source.Chain)
	if err != nil {
		return nil, fmt.Errorf("decode Foundry chain ID: %w", err)
	}
	contracts := make([]deploymentContract, 0)
	for index, transaction := range source.Transactions {
		if transaction.ContractAddress == "" {
			continue
		}
		name := transaction.ContractName
		if name == "" {
			name = fmt.Sprintf("Contract%d", index+1)
		}
		contracts = append(contracts, deploymentContract{
			Name:            name,
			Address:         transaction.ContractAddress,
			TransactionHash: transaction.Hash,
		})
	}
	if len(contracts) == 0 {
		return nil, fmt.Errorf("Foundry broadcast contains no contract deployments")
	}
	sort.SliceStable(contracts, func(left, right int) bool {
		if contracts[left].Name == contracts[right].Name {
			return contracts[left].Address < contracts[right].Address
		}
		return contracts[left].Name < contracts[right].Name
	})
	return &deploymentManifest{
		Format:        "foundry-broadcast",
		SchemaVersion: 1,
		Network:       "Arc Testnet",
		ChainID:       chainID,
		Contracts:     contracts,
	}, nil
}

func parseFlexibleUint(raw json.RawMessage) (uint64, error) {
	if len(raw) == 0 {
		return 0, fmt.Errorf("chain field is missing")
	}
	var number uint64
	if err := json.Unmarshal(raw, &number); err == nil {
		return number, nil
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return 0, fmt.Errorf("chain field must be a number or string")
	}
	base := 10
	if strings.HasPrefix(strings.ToLower(value), "0x") {
		base = 16
		value = value[2:]
	}
	number, err := strconv.ParseUint(value, base, 64)
	if err != nil {
		return 0, err
	}
	return number, nil
}

func applyArtifactOverrides(manifest *deploymentManifest, overrides map[string]string) {
	for index := range manifest.Contracts {
		if artifact, ok := overrides[manifest.Contracts[index].Name]; ok {
			manifest.Contracts[index].Artifact = artifact
		}
	}
}

func invalidManifestFinding(name, detail string) Finding {
	return Finding{
		Code:        "ARC-DEP-001",
		Severity:    SeverityError,
		Confidence:  ConfidenceCertain,
		Title:       "Deployment manifest is invalid",
		Explanation: "Arc Doctor could not interpret the supplied deployment manifest.",
		Evidence: []string{
			fmt.Sprintf("Manifest: %s", name),
			fmt.Sprintf("Detail: %s", detail),
		},
		SuggestedActions: []string{
			"Provide an Arc Doctor schema version 1 manifest or a Foundry broadcast JSON file.",
		},
	}
}

func looksLocalRPC(value string) bool {
	lower := strings.ToLower(value)
	return strings.Contains(lower, "localhost") ||
		strings.Contains(lower, "127.0.0.1") ||
		strings.Contains(lower, "[::1]")
}

type bytecodeReference struct {
	Start  int `json:"start"`
	Length int `json:"length"`
}

type runtimeArtifact struct {
	Code       []byte
	References []bytecodeReference
}

func parseRuntimeArtifact(data []byte) (runtimeArtifact, error) {
	var source struct {
		DeployedBytecode struct {
			Object              string                                    `json:"object"`
			ImmutableReferences map[string][]bytecodeReference            `json:"immutableReferences"`
			LinkReferences      map[string]map[string][]bytecodeReference `json:"linkReferences"`
		} `json:"deployedBytecode"`
	}
	if err := json.Unmarshal(data, &source); err != nil {
		return runtimeArtifact{}, fmt.Errorf("decode artifact JSON: %w", err)
	}
	object := strings.TrimPrefix(source.DeployedBytecode.Object, "0x")
	if object == "" {
		return runtimeArtifact{}, fmt.Errorf("artifact does not contain deployedBytecode.object")
	}
	code, err := hex.DecodeString(object)
	if err != nil {
		return runtimeArtifact{}, fmt.Errorf("decode deployed runtime bytecode: %w", err)
	}
	references := make([]bytecodeReference, 0)
	for _, values := range source.DeployedBytecode.ImmutableReferences {
		references = append(references, values...)
	}
	for _, fileReferences := range source.DeployedBytecode.LinkReferences {
		for _, values := range fileReferences {
			references = append(references, values...)
		}
	}
	sort.Slice(references, func(left, right int) bool {
		if references[left].Start == references[right].Start {
			return references[left].Length < references[right].Length
		}
		return references[left].Start < references[right].Start
	})
	for _, reference := range references {
		if reference.Start < 0 ||
			reference.Length < 0 ||
			reference.Start+reference.Length > len(code) {
			return runtimeArtifact{}, fmt.Errorf(
				"bytecode reference %d:%d is outside runtime code",
				reference.Start,
				reference.Length,
			)
		}
	}
	return runtimeArtifact{
		Code:       code,
		References: references,
	}, nil
}

func compareRuntimeBytecode(
	artifact runtimeArtifact,
	deployed []byte,
) ArtifactComparison {
	if bytes.Equal(artifact.Code, deployed) {
		return ArtifactComparisonExact
	}

	local := append([]byte(nil), artifact.Code...)
	remote := append([]byte(nil), deployed...)
	for _, reference := range artifact.References {
		if reference.Start+reference.Length > len(remote) {
			return ArtifactComparisonMismatch
		}
		clear(local[reference.Start : reference.Start+reference.Length])
		clear(remote[reference.Start : reference.Start+reference.Length])
	}
	local = stripSolidityMetadata(local)
	remote = stripSolidityMetadata(remote)
	if bytes.Equal(local, remote) {
		return ArtifactComparisonNormalized
	}
	return ArtifactComparisonMismatch
}

func stripSolidityMetadata(code []byte) []byte {
	if len(code) < 2 {
		return code
	}
	metadataLength := int(binary.BigEndian.Uint16(code[len(code)-2:]))
	start := len(code) - metadataLength - 2
	if metadataLength == 0 || start < 0 {
		return code
	}
	return code[:start]
}

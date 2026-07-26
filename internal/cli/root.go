package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/anandh8x/arcdoctor/internal/buildinfo"
	"github.com/anandh8x/arcdoctor/internal/doctor"
	"github.com/anandh8x/arcdoctor/internal/jsonlimit"
	"github.com/anandh8x/arcdoctor/internal/localfile"
	"github.com/ethereum/go-ethereum/common"
	"github.com/spf13/cobra"
)

const DefaultArcTestnetRPC = doctor.DefaultArcTestnetRPC

const maxManifestInputBytes = 1 << 20

const maxReportInputBytes = 16 << 20

const maxABIInputBytes = 10 << 20

var ErrDiagnosticFindings = errors.New("diagnostic errors found")

type Diagnoser interface {
	Diagnose(context.Context, doctor.Request) (doctor.Report, error)
}

type DiagnoserFactory func(rpcURL string) Diagnoser

func NewRootCommand(factory DiagnoserFactory) *cobra.Command {
	root := &cobra.Command{
		Use:           "arcdoctor",
		Short:         "Evidence-based diagnostics for Arc Testnet",
		Version:       buildinfo.Version,
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(command *cobra.Command, _ []string) error {
			return command.Help()
		},
	}
	root.SetVersionTemplate("Arc Doctor {{.Version}}\n")

	var (
		rpcURL        string
		asJSON        bool
		timeout       time.Duration
		walletAddress string
	)

	check := &cobra.Command{
		Use:   "check",
		Short: "Check the Arc Testnet network connection",
		RunE: func(command *cobra.Command, _ []string) error {
			ctx, cancel := context.WithTimeout(command.Context(), timeout)
			defer cancel()

			report, err := factory(rpcURL).Diagnose(ctx, doctor.Request{
				Kind:          doctor.NetworkCheck,
				WalletAddress: walletAddress,
			})
			if err != nil {
				return err
			}
			return writeReport(command.OutOrStdout(), report, asJSON)
		},
	}
	check.Flags().StringVar(&rpcURL, "rpc", DefaultArcTestnetRPC, "Arc JSON-RPC endpoint")
	check.Flags().StringVar(
		&walletAddress,
		"address",
		"",
		"optional public wallet address to inspect",
	)
	check.Flags().BoolVar(&asJSON, "json", false, "write a machine-readable JSON report")
	check.Flags().DurationVar(&timeout, "timeout", 10*time.Second, "diagnostic timeout")

	var (
		inspectRPCURL  string
		inspectAsJSON  bool
		inspectTimeout time.Duration
		inspectABIs    []string
	)
	inspect := &cobra.Command{
		Use:   "inspect <address-or-transaction-hash>",
		Short: "Inspect an Arc Testnet address or transaction",
		Args:  cobra.ExactArgs(1),
		RunE: func(command *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(command.Context(), inspectTimeout)
			defer cancel()

			kind := doctor.AddressCheck
			var abiInputs []doctor.ABIInput
			looksLikeTransactionHash := len(args[0]) == 66 &&
				strings.HasPrefix(strings.ToLower(args[0]), "0x")
			if common.IsHexHash(args[0]) || looksLikeTransactionHash || len(inspectABIs) > 0 {
				kind = doctor.TransactionCheck
				var err error
				abiInputs, err = readABIInputs(inspectABIs)
				if err != nil {
					return err
				}
			}
			report, err := factory(inspectRPCURL).Diagnose(ctx, doctor.Request{
				Kind:   kind,
				Target: args[0],
				ABIs:   abiInputs,
			})
			if err != nil {
				return err
			}
			return writeReport(command.OutOrStdout(), report, inspectAsJSON)
		},
	}
	inspect.Flags().StringVar(
		&inspectRPCURL,
		"rpc",
		DefaultArcTestnetRPC,
		"Arc JSON-RPC endpoint",
	)
	inspect.Flags().BoolVar(
		&inspectAsJSON,
		"json",
		false,
		"write a machine-readable JSON report",
	)
	inspect.Flags().DurationVar(
		&inspectTimeout,
		"timeout",
		10*time.Second,
		"diagnostic timeout",
	)
	inspect.Flags().StringSliceVar(
		&inspectABIs,
		"abi",
		nil,
		"Solidity ABI or artifact JSON file (repeatable)",
	)

	var (
		deploymentRPCURL    string
		deploymentAsJSON    bool
		deploymentTimeout   time.Duration
		deploymentArtifacts []string
	)
	deployment := &cobra.Command{
		Use:   "deployment <manifest>",
		Short: "Validate an Arc deployment manifest or Foundry broadcast",
		Args:  cobra.ExactArgs(1),
		RunE: func(command *cobra.Command, args []string) error {
			manifestPath, err := filepath.Abs(args[0])
			if err != nil {
				return fmt.Errorf("resolve deployment manifest %q: %w", args[0], err)
			}
			manifestData, err := readLimitedFile(manifestPath, maxManifestInputBytes)
			if err != nil {
				return fmt.Errorf("read deployment manifest %q: %w", args[0], err)
			}
			artifacts, err := parseArtifactOverrides(deploymentArtifacts)
			if err != nil {
				return err
			}

			ctx, cancel := context.WithTimeout(command.Context(), deploymentTimeout)
			defer cancel()
			report, err := factory(deploymentRPCURL).Diagnose(ctx, doctor.Request{
				Kind: doctor.DeploymentCheck,
				Deployment: &doctor.DeploymentInput{
					Name:      filepath.Base(manifestPath),
					BaseDir:   filepath.Dir(manifestPath),
					Data:      manifestData,
					Artifacts: artifacts,
				},
			})
			if err != nil {
				return err
			}
			return writeReport(command.OutOrStdout(), report, deploymentAsJSON)
		},
	}
	deployment.Flags().StringVar(
		&deploymentRPCURL,
		"rpc",
		DefaultArcTestnetRPC,
		"Arc JSON-RPC endpoint",
	)
	deployment.Flags().BoolVar(
		&deploymentAsJSON,
		"json",
		false,
		"write a machine-readable JSON report",
	)
	deployment.Flags().DurationVar(
		&deploymentTimeout,
		"timeout",
		30*time.Second,
		"diagnostic timeout",
	)
	deployment.Flags().StringArrayVar(
		&deploymentArtifacts,
		"artifact",
		nil,
		"contract artifact override in Name=path form (repeatable)",
	)

	var (
		reportFormat string
		reportOutput string
		reportForce  bool
	)
	reportCommand := &cobra.Command{
		Use:   "report <input>",
		Short: "Sanitize and export an Arc Doctor JSON report",
		Args:  cobra.ExactArgs(1),
		RunE: func(command *cobra.Command, args []string) error {
			data, err := readReportInput(command, args[0])
			if err != nil {
				return err
			}
			if err := jsonlimit.CheckDepth(
				data,
				jsonlimit.DefaultMaxDepth,
			); err != nil {
				return fmt.Errorf("validate report JSON: %w", err)
			}
			var report doctor.Report
			decoder := json.NewDecoder(bytes.NewReader(data))
			if err := decoder.Decode(&report); err != nil {
				return fmt.Errorf("decode report JSON: %w", err)
			}
			var trailing any
			if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
				if err == nil {
					return fmt.Errorf("decode report JSON: multiple JSON values")
				}
				return fmt.Errorf("decode report JSON: %w", err)
			}
			if report.SchemaVersion != 1 {
				return fmt.Errorf(
					"unsupported report schema version %d",
					report.SchemaVersion,
				)
			}
			report = doctor.SanitizeReport(report)

			var rendered bytes.Buffer
			switch reportFormat {
			case "json":
				encoder := json.NewEncoder(&rendered)
				encoder.SetIndent("", "  ")
				err = encoder.Encode(report)
			case "text":
				err = renderTerminal(&rendered, report)
			default:
				return fmt.Errorf(
					"unsupported report format %q: use json or text",
					reportFormat,
				)
			}
			if err != nil {
				return err
			}
			if reportOutput == "" {
				_, err = command.OutOrStdout().Write(rendered.Bytes())
				return err
			}

			flags := os.O_WRONLY | os.O_CREATE
			if reportForce {
				flags |= os.O_TRUNC
			} else {
				flags |= os.O_EXCL
			}
			outputFile, err := os.OpenFile(reportOutput, flags, 0o600)
			if err != nil {
				return fmt.Errorf("create report output %q: %w", reportOutput, err)
			}
			if _, err := outputFile.Write(rendered.Bytes()); err != nil {
				_ = outputFile.Close()
				return fmt.Errorf("write report output: %w", err)
			}
			if err := outputFile.Sync(); err != nil {
				_ = outputFile.Close()
				return fmt.Errorf("sync report output: %w", err)
			}
			if err := outputFile.Close(); err != nil {
				return fmt.Errorf("close report output: %w", err)
			}
			return nil
		},
	}
	reportCommand.Flags().StringVar(
		&reportFormat,
		"format",
		"json",
		"output format: json or text",
	)
	reportCommand.Flags().StringVar(
		&reportOutput,
		"output",
		"",
		"write to a file instead of standard output",
	)
	reportCommand.Flags().BoolVar(
		&reportForce,
		"force",
		false,
		"replace an existing output file",
	)

	root.AddCommand(check, inspect, deployment, reportCommand)
	return root
}

func readReportInput(command *cobra.Command, path string) ([]byte, error) {
	if path == "-" {
		data, err := io.ReadAll(io.LimitReader(
			command.InOrStdin(),
			maxReportInputBytes+1,
		))
		if err != nil {
			return nil, fmt.Errorf("read report from standard input: %w", err)
		}
		if len(data) > maxReportInputBytes {
			return nil, fmt.Errorf(
				"report input exceeds %d bytes",
				maxReportInputBytes,
			)
		}
		return data, nil
	}
	data, err := readLimitedFile(path, maxReportInputBytes)
	if err != nil {
		return nil, fmt.Errorf("read report input %q: %w", path, err)
	}
	return data, nil
}

func readLimitedFile(path string, maximum int64) ([]byte, error) {
	return localfile.Read(path, maximum)
}

func parseArtifactOverrides(values []string) (map[string]string, error) {
	overrides := make(map[string]string, len(values))
	for _, value := range values {
		name, path, ok := strings.Cut(value, "=")
		if !ok || strings.TrimSpace(name) == "" || strings.TrimSpace(path) == "" {
			return nil, fmt.Errorf(
				"invalid --artifact %q: expected Name=path",
				value,
			)
		}
		name = strings.TrimSpace(name)
		if _, duplicate := overrides[name]; duplicate {
			return nil, fmt.Errorf("duplicate --artifact override for %q", name)
		}
		resolvedPath, err := filepath.Abs(strings.TrimSpace(path))
		if err != nil {
			return nil, fmt.Errorf("resolve artifact path for %q: %w", name, err)
		}
		overrides[name] = resolvedPath
	}
	return overrides, nil
}

func readABIInputs(paths []string) ([]doctor.ABIInput, error) {
	inputs := make([]doctor.ABIInput, 0, len(paths))
	for _, path := range paths {
		data, err := readLimitedFile(path, maxABIInputBytes)
		if err != nil {
			return nil, fmt.Errorf("read ABI file %q: %w", path, err)
		}
		inputs = append(inputs, doctor.ABIInput{
			Name: filepath.Base(path),
			Data: data,
		})
	}
	return inputs, nil
}

func writeReport(writer io.Writer, report doctor.Report, asJSON bool) error {
	var outputErr error
	if asJSON {
		encoder := json.NewEncoder(writer)
		encoder.SetIndent("", "  ")
		outputErr = encoder.Encode(report)
	} else {
		outputErr = renderTerminal(writer, report)
	}
	if outputErr != nil {
		return outputErr
	}
	if report.HasErrors() {
		return ErrDiagnosticFindings
	}
	return nil
}

func renderTerminal(writer io.Writer, report doctor.Report) error {
	if _, err := fmt.Fprintln(writer, "Arc Doctor"); err != nil {
		return fmt.Errorf("write report title: %w", err)
	}
	if report.SchemaVersion != 0 {
		if _, err := fmt.Fprintf(
			writer,
			"Version:       %s\nRuleset:       %s\nCollected:     %s\nSanitized:     %t\n",
			report.Tool.Version,
			report.Tool.RulesetVersion,
			report.CollectedAt.Format(time.RFC3339),
			report.Sanitized,
		); err != nil {
			return fmt.Errorf("write report metadata: %w", err)
		}
	}

	if report.Network.ExpectedChainID != 0 {
		if _, err := fmt.Fprintf(
			writer,
			"\nNetwork target: Arc Testnet\nExpected ID:  %d\n",
			report.Network.ExpectedChainID,
		); err != nil {
			return fmt.Errorf("write network report: %w", err)
		}
		if report.Network.ObservedChainID != 0 {
			if _, err := fmt.Fprintf(
				writer,
				"Observed ID:  %d\n",
				report.Network.ObservedChainID,
			); err != nil {
				return fmt.Errorf("write observed chain ID: %w", err)
			}
		}
		if report.Network.BlockNumber != 0 {
			if _, err := fmt.Fprintf(
				writer,
				"Latest block: %d\n",
				report.Network.BlockNumber,
			); err != nil {
				return fmt.Errorf("write latest block: %w", err)
			}
		}
		if !report.Network.BlockTimestamp.IsZero() {
			if _, err := fmt.Fprintf(
				writer,
				"Block time:   %s\n",
				report.Network.BlockTimestamp.Format(time.RFC3339),
			); err != nil {
				return fmt.Errorf("write block timestamp: %w", err)
			}
		}
		if report.Network.Latency > 0 {
			if _, err := fmt.Fprintf(
				writer,
				"Latency:      %s\n",
				report.Network.Latency.Round(time.Millisecond),
			); err != nil {
				return fmt.Errorf("write RPC latency: %w", err)
			}
		}
	}

	if report.Address != nil {
		if _, err := fmt.Fprintf(
			writer,
			"\nAddress:      %s\nType:         %s\nBalance:      %s base units\nNonce:        %d\nBytecode:     %d bytes\nCode hash:    %s\nExplorer:     %s\n",
			report.Address.Address,
			report.Address.Kind,
			report.Address.BalanceBaseUnits,
			report.Address.Nonce,
			report.Address.CodeSize,
			report.Address.CodeHash,
			report.Address.ExplorerURL,
		); err != nil {
			return fmt.Errorf("write address report: %w", err)
		}
		if report.Address.Proxy != nil {
			if _, err := fmt.Fprintf(
				writer,
				"Proxy:        %s\nImplementation: %s\nBeacon:       %s\nProxy basis:  %s\n",
				report.Address.Proxy.Standard,
				report.Address.Proxy.Implementation,
				report.Address.Proxy.Beacon,
				report.Address.Proxy.Basis,
			); err != nil {
				return fmt.Errorf("write proxy evidence: %w", err)
			}
		}
	}

	if report.Transaction != nil {
		transaction := report.Transaction
		if _, err := fmt.Fprintf(
			writer,
			"\nTransaction:  %s\nState:        %s\nFrom:         %s\nTo:           %s\nValue:        %s base units\nGas limit:    %d\nType:         %d\nExplorer:     %s\n",
			transaction.Hash,
			transaction.State,
			transaction.From,
			transaction.To,
			transaction.ValueBaseUnits,
			transaction.GasLimit,
			transaction.Type,
			transaction.ExplorerURL,
		); err != nil {
			return fmt.Errorf("write transaction report: %w", err)
		}
		if transaction.BlockNumber != nil {
			if _, err := fmt.Fprintf(
				writer,
				"Block:        %d\n",
				*transaction.BlockNumber,
			); err != nil {
				return fmt.Errorf("write transaction block: %w", err)
			}
		}
		if transaction.GasUsed != nil {
			if _, err := fmt.Fprintf(
				writer,
				"Gas used:     %d\n",
				*transaction.GasUsed,
			); err != nil {
				return fmt.Errorf("write transaction gas use: %w", err)
			}
		}
		if transaction.Call != nil {
			if _, err := fmt.Fprintf(
				writer,
				"Function:     %s\nABI source:   %s\n",
				transaction.Call.Signature,
				transaction.Call.Source,
			); err != nil {
				return fmt.Errorf("write decoded call: %w", err)
			}
		}
		if transaction.Revert != nil {
			if _, err := fmt.Fprintf(
				writer,
				"Revert:       %s\nRaw data:     %s\n",
				transaction.Revert.Signature,
				transaction.Revert.RawData,
			); err != nil {
				return fmt.Errorf("write revert evidence: %w", err)
			}
		}
	}

	if report.Deployment != nil {
		deployment := report.Deployment
		if _, err := fmt.Fprintf(
			writer,
			"\nManifest:     %s\nFormat:       %s\nChain ID:     %d\nContracts:    %d\n",
			deployment.ManifestName,
			deployment.Format,
			deployment.ChainID,
			len(deployment.Contracts),
		); err != nil {
			return fmt.Errorf("write deployment report: %w", err)
		}
		for _, contract := range deployment.Contracts {
			if _, err := fmt.Fprintf(
				writer,
				"\nContract:     %s\nAddress:      %s\nBytecode:     %d bytes\nCode hash:    %s\nArtifact:     %s\nComparison:   %s\nExplorer:     %s\n",
				contract.Name,
				contract.Address,
				contract.CodeSize,
				contract.CodeHash,
				contract.Artifact,
				contract.ArtifactComparison,
				contract.AddressExplorerURL,
			); err != nil {
				return fmt.Errorf("write deployment contract: %w", err)
			}
		}
	}

	if _, err := fmt.Fprintln(writer); err != nil {
		return fmt.Errorf("separate report findings: %w", err)
	}
	for _, finding := range report.Findings {
		if _, err := fmt.Fprintf(
			writer,
			"[%s] %s  %s\n%s\nConfidence: %s\n",
			strings.ToUpper(string(finding.Severity)),
			finding.Code,
			finding.Title,
			finding.Explanation,
			finding.Confidence,
		); err != nil {
			return fmt.Errorf("write finding: %w", err)
		}
		for _, evidence := range finding.Evidence {
			if _, err := fmt.Fprintf(writer, "Evidence: %s\n", evidence); err != nil {
				return fmt.Errorf("write finding evidence: %w", err)
			}
		}
		for _, action := range finding.SuggestedActions {
			if _, err := fmt.Fprintf(writer, "Check: %s\n", action); err != nil {
				return fmt.Errorf("write suggested action: %w", err)
			}
		}
		if _, err := fmt.Fprintln(writer); err != nil {
			return fmt.Errorf("finish finding: %w", err)
		}
	}

	return nil
}

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/anandh8x/arcdoctor/internal/doctor"
	"github.com/spf13/cobra"
)

const DefaultArcTestnetRPC = "https://rpc.testnet.arc.network"

var ErrDiagnosticFindings = errors.New("diagnostic errors found")

type Diagnoser interface {
	Diagnose(context.Context, doctor.Request) (doctor.Report, error)
}

type DiagnoserFactory func(rpcURL string) Diagnoser

func NewRootCommand(factory DiagnoserFactory) *cobra.Command {
	root := &cobra.Command{
		Use:           "arcdoctor",
		Short:         "Evidence-based diagnostics for Arc Testnet",
		SilenceErrors: true,
		SilenceUsage:  true,
	}

	var (
		rpcURL  string
		asJSON  bool
		timeout time.Duration
	)

	check := &cobra.Command{
		Use:   "check",
		Short: "Check the Arc Testnet network connection",
		RunE: func(command *cobra.Command, _ []string) error {
			ctx, cancel := context.WithTimeout(command.Context(), timeout)
			defer cancel()

			report, err := factory(rpcURL).Diagnose(ctx, doctor.Request{
				Kind: doctor.NetworkCheck,
			})
			if err != nil {
				return err
			}
			return writeReport(command.OutOrStdout(), report, asJSON)
		},
	}
	check.Flags().StringVar(&rpcURL, "rpc", DefaultArcTestnetRPC, "Arc JSON-RPC endpoint")
	check.Flags().BoolVar(&asJSON, "json", false, "write a machine-readable JSON report")
	check.Flags().DurationVar(&timeout, "timeout", 10*time.Second, "diagnostic timeout")

	var (
		inspectRPCURL  string
		inspectAsJSON  bool
		inspectTimeout time.Duration
	)
	inspect := &cobra.Command{
		Use:   "inspect <address>",
		Short: "Inspect an Arc Testnet address",
		Args:  cobra.ExactArgs(1),
		RunE: func(command *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(command.Context(), inspectTimeout)
			defer cancel()

			report, err := factory(inspectRPCURL).Diagnose(ctx, doctor.Request{
				Kind:   doctor.AddressCheck,
				Target: args[0],
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

	root.AddCommand(check, inspect)
	return root
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

	if report.Network.ExpectedChainID != 0 {
		if _, err := fmt.Fprintf(
			writer,
			"\nNetwork:      Arc Testnet\nChain ID:     %d\nLatest block: %d\nBlock time:   %s\nLatency:      %s\n",
			report.Network.ObservedChainID,
			report.Network.BlockNumber,
			report.Network.BlockTimestamp.Format(time.RFC3339),
			report.Network.Latency.Round(time.Millisecond),
		); err != nil {
			return fmt.Errorf("write network report: %w", err)
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

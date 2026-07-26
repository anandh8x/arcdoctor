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

			var outputErr error
			if !asJSON {
				outputErr = renderTerminal(command.OutOrStdout(), report)
			} else {
				encoder := json.NewEncoder(command.OutOrStdout())
				encoder.SetIndent("", "  ")
				outputErr = encoder.Encode(report)
			}
			if outputErr != nil {
				return outputErr
			}
			if report.HasErrors() {
				return ErrDiagnosticFindings
			}
			return nil
		},
	}
	check.Flags().StringVar(&rpcURL, "rpc", DefaultArcTestnetRPC, "Arc JSON-RPC endpoint")
	check.Flags().BoolVar(&asJSON, "json", false, "write a machine-readable JSON report")
	check.Flags().DurationVar(&timeout, "timeout", 10*time.Second, "diagnostic timeout")

	root.AddCommand(check)
	return root
}

func renderTerminal(writer io.Writer, report doctor.Report) error {
	if _, err := fmt.Fprintf(
		writer,
		"Arc Doctor\n\nNetwork:      Arc Testnet\nChain ID:     %d\nLatest block: %d\nBlock time:   %s\nLatency:      %s\n\n",
		report.Network.ObservedChainID,
		report.Network.BlockNumber,
		report.Network.BlockTimestamp.Format(time.RFC3339),
		report.Network.Latency.Round(time.Millisecond),
	); err != nil {
		return fmt.Errorf("write network report: %w", err)
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

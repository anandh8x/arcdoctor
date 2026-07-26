package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/anandh8x/arcdoctor/internal/chain"
	"github.com/anandh8x/arcdoctor/internal/cli"
	"github.com/anandh8x/arcdoctor/internal/doctor"
	"github.com/anandh8x/arcdoctor/internal/redact"
	"github.com/anandh8x/arcdoctor/internal/tui"
	"golang.org/x/term"
)

func main() {
	factory := func(rpcURL string) cli.Diagnoser {
		probe := chain.NewRPCProbe(rpcURL)
		return doctor.New(
			probe,
			doctor.WithAddressProbe(probe),
			doctor.WithBytecodeProbe(probe),
			doctor.WithTransactionProbe(probe),
			doctor.WithArtifactLoader(os.ReadFile),
		)
	}
	if shouldLaunchTUI(
		os.Args[1:],
		term.IsTerminal(int(os.Stdin.Fd())),
		term.IsTerminal(int(os.Stdout.Fd())),
	) {
		err := tui.Run(
			func(rpcURL string) tui.Diagnoser {
				return factory(rpcURL)
			},
			os.ReadFile,
			nil,
			os.Stdin,
			os.Stdout,
		)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "arcdoctor: %s\n", redact.String(err.Error()))
			os.Exit(2)
		}
		os.Exit(0)
	}
	os.Exit(execute(os.Args[1:], os.Stdout, os.Stderr, factory))
}

func shouldLaunchTUI(args []string, inputTerminal, outputTerminal bool) bool {
	return len(args) == 0 && inputTerminal && outputTerminal
}

func execute(
	args []string,
	stdout io.Writer,
	stderr io.Writer,
	factory cli.DiagnoserFactory,
) int {
	command := cli.NewRootCommand(factory)
	command.SetArgs(args)
	command.SetOut(stdout)
	command.SetErr(stderr)

	err := command.ExecuteContext(context.Background())
	switch {
	case err == nil:
		return 0
	case errors.Is(err, cli.ErrDiagnosticFindings):
		return 1
	default:
		_, _ = fmt.Fprintf(stderr, "arcdoctor: %s\n", redact.String(err.Error()))
		return 2
	}
}

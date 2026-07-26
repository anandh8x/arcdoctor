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
	os.Exit(execute(os.Args[1:], os.Stdout, os.Stderr, factory))
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

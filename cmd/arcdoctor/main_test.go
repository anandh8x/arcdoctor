package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/anandh8x/arcdoctor/internal/cli"
	"github.com/anandh8x/arcdoctor/internal/doctor"
)

type failingDiagnoser struct {
	err error
}

func (d failingDiagnoser) Diagnose(
	context.Context,
	doctor.Request,
) (doctor.Report, error) {
	return doctor.Report{}, d.err
}

func TestExecuteRedactsOperationalErrors(t *testing.T) {
	t.Parallel()

	factory := func(string) cli.Diagnoser {
		return failingDiagnoser{
			err: errors.New("connect https://alice:secret@rpc.example?token=value: refused"),
		}
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := execute([]string{"check"}, &stdout, &stderr, factory)

	if exitCode != 2 {
		t.Fatalf("exit code = %d, want 2", exitCode)
	}
	for _, secret := range []string{"alice", "secret", "value"} {
		if strings.Contains(stderr.String(), secret) {
			t.Errorf("stderr contains %q: %s", secret, stderr.String())
		}
	}
	if !strings.Contains(stderr.String(), "[REDACTED]") {
		t.Errorf("stderr does not contain redaction marker: %s", stderr.String())
	}
}

func TestShouldLaunchTUIOnlyForInteractiveNoArgumentSession(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		args           []string
		inputTerminal  bool
		outputTerminal bool
		want           bool
	}{
		{
			name:           "interactive",
			inputTerminal:  true,
			outputTerminal: true,
			want:           true,
		},
		{
			name:           "piped input",
			inputTerminal:  false,
			outputTerminal: true,
		},
		{
			name:           "redirected output",
			inputTerminal:  true,
			outputTerminal: false,
		},
		{
			name:           "explicit command",
			args:           []string{"check"},
			inputTerminal:  true,
			outputTerminal: true,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := shouldLaunchTUI(
				test.args,
				test.inputTerminal,
				test.outputTerminal,
			); got != test.want {
				t.Errorf("shouldLaunchTUI() = %t, want %t", got, test.want)
			}
		})
	}
}

func TestExecuteWithoutArgumentsPrintsHelpForNonInteractiveCaller(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := execute(nil, &stdout, &stderr, func(string) cli.Diagnoser {
		return failingDiagnoser{err: errors.New("should not diagnose")}
	})

	if exitCode != 0 {
		t.Fatalf("exit code = %d, want 0", exitCode)
	}
	if !strings.Contains(stdout.String(), "Usage:") ||
		!strings.Contains(stdout.String(), "deployment") {
		t.Errorf("stdout does not contain command help:\n%s", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Errorf("stderr = %q, want empty", stderr.String())
	}
}

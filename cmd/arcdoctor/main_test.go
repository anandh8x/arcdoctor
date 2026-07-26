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

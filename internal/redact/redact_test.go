package redact_test

import (
	"strings"
	"testing"

	"github.com/anandh8x/arcdoctor/internal/redact"
)

func TestStringRemovesCredentialsFromDiagnosticErrors(t *testing.T) {
	t.Parallel()

	input := "connect https://alice:super-secret@rpc.example/path?api_key=token-value&mode=debug: connection refused"
	output := redact.String(input)

	for _, secret := range []string{"alice", "super-secret", "token-value"} {
		if strings.Contains(output, secret) {
			t.Errorf("redacted output contains %q: %s", secret, output)
		}
	}
	if !strings.Contains(output, "[REDACTED]") {
		t.Errorf("redacted output does not contain marker: %s", output)
	}
	if !strings.Contains(output, "mode=debug") {
		t.Errorf("redacted output removed safe query data: %s", output)
	}
}

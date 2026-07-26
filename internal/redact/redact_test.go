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

func TestStringRedactsCommonSecretContextsWithoutRemovingTransactionHashes(t *testing.T) {
	t.Parallel()

	privateKey := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	transactionHash := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	input := strings.Join([]string{
		"private_key=" + privateKey,
		`{"api_key":"json-secret"}`,
		"Authorization: Bearer bearer-secret",
		"mnemonic=alpha beta gamma delta epsilon zeta eta theta iota kappa lambda mu",
		"path=/home/anaxy/Projects/app",
		"transaction=" + transactionHash,
		"\x1b[31mred\x1b[0m",
	}, "\n")

	output := redact.String(input)
	for _, secret := range []string{
		privateKey,
		"json-secret",
		"bearer-secret",
		"alpha beta gamma",
		"/home/anaxy/",
		"\x1b[31m",
	} {
		if strings.Contains(output, secret) {
			t.Errorf("redacted output contains %q:\n%s", secret, output)
		}
	}
	if !strings.Contains(output, transactionHash) {
		t.Errorf("redacted output removed public transaction hash:\n%s", output)
	}
}

func TestStringsSanitizesNestedValues(t *testing.T) {
	t.Parallel()

	value := struct {
		Message string
		Nested  []struct {
			Detail string
		}
	}{
		Message: "https://alice:password@rpc.example",
		Nested: []struct {
			Detail string
		}{
			{Detail: "token=nested-secret"},
		},
	}

	redact.Strings(&value)
	if strings.Contains(value.Message, "alice") ||
		strings.Contains(value.Nested[0].Detail, "nested-secret") {
		t.Fatalf("nested value was not sanitized: %#v", value)
	}
}

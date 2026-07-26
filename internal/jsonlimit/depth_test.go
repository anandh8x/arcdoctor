package jsonlimit_test

import (
	"strings"
	"testing"

	"github.com/anandh8x/arcdoctor/internal/jsonlimit"
)

func TestCheckDepthAcceptsBoundaryAndIgnoresQuotedDelimiters(t *testing.T) {
	t.Parallel()

	input := []byte(`{"quoted":"[[[{{{","value":[{"ok":true}]]}`)
	if err := jsonlimit.CheckDepth(input, 4); err != nil {
		t.Fatalf("CheckDepth() error = %v", err)
	}
}

func TestCheckDepthRejectsExcessiveNesting(t *testing.T) {
	t.Parallel()

	input := []byte(strings.Repeat("[", 65) + strings.Repeat("]", 65))
	err := jsonlimit.CheckDepth(input, jsonlimit.DefaultMaxDepth)
	if err == nil || !strings.Contains(err.Error(), "exceeds 64") {
		t.Fatalf("CheckDepth() error = %v, want depth error", err)
	}
}

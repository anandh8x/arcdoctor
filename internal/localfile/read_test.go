package localfile_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/anandh8x/arcdoctor/internal/localfile"
)

func TestReadEnforcesMaximumWithoutReturningPartialInput(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "input.json")
	if err := os.WriteFile(path, []byte("12345"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	data, err := localfile.Read(path, 4)
	if err == nil || !strings.Contains(err.Error(), "exceeds 4 bytes") {
		t.Fatalf("Read() error = %v, want size error", err)
	}
	if data != nil {
		t.Errorf("Read() data = %q, want nil", data)
	}
}

func TestReadReturnsInputWithinLimit(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "input.json")
	if err := os.WriteFile(path, []byte("1234"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	data, err := localfile.Read(path, 4)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if string(data) != "1234" {
		t.Errorf("Read() = %q, want 1234", data)
	}
}

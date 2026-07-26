package redact_test

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/anandh8x/arcdoctor/internal/redact"
)

func FuzzStringAlwaysProducesTerminalSafeUTF8(f *testing.F) {
	f.Add("ordinary output")
	f.Add("https://alice:secret@rpc.example?api_key=value")
	f.Add("\x1b[31mred\x1b[0m\x00")
	f.Add(string([]byte{0xff, 0xfe, 0xfd}))

	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > 1<<20 {
			t.Skip()
		}
		output := redact.String(input)
		if !utf8.ValidString(output) {
			t.Fatalf("output is invalid UTF-8: %q", output)
		}
		if strings.ContainsRune(output, '\x1b') {
			t.Fatalf("output contains an escape character: %q", output)
		}
		for _, character := range output {
			if character < 0x20 &&
				character != '\n' &&
				character != '\r' &&
				character != '\t' {
				t.Fatalf("output contains control character U+%04X", character)
			}
			if character == 0x7f {
				t.Fatal("output contains DEL control character")
			}
		}
	})
}

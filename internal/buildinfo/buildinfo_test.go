package buildinfo

import (
	"runtime/debug"
	"testing"
)

func TestResolveVersion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		injected string
		info     *debug.BuildInfo
		ok       bool
		want     string
	}{
		{
			name:     "release linker value wins",
			injected: "0.2.0",
			info:     &debug.BuildInfo{Main: debug.Module{Version: "v0.1.0"}},
			ok:       true,
			want:     "0.2.0",
		},
		{
			name:     "go install module version",
			injected: "dev",
			info:     &debug.BuildInfo{Main: debug.Module{Version: "v0.1.0"}},
			ok:       true,
			want:     "0.1.0",
		},
		{
			name:     "development build",
			injected: "dev",
			info:     &debug.BuildInfo{Main: debug.Module{Version: "(devel)"}},
			ok:       true,
			want:     "dev",
		},
		{
			name: "empty fallback",
			want: "dev",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := resolveVersion(test.injected, test.info, test.ok); got != test.want {
				t.Fatalf("resolveVersion() = %q, want %q", got, test.want)
			}
		})
	}
}

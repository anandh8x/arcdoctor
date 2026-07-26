package buildinfo

import (
	"runtime/debug"
	"strings"
)

const (
	ReportSchemaVersion = 1
	RulesetVersion      = "1.0.0"
)

var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

// ResolvedVersion uses release linker metadata when available and falls back
// to the module version embedded by `go install module@version`.
func ResolvedVersion() string {
	info, ok := debug.ReadBuildInfo()
	return resolveVersion(Version, info, ok)
}

func resolveVersion(injected string, info *debug.BuildInfo, ok bool) string {
	if injected != "" && injected != "dev" {
		return strings.TrimPrefix(injected, "v")
	}
	if ok && info != nil &&
		info.Main.Version != "" &&
		info.Main.Version != "(devel)" {
		return strings.TrimPrefix(info.Main.Version, "v")
	}
	if injected != "" {
		return injected
	}
	return "dev"
}

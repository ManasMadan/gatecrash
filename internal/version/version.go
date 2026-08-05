// Package version carries build metadata stamped in by the linker.
package version

import (
	"fmt"
	"runtime"
)

// These are set with -ldflags at build time by scripts/build.sh. The zero
// values are what you get from a plain `go build`, which is fine for dev.
var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

// APIVersion is the wire contract version advertised over mDNS TXT records, the
// UDP beacon and GET /v1/meta. Scanners refuse to enroll against a box whose
// major differs.
const APIVersion = "1"

// String renders the one-line banner used by --version and the boot log.
func String() string {
	return fmt.Sprintf("gatecrash %s (%s, %s, %s/%s, api v%s)",
		Version, Commit, Date, runtime.GOOS, runtime.GOARCH, APIVersion)
}

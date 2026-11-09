// Package helperbin embeds the pgs-sqlhelper binaries that the provider uploads to a
// remote host. Build them with `just helpers` (they are not committed).
package helperbin

import (
	"embed"
	"fmt"
)

//go:embed all:bin
var fs embed.FS

// Get returns the helper binary for the given GOOS/GOARCH.
func Get(goos, goarch string) ([]byte, error) {
	b, err := fs.ReadFile("bin/" + goos + "_" + goarch)
	if err != nil {
		return nil, fmt.Errorf("no embedded sqlite helper for %s/%s (supported: linux/amd64, linux/arm64; build with `just helpers`)", goos, goarch)
	}
	return b, nil
}

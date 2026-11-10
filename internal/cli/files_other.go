//go:build !unix && !windows

package cli

import (
	"io/fs"
	"os"
)

// cmd/lce doesn't build for this system. These keep the package building, and do without what lce can't do here.

// soleLink accepts every file: lce can't count a file's links here.
func soleLink(string, fs.FileInfo) error { return nil }

// openDir returns nil: lce can't flush a directory to disk here.
func openDir(string) *os.File { return nil }

//go:build !windows && !(linux && (amd64 || arm64))

package cli

import "errors"

// renameNoReplace reports errors.ErrUnsupported: this system has no rename that refuses to replace a file, at least
// none that package syscall reaches.
func renameNoReplace(string, string) error { return errors.ErrUnsupported }

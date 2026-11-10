//go:build unix

package cli

import (
	"io/fs"
	"os"
	"syscall"
)

// soleLink refuses the file at path, whose information is info, if it has other hard links.
func soleLink(path string, info fs.FileInfo) error {
	if info.Sys().(*syscall.Stat_t).Nlink > 1 {
		return otherLinks(path)
	}
	return nil
}

// openDir opens the directory dir, to flush it to disk once a file in it has its new name, so that the name survives
// a crash. It returns nil if it can't: lce may write into a directory that it can't read.
func openDir(dir string) *os.File {
	d, err := os.Open(dir)
	if err != nil {
		return nil
	}
	return d
}

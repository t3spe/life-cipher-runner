package cli

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

func TestRenameNoReplace(t *testing.T) {
	dir := t.TempDir()
	a, b, c := put(t, filepath.Join(dir, "a"), []byte("a")), put(t, filepath.Join(dir, "b"), []byte("b")),
		filepath.Join(dir, "c")
	if err := renameNoReplace(a, b); !errors.Is(err, fs.ErrExist) || string(read(t, b)) != "b" {
		t.Errorf("onto a file that exists: %v", err)
	}
	if err := renameNoReplace(a, c); err != nil || string(read(t, c)) != "a" {
		t.Errorf("to a free name: %v", err)
	}
	if _, err := os.Stat(a); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the old name stays: %v", err)
	}
	// A name with a NUL byte can't reach the kernel, whichever name it is.
	if err := renameNoReplace(c+"\x00", filepath.Join(dir, "d")); err == nil {
		t.Error("an old name with a NUL byte")
	}
	if err := renameNoReplace(c, filepath.Join(dir, "d\x00")); err == nil {
		t.Error("a new name with a NUL byte")
	}
	// renameat2 answers EINVAL where it can't refuse to replace, and also for a directory moved into itself.
	if err := renameNoReplace(dir, filepath.Join(dir, "inside")); !errors.Is(err, errors.ErrUnsupported) {
		t.Errorf("EINVAL: %v", err)
	}
}

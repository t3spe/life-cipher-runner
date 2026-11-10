//go:build unix

package cli

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestOutputNotARegularFile(t *testing.T) {
	// Renaming over a pipe or a device would stop it being one: lce refuses, with -f or without.
	t.Parallel()
	dir, key := workspace(t)
	notes := put(t, filepath.Join(dir, "notes.txt"), []byte("notes"))
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, out := range []string{fifo, os.DevNull} {
		for _, force := range []string{"-f=false", "-f"} {
			expect(t, run(t, "encrypt", "-k", key, force, "-o", out, notes), ExitFailure,
				"lce encrypt: OUTPUT "+out+" isn't a regular file")
		}
	}
	if info, err := os.Lstat(fifo); err != nil || info.Mode()&fs.ModeNamedPipe == 0 {
		t.Errorf("the pipe: %v, %v", info, err)
	}
}

func TestOutputMode(t *testing.T) {
	// OUTPUT is readable and writable by its owner only, whatever the umask, and so is a file that -f replaces.
	t.Parallel()
	dir, key := workspace(t)
	notes := put(t, filepath.Join(dir, "notes.txt"), []byte("notes"))
	shared := put(t, filepath.Join(dir, "shared.lc"), nil)
	if err := os.Chmod(shared, 0o644); err != nil {
		t.Fatal(err)
	}
	fresh := filepath.Join(dir, "fresh.lc")
	expect(t, run(t, "encrypt", "-k", key, "-o", fresh, notes), ExitOK, "")
	expect(t, run(t, "encrypt", "-k", key, "-f", "-o", shared, notes), ExitOK, "")
	for _, path := range []string{fresh, shared} {
		if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
			t.Errorf("%s: %v, %v", path, info.Mode(), err)
		}
	}
}

func TestOpenDir(t *testing.T) {
	if d := openDir(t.TempDir()); d == nil || d.Close() != nil {
		t.Error("a directory didn't open")
	}
	if d := openDir(filepath.Join(t.TempDir(), "missing")); d != nil {
		t.Error("a missing directory opened")
	}
}

// skipIfRoot skips a test that relies on permissions, which root bypasses.
func skipIfRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("root bypasses permissions")
	}
}

func TestWriteOnlyDirectory(t *testing.T) {
	// lce can write into a directory it can't read, and so can't flush: OUTPUT appears, and the run succeeds.
	skipIfRoot(t)
	t.Parallel()
	dir, key := workspace(t)
	notes := put(t, filepath.Join(dir, "notes.txt"), []byte("notes"))
	wo := filepath.Join(dir, "write-only")
	if err := os.Mkdir(wo, 0o300); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chmod(wo, 0o700) }()
	out := filepath.Join(wo, "notes.lce")
	expect(t, run(t, "encrypt", "-k", key, "-o", out, notes), ExitOK, "")
	if err := os.Chmod(wo, 0o700); err != nil {
		t.Fatal(err)
	}
	if r := run(t, "decrypt", "-k", key, out); r.status != ExitOK || r.stdout != "notes" || r.stderr != "" {
		t.Errorf("decrypting it: %+v", r)
	}
}

func TestLateWarning(t *testing.T) {
	// Not parallel: it replaces renameNew and link. A problem once OUTPUT has its new contents is only a warning:
	// here, the temporary name that a link leaves can't be removed.
	skipIfRoot(t)
	dir, key := workspace(t)
	notes := put(t, filepath.Join(dir, "notes.txt"), []byte("notes"))
	sub := filepath.Join(dir, "sub")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chmod(sub, 0o700) }()
	defer func(f func(string, string) error) { renameNew = f }(renameNew)
	defer func(f func(string, string) error) { link = f }(link)
	renameNew = func(string, string) error { return errors.ErrUnsupported }
	link = func(tmp, path string) error {
		if err := os.Link(tmp, path); err != nil {
			return err
		}
		return os.Chmod(sub, 0o500) // so the temporary name can't be removed
	}
	out := filepath.Join(sub, "notes.lce")
	r := run(t, "encrypt", "-k", key, "-o", out, notes)
	if r.status != ExitOK || !strings.HasPrefix(r.stderr, "lce encrypt: warning: OUTPUT "+out+" is written, but its "+
		"temporary file stays, a second name for it: ") {
		t.Errorf("%+v", r)
	}
	if back := run(t, "decrypt", "-k", key, out); back.stdout != "notes" {
		t.Errorf("OUTPUT: %+v", back)
	}
}

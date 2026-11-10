//go:build (amd64 || arm64) && (unix || windows)

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// demoKey is the burned demo key of SPEC.md Appendix B, as SPEC.md writes it. It must never protect anything.
const demoKey = "6B3028A8 DB46016A 318DA713 85D82A92 6489431E 9A2B00E1 1CB1E684 4106B26D " +
	"90FC90AC 77361985 884930EB 551A3B52 81186009 E8144094 82842900 D88996D1 " +
	"9514CC13 3A81EC34 47580B9D F304B451 84A2B274 24122838 08F6D934 3A69CBB8 " +
	"6A04296A 5F54D36A 42549769 1420992C 30F90206 7215518A 1CE02869 BA961C3B\n"

// asLce, set in the environment, makes the test binary run as lce: the signal tests start it as a child process.
const asLce = "LCE_TEST_AS_LCE"

func TestMain(m *testing.M) {
	if os.Getenv(asLce) == "1" {
		main()
	}
	os.Exit(m.Run())
}

// runMain runs main with the command line args, and returns its exit status and standard output.
func runMain(t *testing.T, args ...string) (int, string) {
	t.Helper()
	status := -1
	stdout, err := os.Create(filepath.Join(t.TempDir(), "stdout"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stdout.Close() }()
	realArgs, realStdout := os.Args, os.Stdout
	defer func() { exit, os.Args, os.Stdout = os.Exit, realArgs, realStdout }()
	exit = func(s int) { status = s }
	os.Args, os.Stdout = append([]string{"lce"}, args...), stdout

	main()

	out, err := os.ReadFile(stdout.Name())
	if err != nil {
		t.Fatal(err)
	}
	return status, string(out)
}

// workspace returns a new directory holding the demo key, as key.txt, and the key's path.
func workspace(t *testing.T) (dir, key string) {
	t.Helper()
	dir = t.TempDir()
	key = filepath.Join(dir, "key.txt")
	if err := os.WriteFile(key, []byte(demoKey), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir, key
}

func TestMainRunsTheCommandLine(t *testing.T) {
	if status, out := runMain(t, "version"); status != 0 || !strings.HasPrefix(out, "lce ") {
		t.Errorf("version: status %d, output %q", status, out)
	}
	if status, _ := runMain(t, "no-such-command"); status != 2 {
		t.Errorf("an unknown command: status %d", status)
	}
}

func TestMainEncryptsAndDecrypts(t *testing.T) {
	// The whole program, with the real key setup and erasure.
	dir, key := workspace(t)
	notes := filepath.Join(dir, "notes.txt")
	if err := os.WriteFile(notes, []byte("attack at dawn\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if status, _ := runMain(t, "encrypt", "-k", key, "-o", notes+".lce", notes); status != 0 {
		t.Fatalf("encrypt: status %d", status)
	}
	if status, out := runMain(t, "decrypt", "-k", key, notes+".lce"); status != 0 || out != "attack at dawn\n" {
		t.Errorf("decrypt: status %d, output %q", status, out)
	}
	glider := filepath.Join(dir, "glider.key")
	if err := os.WriteFile(glider, []byte("40000000 20000000 E0000000"+strings.Repeat(" 00000000", 29)), 0o600); err != nil {
		t.Fatal(err)
	}
	if status, _ := runMain(t, "decrypt", "-k", glider, notes+".lce"); status != 1 {
		t.Errorf("a key that fails the key check: status %d", status)
	}
}

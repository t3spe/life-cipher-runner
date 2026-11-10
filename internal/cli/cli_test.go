package cli

import (
	"bytes"
	"cmp"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"testing/iotest"
	"time"

	"github.com/t3spe/life-cipher-runner/internal/container"
	"github.com/t3spe/life-cipher-runner/lifecipher"
)

// demoKey is the burned demo key of SPEC.md Appendix B, as SPEC.md writes it. It must never protect anything.
const demoKey = "6B3028A8 DB46016A 318DA713 85D82A92 6489431E 9A2B00E1 1CB1E684 4106B26D\n" +
	"90FC90AC 77361985 884930EB 551A3B52 81186009 E8144094 82842900 D88996D1\n" +
	"9514CC13 3A81EC34 47580B9D F304B451 84A2B274 24122838 08F6D934 3A69CBB8\n" +
	"6A04296A 5F54D36A 42549769 1420992C 30F90206 7215518A 1CE02869 BA961C3B\n"

// gliderKey is a glider, whose generations repeat after 128 steps, so it fails the key check.
const gliderKey = "40000000 20000000 E0000000" + " 00000000" + " 00000000 00000000 00000000 00000000" +
	" 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000" +
	" 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000" +
	" 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000"

func TestMain(m *testing.M) {
	// Key setup takes the better part of a second, so these tests set each key up once and share it, and never erase
	// it. A Key never changes, so sharing it is safe. cmd/lce's tests run the real setup and erasure.
	var mu sync.Mutex
	setups := map[string]func() (*lifecipher.Key, error){}
	newKey = func(p lifecipher.Params, key []byte) (*lifecipher.Key, error) {
		id, own := p.String()+string(key), bytes.Clone(key)
		mu.Lock()
		setup, ok := setups[id]
		if !ok {
			setup = sync.OnceValues(func() (*lifecipher.Key, error) { return lifecipher.NewKey(p, own) })
			setups[id] = setup
		}
		mu.Unlock()
		return setup()
	}
	eraseKey = func(*lifecipher.Key) {}
	os.Exit(m.Run())
}

type result struct {
	status         int
	stdout, stderr string
}

// runIn runs a command line with the given standard input, randomness and context.
func runIn(ctx context.Context, stdin, random io.Reader, args ...string) result {
	var stdout, stderr bytes.Buffer
	status := Run(ctx, args, Env{Stdin: stdin, Stdout: &stdout, Stderr: &stderr, Rand: random})
	return result{status, stdout.String(), stderr.String()}
}

// runTo runs a command line with the given standard input and output, and returns its status and standard error.
func runTo(t *testing.T, stdin io.Reader, stdout io.Writer, args ...string) (int, string) {
	t.Helper()
	var stderr bytes.Buffer
	status := Run(t.Context(), args, Env{Stdin: stdin, Stdout: stdout, Stderr: &stderr, Rand: rand.Reader})
	return status, stderr.String()
}

func run(t *testing.T, args ...string) result {
	t.Helper()
	return runIn(t.Context(), strings.NewReader(""), rand.Reader, args...)
}

// put writes a file, and returns its path.
func put(t *testing.T, path string, data []byte) string {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func read(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// demoKeyBytes returns the demo key's 128 bytes.
func demoKeyBytes(t *testing.T) []byte {
	t.Helper()
	raw, err := hex.DecodeString(strings.Join(strings.Fields(demoKey), ""))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// workspace returns a new directory holding the demo key, as key.txt, and the key's path.
func workspace(t *testing.T) (dir, key string) {
	t.Helper()
	dir = t.TempDir()
	return dir, put(t, filepath.Join(dir, "key.txt"), []byte(demoKey))
}

// files lists a directory's file names, so tests can check that nothing was left behind.
func files(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

// expect checks a result's status and that its standard error says want.
func expect(t *testing.T, r result, status int, want string) {
	t.Helper()
	if r.status != status || !strings.Contains(r.stderr, want) {
		t.Errorf("got status %d, stdout %q, stderr %q; want status %d, stderr with %q",
			r.status, r.stdout, r.stderr, status, want)
	}
}

func TestHelp(t *testing.T) {
	expect(t, run(t), ExitUsage, "Usage:\n  lce encrypt")
	for _, args := range [][]string{{"help"}, {"-h"}, {"-help"}, {"--help"}} {
		r := run(t, args...)
		if r.status != ExitOK || r.stdout != mainUsage || r.stderr != "" {
			t.Errorf("%v: %+v", args, r)
		}
	}
	for args, want := range map[[2]string]string{
		{"help", "encrypt"}:   encryptUsage,
		{"help", "decrypt"}:   decryptUsage,
		{"help", "e"}:         encryptUsage,
		{"help", "d"}:         decryptUsage,
		{"e", "-h"}:           encryptUsage,
		{"d", "--help"}:       decryptUsage,
		{"help", "version"}:   versionUsage,
		{"encrypt", "-h"}:     encryptUsage,
		{"decrypt", "--help"}: decryptUsage,
		{"encrypt", "-help"}:  encryptUsage,
	} {
		r := run(t, args[:]...)
		if r.status != ExitOK || r.stdout != want || r.stderr != "" {
			t.Errorf("%v: %+v", args, r)
		}
	}
	expect(t, run(t, "help", "nope"), ExitUsage, `lce: no help for "nope"`)
	expect(t, run(t, "help", "encrypt", "decrypt"), ExitUsage, `no help for "encrypt decrypt"`)
	expect(t, run(t, "frobnicate"), ExitUsage, "lce: unknown command \"frobnicate\"\nRun \"lce help\"")
}

func TestVersion(t *testing.T) {
	for _, arg := range []string{"version", "--version", "-version"} {
		r := run(t, arg)
		for _, want := range []string{"lce ", "SPEC.md draft 0.4, algorithm version 1",
			"T = 6000, S = 16, k = 30, R = 24, version 1", "file format: 1", runtime.Version()} {
			if !strings.Contains(r.stdout, want) {
				t.Errorf("%s: %q has no %q", arg, r.stdout, want)
			}
		}
		if r.status != ExitOK || r.stderr != "" {
			t.Errorf("%s: %+v", arg, r)
		}
	}
	expect(t, run(t, "version", "--extra"), ExitUsage, "lce: version takes no arguments")

	for _, c := range []struct {
		info *debug.BuildInfo
		ok   bool
		want string
	}{
		{&debug.BuildInfo{Main: debug.Module{Version: "v1.2.3"}}, true, "v1.2.3"},
		{&debug.BuildInfo{}, true, "(devel)"},
		{nil, false, "(devel)"},
	} {
		if got := versionOf(c.info, c.ok); got != c.want {
			t.Errorf("versionOf(%v, %v) = %q, want %q", c.info, c.ok, got, c.want)
		}
	}
}

func TestUsageErrors(t *testing.T) {
	t.Parallel()
	dir, key := workspace(t)
	notes := put(t, filepath.Join(dir, "notes.txt"), []byte("notes"))
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"encrypt"}, "lce encrypt: no key: give the key file with -k"},
		{[]string{"encrypt", "-k", "", notes}, "no key"},
		{[]string{"encrypt", "-k", key, notes, notes}, "expected at most one INPUT, but got 2"},
		{[]string{"decrypt", "-k", key, notes, "-", "-"}, "expected at most one INPUT, but got 3"},
		{[]string{"encrypt", "-x", notes}, "flag provided but not defined: -x"},
		{[]string{"encrypt", notes, "-k"}, "flag needs an argument: -k"},
		{[]string{"encrypt", "-f=maybe", "-k", key, notes}, `invalid boolean value "maybe" for -f`},
		{[]string{"decrypt", "-k", key, "-o", "", notes}, "an empty OUTPUT: give a file name, or - for standard output"},
		{[]string{"decrypt", "-k", key, "--output=", notes}, "an empty OUTPUT"},
		{[]string{"encrypt", "-k", key, ""}, "an empty INPUT: give a file name, or - for standard input"},
		{[]string{"encrypt", "-k", key, "-o", "--", notes, "-x"}, "flag provided but not defined: -x"},
	} {
		r := run(t, c.args...)
		hint := `Run "lce help ` + c.args[0] + `" for its options.`
		if r.status != ExitUsage || !strings.Contains(r.stderr, c.want) || !strings.Contains(r.stderr, hint) {
			t.Errorf("%v: %+v; want %q", c.args, r, c.want)
		}
	}
	if !slices.Equal(files(t, dir), []string{"key.txt", "notes.txt"}) {
		t.Errorf("a usage error left files: %v", files(t, dir))
	}
}

func TestRoundTrip(t *testing.T) {
	t.Parallel()
	dir, key := workspace(t)
	for _, n := range []int{0, 1, 1000, 200_000} {
		pt := make([]byte, n)
		_, _ = rand.Read(pt)
		in := put(t, filepath.Join(dir, "plain.bin"), pt)
		enc, back := filepath.Join(dir, "plain.lce"), filepath.Join(dir, "back.bin")
		for _, form := range []struct {
			flags []string
			ok    func(ct []byte) bool
		}{
			{nil, func(ct []byte) bool { return strings.HasPrefix(string(ct), textStart) }},
			{[]string{"-b"}, func(ct []byte) bool { return len(ct) == n+container.Overhead && string(ct[:8]) == "LIFECIPH" }},
		} {
			expect(t, run(t, slices.Concat([]string{"encrypt", "-k", key, "-o", enc, "-f"}, form.flags, []string{in})...),
				ExitOK, "")
			if ct := read(t, enc); !form.ok(ct) {
				t.Fatalf("%d bytes, %v: the encrypted file starts %q", n, form.flags, ct[:min(40, len(ct))])
			}
			expect(t, run(t, "decrypt", "-k", key, "-o", back, "-f", enc), ExitOK, "")
			if !bytes.Equal(read(t, back), pt) {
				t.Fatalf("%d bytes, %v: decryption doesn't give the plaintext back", n, form.flags)
			}
		}
		for _, path := range []string{enc, back} {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
		}
	}
	if !slices.Equal(files(t, dir), []string{"key.txt", "plain.bin"}) {
		t.Errorf("left behind: %v", files(t, dir))
	}
}

func TestForms(t *testing.T) {
	// encrypt writes text, or binary with -b, and decrypt reads either, text in other text too.
	t.Parallel()
	_, key := workspace(t)
	pipe := func(stdin string, args ...string) result {
		return runIn(t.Context(), strings.NewReader(stdin), rand.Reader, args...)
	}
	text, bin := pipe("both forms", "e", "-k", key), pipe("both forms", "e", "-k", key, "--binary")
	if !strings.HasPrefix(text.stdout, textStart) || !strings.HasSuffix(text.stdout, "-------\n") {
		t.Fatalf("the text form: %+v", text)
	}
	if !strings.HasPrefix(bin.stdout, "LIFECIPH") || len(bin.stdout) != len("both forms")+container.Overhead {
		t.Fatalf("the binary form: %+v", bin)
	}
	for name, in := range map[string]string{
		"text":   text.stdout,
		"binary": bin.stdout,
		"text in an email, with CRLFs": "Subject: the figures\r\n\r\n" + strings.ReplaceAll(text.stdout, "\n", "\r\n") +
			"\r\n-- \r\nsent from my phone\r\n",
	} {
		if back := pipe(in, "d", "-k", key); back.status != ExitOK || back.stdout != "both forms" {
			t.Errorf("%s: %+v", name, back)
		}
	}
	expect(t, run(t, "d", "-k", key, "-b"), ExitUsage, "lce decrypt: flag provided but not defined: -b")
}

func TestOptionForms(t *testing.T) {
	t.Parallel()
	dir, key := workspace(t)
	notes := put(t, filepath.Join(dir, "notes.txt"), []byte("attack at dawn"))
	enc, back := filepath.Join(dir, "notes.lc"), filepath.Join(dir, "back.txt")
	for _, args := range [][]string{
		{"encrypt", "-k", key, "-o", enc, "-f", notes},
		{"encrypt", notes, "-k", key, "-o", enc, "-f"}, // options after INPUT
		{"encrypt", "--key", key, "--output", enc, "--force", notes},
		{"encrypt", "-k=" + key, "-o=" + enc, "-f=true", notes},
	} {
		expect(t, run(t, args...), ExitOK, "")
		expect(t, run(t, "decrypt", "-f", "-k", key, "-o", back, enc), ExitOK, "")
		if got := read(t, back); string(got) != "attack at dawn" {
			t.Fatalf("%v: decrypted to %q", args, got)
		}
	}
}

func TestDoubleDash(t *testing.T) {
	dir, key := workspace(t)
	t.Chdir(dir)
	put(t, "-dash.txt", []byte("an awkward name"))
	expect(t, run(t, "encrypt", "-k", key, "-o", "-dash.lc", "--", "-dash.txt"), ExitOK, "")
	expect(t, run(t, "decrypt", "-k", key, "-o", "back.txt", "--", "-dash.lc"), ExitOK, "")
	if got := read(t, "back.txt"); string(got) != "an awkward name" {
		t.Errorf("decrypted to %q", got)
	}
	// "--" as the value of -o doesn't end the options: -f after INPUT is still an option.
	put(t, "--", []byte("an old file named --"))
	expect(t, run(t, "encrypt", "-k", key, "-o", "--", "back.txt", "-f"), ExitOK, "")
	if r := run(t, "decrypt", "-k", key, "-o", "-", "--", "--"); r.status != ExitOK || r.stdout != "an awkward name" {
		t.Errorf("decrypting the file named --: %+v", r)
	}
}

func TestKeyForms(t *testing.T) {
	t.Parallel()
	dir, hexKey := workspace(t)
	raw := demoKeyBytes(t)
	var bits strings.Builder
	for _, b := range raw {
		for i := 7; i >= 0; i-- {
			bits.WriteByte('0' + b>>i&1)
		}
		bits.WriteByte('\n')
	}
	rawKey := put(t, filepath.Join(dir, "key.bin"), raw)
	bitKey := put(t, filepath.Join(dir, "key.bits"), []byte(bits.String()))
	crlfKey := put(t, filepath.Join(dir, "key.crlf"), []byte("\uFEFF"+strings.ReplaceAll(demoKey, "\n", "\r\n")))
	notes := put(t, filepath.Join(dir, "notes.txt"), []byte("one key, four forms"))
	expect(t, run(t, "encrypt", "-k", hexKey, "-o", notes+".lc", notes), ExitOK, "")
	for _, key := range []string{rawKey, bitKey, crlfKey, hexKey} {
		r := run(t, "decrypt", "-k", key, notes+".lc")
		if r.status != ExitOK || r.stdout != "one key, four forms" {
			t.Errorf("%s: %+v", key, r)
		}
	}
}

func TestKeyRefused(t *testing.T) {
	t.Parallel()
	dir, _ := workspace(t)
	notes := put(t, filepath.Join(dir, "notes.txt"), []byte("notes"))
	missingInput := filepath.Join(dir, "missing.txt")
	glider := put(t, filepath.Join(dir, "glider.key"), []byte(gliderKey))
	empty := put(t, filepath.Join(dir, "empty.key"), make([]byte, 128))
	bad := put(t, filepath.Join(dir, "bad.key"), []byte("not a key"))
	for _, c := range []struct {
		key, input, want string
	}{
		{glider, notes, "the key in " + glider + " fails the key check (SPEC.md §6.1): its first 6000 generations " +
			"aren't all distinct, so it can't be a vetted key"},
		{empty, notes, "fails the key check"},
		// INPUT is opened before the key setup, so its problems show at once.
		{glider, missingInput, "open " + missingInput + ": no such file or directory"},
		{bad, notes, "reading the key: " + bad + ": not a key"},
		{filepath.Join(dir, "missing.key"), notes, "reading the key: open "},
	} {
		for _, cmd := range []string{"encrypt", "decrypt"} {
			r := run(t, cmd, "-k", c.key, "-o", filepath.Join(dir, "out"), c.input)
			if r.status != ExitFailure || !strings.HasPrefix(r.stderr, "lce "+cmd+": ") || !strings.Contains(r.stderr, c.want) {
				t.Errorf("%s with %s: %+v; want %q", cmd, c.key, r, c.want)
			}
		}
	}
	if slices.Contains(files(t, dir), "out") {
		t.Error("a refused key still produced output")
	}
}

func TestOutputRules(t *testing.T) {
	t.Parallel()
	dir, key := workspace(t)
	notes := put(t, filepath.Join(dir, "notes.txt"), []byte("notes"))
	existing := put(t, filepath.Join(dir, "existing.lc"), []byte("keep me"))

	expect(t, run(t, "encrypt", "-k", key, "-o", existing, notes), ExitFailure,
		"lce encrypt: OUTPUT "+existing+" exists: use -f to replace it")
	if string(read(t, existing)) != "keep me" {
		t.Error("an existing OUTPUT changed without -f")
	}
	expect(t, run(t, "encrypt", "-k", key, "-o", existing, "-f", notes), ExitOK, "")
	if !strings.HasPrefix(string(read(t, existing)), textStart) {
		t.Error("-f didn't replace OUTPUT")
	}
	if err := os.Remove(existing); err != nil {
		t.Fatal(err)
	}

	missingDir := filepath.Join(dir, "no", "such", "dir.lc")
	underFile := filepath.Join(notes, "out.lc")
	expect(t, run(t, "encrypt", "-k", key, "-o", dir, "-f", notes), ExitFailure, "OUTPUT "+dir+" is a directory")
	expect(t, run(t, "encrypt", "-k", key, "-o", missingDir, notes), ExitFailure,
		"lce encrypt: OUTPUT "+missingDir+": no such file or directory")
	expect(t, run(t, "encrypt", "-k", key, "-o", underFile, notes), ExitFailure,
		"lce encrypt: OUTPUT "+underFile+": not a directory")
	expect(t, run(t, "encrypt", "-k", key, "-o", key, "-f", notes), ExitFailure, "OUTPUT "+key+" is the key file")
	if string(read(t, key)) != demoKey {
		t.Fatal("the key file changed")
	}

	// INPUT may be OUTPUT: the file is replaced by its encryption, and then by its decryption.
	expect(t, run(t, "encrypt", "-k", key, "-o", notes, "-f", notes), ExitOK, "")
	if !strings.HasPrefix(string(read(t, notes)), textStart) {
		t.Error("encrypting a file onto itself didn't replace it")
	}
	expect(t, run(t, "decrypt", "-k", key, "-o", notes, "-f", notes), ExitOK, "")
	if string(read(t, notes)) != "notes" {
		t.Error("decrypting a file onto itself didn't give the plaintext back")
	}
	if !slices.Equal(files(t, dir), []string{"key.txt", "notes.txt"}) {
		t.Errorf("left behind: %v", files(t, dir))
	}
}

func TestOutputLinks(t *testing.T) {
	// Replacing a link would leave the file it points to, or the file's other names, as they were: lce refuses.
	t.Parallel()
	dir, key := workspace(t)
	notes := put(t, filepath.Join(dir, "notes.txt"), []byte("notes"))
	symlink, dangling, hardLink := filepath.Join(dir, "symlink"), filepath.Join(dir, "dangling"), filepath.Join(dir, "hard")
	for _, err := range []error{
		os.Symlink(notes, symlink), os.Symlink(filepath.Join(dir, "nowhere"), dangling), os.Link(notes, hardLink),
	} {
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"-f", "-o", symlink, symlink}, "OUTPUT " + symlink + " is a symbolic link: name the file it points to"},
		{[]string{"-f", "-o", symlink, notes}, "is a symbolic link"},
		{[]string{"-o", dangling, notes}, "OUTPUT " + dangling + " is a symbolic link"},
		{[]string{"-f", "-o", hardLink, hardLink}, "OUTPUT " + hardLink + " has other hard links, " +
			"which replacing it would leave as they are"},
		{[]string{"-f", "-o", notes, notes}, "OUTPUT " + notes + " has other hard links"},
		{[]string{"-o", notes, notes}, "OUTPUT " + notes + " exists: use -f"},
	} {
		expect(t, run(t, slices.Concat([]string{"encrypt", "-k", key}, c.args)...), ExitFailure, c.want)
	}
	if string(read(t, notes)) != "notes" || string(read(t, hardLink)) != "notes" {
		t.Error("a link's file changed")
	}
	if _, err := os.Lstat(filepath.Join(dir, "nowhere")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("writing through a dangling link: %v", err)
	}
	if !slices.Equal(files(t, dir), []string{"dangling", "hard", "key.txt", "notes.txt", "symlink"}) {
		t.Errorf("left behind: %v", files(t, dir))
	}
}

// appearing is standard input that, on its first read, puts a file at path: another process's, which takes OUTPUT's
// name while lce runs.
type appearing struct {
	t      *testing.T
	path   string
	file   func(path string) error
	r      io.Reader
	placed bool
}

func (a *appearing) Read(p []byte) (int, error) {
	if !a.placed {
		a.placed = true
		if err := a.file(a.path); err != nil {
			a.t.Error(err)
		}
	}
	return a.r.Read(p)
}

func TestOutputAppears(t *testing.T) {
	// Without -f, a file that takes OUTPUT's name during the run stays. With -f, a link that does stays too.
	t.Parallel()
	dir, key := workspace(t)
	theirs := func(path string) error { return os.WriteFile(path, []byte("theirs"), 0o600) }
	target := put(t, filepath.Join(dir, "target"), []byte("target"))
	link := func(path string) error { return os.Symlink(target, path) }
	for _, c := range []struct {
		name  string
		force bool
		file  func(string) error
		want  string
	}{
		{"a file, without -f", false, theirs, " exists: use -f to replace it"},
		{"a symbolic link, with -f", true, link, " is a symbolic link: name the file it points to"},
	} {
		for _, cmd := range []string{"encrypt", "decrypt"} {
			out := filepath.Join(dir, "out")
			ct := run(t, "encrypt", "-k", key, "-b", target).stdout
			in := &appearing{t: t, path: out, file: c.file, r: strings.NewReader(ct)}
			args := []string{cmd, "-k", key, "-o", out}
			if c.force {
				args = append(args, "-f")
			}
			status, stderr := runTo(t, in, io.Discard, args...)
			if status != ExitFailure || stderr != "lce "+cmd+": OUTPUT "+out+c.want+"\n" {
				t.Errorf("%s, %s: status %d, %q", c.name, cmd, status, stderr)
			}
			if data, err := os.ReadFile(out); err != nil || string(data) != map[bool]string{false: "theirs", true: "target"}[c.force] {
				t.Errorf("%s, %s: OUTPUT holds %q, %v", c.name, cmd, data, err)
			}
			if err := os.Remove(out); err != nil {
				t.Fatal(err)
			}
		}
	}
	if !slices.Equal(files(t, dir), []string{"key.txt", "target"}) {
		t.Errorf("left behind: %v", files(t, dir))
	}
}

func TestStandardOutputIsAFile(t *testing.T) {
	// Standard output redirected to INPUT or to the key file is refused; to any other file, it's fine.
	t.Parallel()
	dir, key := workspace(t)
	big := put(t, filepath.Join(dir, "big.bin"), bytes.Repeat([]byte("big"), 1000))
	appendTo := func(path string) *os.File {
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = f.Close() })
		return f
	}
	open := func(path string) *os.File {
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = f.Close() })
		return f
	}
	for _, c := range []struct {
		stdin  io.Reader
		stdout *os.File
		args   []string
		want   string
	}{
		{nil, appendTo(big), []string{"encrypt", "-b", "-k", key, big}, "lce encrypt: standard output is INPUT\n"},
		{open(big), appendTo(big), []string{"encrypt", "-k", key}, "lce encrypt: standard output is INPUT\n"},
		{nil, appendTo(big), []string{"decrypt", "-k", key, big}, "lce decrypt: standard output is INPUT\n"},
		{nil, appendTo(key), []string{"encrypt", "-k", key, big}, "lce encrypt: standard output is the key file\n"},
	} {
		if status, stderr := runTo(t, c.stdin, c.stdout, c.args...); status != ExitFailure || stderr != c.want {
			t.Errorf("%v: status %d, %q", c.args, status, stderr)
		}
	}
	if !bytes.Equal(read(t, big), bytes.Repeat([]byte("big"), 1000)) || string(read(t, key)) != demoKey {
		t.Fatal("a refused run changed a file")
	}

	out := put(t, filepath.Join(dir, "out.lce"), nil)
	if status, stderr := runTo(t, nil, appendTo(out), "encrypt", "-b", "-k", key, big); status != ExitOK || stderr != "" {
		t.Errorf("standard output to another file: status %d, %q", status, stderr)
	}
	if status, stderr := runTo(t, open(out), io.Discard, "decrypt", "-k", key); status != ExitOK || stderr != "" {
		t.Errorf("decrypting it: status %d, %q", status, stderr)
	}
}

func TestFormDetection(t *testing.T) {
	// The binary form starts with the magic and a zero byte. Anything else is text, which may come after other text,
	// even text that starts with the magic, or after a byte-order mark.
	t.Parallel()
	_, key := workspace(t)
	text := runIn(t.Context(), strings.NewReader("found it"), rand.Reader, "e", "-k", key).stdout
	bin := []byte(runIn(t.Context(), strings.NewReader("found it"), rand.Reader, "e", "-b", "-k", key).stdout)
	version2 := slices.Concat(bin[:11], []byte{2}, bin[12:])
	for name, c := range map[string]struct{ in, stdout, stderr string }{
		"text after a preface starting LIFECIPH": {"LIFECIPHER message below\n\n" + text, "found it", ""},
		"text after a byte-order mark":           {"\uFEFF" + text, "found it", ""},
		"binary":                                 {string(bin), "found it", ""},
		"binary, format version 2":               {string(version2), "", "standard input: unsupported format version 2\n"},
		"the magic alone":                        {"LIFECIPH", "", "standard input: not a file encrypted by lce\n"},
	} {
		r := runIn(t.Context(), strings.NewReader(c.in), rand.Reader, "d", "-k", key)
		if r.stdout != c.stdout || !strings.HasSuffix(r.stderr, c.stderr) || (r.stderr == "") != (c.stderr == "") {
			t.Errorf("%s: %+v", name, r)
		}
	}
	// A failure to read the input's start is reported as itself, not as a file in the wrong form.
	r := runIn(t.Context(), iotest.ErrReader(errors.New("unreadable")), rand.Reader, "d", "-k", key)
	if r.status != ExitFailure || r.stderr != "lce decrypt: unreadable\n" {
		t.Errorf("an unreadable input: %+v", r)
	}
}

func TestDecryptRefuses(t *testing.T) {
	t.Parallel()
	dir, key := workspace(t)
	notes := put(t, filepath.Join(dir, "notes.txt"), []byte("the plaintext"))
	expect(t, run(t, "encrypt", "-k", key, "-b", "-o", notes+".lc", notes), ExitOK, "")
	expect(t, run(t, "encrypt", "-k", key, "-o", notes+".lce", notes), ExitOK, "")
	ct, text := read(t, notes+".lc"), string(read(t, notes+".lce"))
	changed := slices.Clone(ct)
	changed[len(changed)-20] ^= 1
	tampered := put(t, filepath.Join(dir, "tampered.lc"), changed)
	truncated := put(t, filepath.Join(dir, "truncated.lc"), ct[:100])
	tamperedText := put(t, filepath.Join(dir, "tampered.lce"), []byte(changeIV(text)))
	truncatedText := put(t, filepath.Join(dir, "truncated.lce"), []byte(text[:len(text)/2]))
	malformed := put(t, filepath.Join(dir, "malformed.lce"), []byte(strings.Replace(text, "T: 6000", "T: 06000", 1)))
	plain := put(t, filepath.Join(dir, "plain.lc"), []byte(strings.Repeat("not encrypted ", 20)))
	demoSetKey, err := newKey(lifecipher.Demo(), demoKeyBytes(t))
	if err != nil {
		t.Fatal(err)
	}
	var demoFile bytes.Buffer
	err = container.Encrypt(t.Context(), demoSetKey, make([]byte, lifecipher.IVSize), strings.NewReader("demo"), &demoFile)
	if err != nil {
		t.Fatal(err)
	}
	demoSet := put(t, filepath.Join(dir, "demo-set.lc"), demoFile.Bytes())
	for _, c := range []struct{ input, want string }{
		{tampered, tampered + ": the tag doesn't match: the file was changed or damaged, or this isn't its key. " +
			"Nothing was written"},
		{tamperedText, tamperedText + ": the tag doesn't match"},
		{truncated, truncated + ": the file is truncated"},
		{truncatedText, truncatedText + ": the file is truncated: the text stops at line "},
		{demoSet, demoSet + ": the file was encrypted under T = 6000, S = 16, k = 4, R = 16, version 1, " +
			"and lce uses T = 6000, S = 16, k = 30, R = 24, version 1"},
		{malformed, malformed + `: not in lce's text form: line 3: expected "T:" and a number`},
		{plain, plain + ": not a file encrypted by lce"},
		{filepath.Join(dir, "missing.lc"), "missing.lc"},
		{dir, "INPUT " + dir + " is a directory"},
	} {
		for _, out := range []string{filepath.Join(dir, "out.txt"), "-"} {
			r := run(t, "decrypt", "-k", key, "-o", out, c.input)
			if r.status != ExitFailure || r.stdout != "" || !strings.HasPrefix(r.stderr, "lce decrypt: ") ||
				!strings.Contains(r.stderr, c.want) {
				t.Errorf("%s to %s: %+v; want %q", c.input, out, r, c.want)
			}
		}
	}
	if slices.ContainsFunc(files(t, dir), func(name string) bool { return strings.HasPrefix(name, ".") || name == "out.txt" }) {
		t.Errorf("a refused file left output behind: %v", files(t, dir))
	}
}

func TestStandardStreams(t *testing.T) {
	// Without INPUT the commands read standard input, and without -o they write standard output. - names either one.
	t.Parallel()
	dir, key := workspace(t)
	notes := put(t, filepath.Join(dir, "notes.txt"), []byte("through the pipes"))
	pipe := func(stdin string, args ...string) result {
		return runIn(t.Context(), strings.NewReader(stdin), rand.Reader, args...)
	}
	for _, args := range [][]string{
		{"encrypt", "-k", key},
		{"encrypt", "-k", key, "-"},
		{"encrypt", "-k", key, "-o", "-", "-"},
		{"encrypt", "-k", key, notes}, // a file INPUT, written to standard output
	} {
		r := pipe("through the pipes", args...)
		if r.status != ExitOK || !strings.HasPrefix(r.stdout, textStart) {
			t.Fatalf("%v: %+v", args, r)
		}
		for _, back := range []result{pipe(r.stdout, "decrypt", "-k", key), pipe(r.stdout, "decrypt", "-k", key, "-o", "-", "-")} {
			if back.status != ExitOK || back.stdout != "through the pipes" {
				t.Errorf("%v, decrypted from standard input: %+v", args, back)
			}
		}
		bad := pipe(changeIV(r.stdout), "decrypt", "-k", key)
		if bad.status != ExitFailure || bad.stdout != "" || !strings.Contains(bad.stderr, "standard input: the tag doesn't match") {
			t.Errorf("%v, changed: %+v", args, bad)
		}
	}
	if !slices.Equal(files(t, dir), []string{"key.txt", "notes.txt"}) {
		t.Errorf("the standard streams left files: %v", files(t, dir))
	}
}

func TestShortCommands(t *testing.T) {
	// e and d are encrypt and decrypt, and their messages name the command in full.
	t.Parallel()
	_, key := workspace(t)
	enc := runIn(t.Context(), strings.NewReader("short and sweet"), rand.Reader, "e", "-k", key)
	dec := runIn(t.Context(), strings.NewReader(enc.stdout), rand.Reader, "d", "-k", key)
	if enc.status != ExitOK || dec.status != ExitOK || dec.stdout != "short and sweet" {
		t.Errorf("e then d: %+v, %+v", enc, dec)
	}
	expect(t, run(t, "e"), ExitUsage, "lce encrypt: no key")
	expect(t, run(t, "d", "-k", key, "a", "b"), ExitUsage, "lce decrypt: expected at most one INPUT")
	expect(t, run(t, "x"), ExitUsage, `lce: unknown command "x"`)
}

// textStart is how the text form starts.
const textStart = "-----BEGIN LIFE CIPHER MESSAGE-----"

// changeIV changes the first character of a text form's IV to another base64 digit: the text stays well formed, but
// the message changes.
func changeIV(text string) string {
	line := strings.Index(text, "-----IV-")
	at := line + strings.Index(text[line:], "\n") + 1
	digit := "A"
	if text[at] == 'A' {
		digit = "B"
	}
	return text[:at] + digit + text[at+1:]
}

// brokenWriter fails every write.
type brokenWriter struct{}

func (brokenWriter) Write([]byte) (int, error) { return 0, errors.New("broken pipe") }

func TestFailures(t *testing.T) {
	t.Parallel()
	dir, key := workspace(t)
	notes := put(t, filepath.Join(dir, "notes.txt"), []byte("notes"))
	expect(t, runIn(t.Context(), nil, iotest.ErrReader(errors.New("no entropy")), "encrypt", "-k", key, notes),
		ExitFailure, "lce encrypt: drawing a random IV: no entropy")
	expect(t, run(t, "encrypt", "-k", key, filepath.Join(dir, "missing.txt")), ExitFailure, "missing.txt")

	// An INPUT that's a directory is refused before anything is written.
	for _, cmd := range []string{"encrypt", "decrypt"} {
		r := run(t, cmd, "-k", key, dir)
		if r.status != ExitFailure || r.stdout != "" || r.stderr != "lce "+cmd+": INPUT "+dir+" is a directory\n" {
			t.Errorf("%s with a directory: %+v", cmd, r)
		}
	}

	expect(t, run(t, "encrypt", "-k", key, "-o", notes+".lc", notes), ExitOK, "")
	for _, args := range [][]string{
		{"encrypt", "-k", key, notes},
		{"decrypt", "-k", key, notes + ".lc"},
	} {
		var stderr bytes.Buffer
		status := Run(t.Context(), args, Env{Stdin: nil, Stdout: brokenWriter{}, Stderr: &stderr, Rand: rand.Reader})
		if status != ExitFailure || !strings.Contains(stderr.String(), "broken pipe") {
			t.Errorf("%v to a broken standard output: %d, %q", args, status, stderr.String())
		}
	}
}

func TestInterrupted(t *testing.T) {
	t.Parallel()
	dir, key := workspace(t)
	notes := put(t, filepath.Join(dir, "notes.txt"), []byte("notes"))
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	expect(t, runIn(ctx, nil, rand.Reader, "encrypt", "-k", key, "-o", notes+".lc", notes), ExitFailure,
		"lce encrypt: interrupted")
	if !slices.Equal(files(t, dir), []string{"key.txt", "notes.txt"}) {
		t.Errorf("an interrupted run left files: %v", files(t, dir))
	}
}

// warnings collects writeFile's warnings.
type warnings []string

func (w *warnings) warn(msg string) { *w = append(*w, msg) }

func TestWriteFile(t *testing.T) {
	// Not parallel: it replaces renameNew and link, which every run uses.
	ctx := t.Context()
	dir := t.TempDir()
	path := filepath.Join(dir, "out")
	write := func(s string) func(io.Writer) error {
		return func(w io.Writer) error { _, err := io.WriteString(w, s); return err }
	}
	var g Guard
	var warned warnings

	// A file appears whole, or not at all.
	if err := writeFile(ctx, &g, path, false, write("whole"), warned.warn); err != nil {
		t.Fatal(err)
	}
	failed := errors.New("failed")
	err := writeFile(ctx, &g, path, true, func(w io.Writer) error { _, _ = io.WriteString(w, "half"); return failed },
		warned.warn)
	if !errors.Is(err, failed) || string(read(t, path)) != "whole" {
		t.Errorf("a failed fill: %v, and the file holds %q", err, read(t, path))
	}

	// Flushing fails, here because fill closed the file. The error names OUTPUT, not the temporary file.
	err = writeFile(ctx, &g, path, true, func(w io.Writer) error { return w.(outputFile).f.Close() }, warned.warn)
	if err == nil || err.Error() != "OUTPUT "+path+": file already closed" || string(read(t, path)) != "whole" {
		t.Errorf("a failed flush: %v", err)
	}
	// So does a failed write.
	err = writeFile(ctx, &g, path, true, func(w io.Writer) error {
		_ = w.(outputFile).f.Close()
		return write("more")(w)
	}, warned.warn)
	if err == nil || err.Error() != "OUTPUT "+path+": file already closed" {
		t.Errorf("a failed write: %v", err)
	}
	// And a temporary file that can't be created.
	missing := filepath.Join(dir, "missing", "out")
	if err = writeFile(ctx, &g, missing, false, write("x"), warned.warn); err == nil ||
		err.Error() != "OUTPUT "+missing+": no such file or directory" {
		t.Errorf("no directory: %v", err)
	}

	// The run is interrupted while fill runs: nothing is published.
	interrupted, cancel := context.WithCancel(ctx)
	err = writeFile(interrupted, &g, filepath.Join(dir, "interrupted"), false, func(w io.Writer) error {
		cancel()
		return write("cut short")(w)
	}, warned.warn)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("an interrupted run: %v", err)
	}

	// A stopped Guard: no temporary file, and nothing published.
	var stopped Guard
	stopped.Stop()
	err = writeFile(ctx, &stopped, filepath.Join(dir, "stopped"), false, write("x"), warned.warn)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("a stopped Guard: %v", err)
	}
	var stopping Guard
	err = writeFile(ctx, &stopping, filepath.Join(dir, "stopping"), false, func(w io.Writer) error {
		stopping.Stop()
		return write("x")(w)
	}, warned.warn)
	if err == nil {
		t.Error("a run stopped while it wrote OUTPUT succeeded")
	}

	// Without a rename that refuses to replace a file, writeFile links, and removes the temporary name.
	defer func(f func(string, string) error) { renameNew = f }(renameNew)
	defer func(f func(string, string) error) { link = f }(link)
	renameNew = func(string, string) error { return errors.ErrUnsupported }
	linked := filepath.Join(dir, "linked")
	if err := writeFile(ctx, &g, linked, false, write("linked"), warned.warn); err != nil || string(read(t, linked)) != "linked" {
		t.Errorf("by a link: %v", err)
	}
	if err := writeFile(ctx, &g, linked, false, write("again"), warned.warn); err == nil || err.Error() != "OUTPUT "+linked+
		" exists: use -f to replace it" {
		t.Errorf("by a link, to a file that exists: %v", err)
	}
	// Without hard links either, writeFile checks that OUTPUT is absent, and renames.
	link = func(string, string) error { return errors.ErrUnsupported }
	renamed := filepath.Join(dir, "renamed")
	if err := writeFile(ctx, &g, renamed, false, write("renamed"), warned.warn); err != nil || string(read(t, renamed)) != "renamed" {
		t.Errorf("by a rename: %v", err)
	}
	if err := writeFile(ctx, &g, renamed, false, write("again"), warned.warn); err == nil || err.Error() != "OUTPUT "+renamed+
		" exists: use -f to replace it" {
		t.Errorf("by a rename, to a file that exists: %v", err)
	}
	// Renaming fails, here because the temporary file is gone.
	link = func(tmp, _ string) error { return cmp.Or(os.Remove(tmp), errors.ErrUnsupported) }
	gone := filepath.Join(dir, "gone")
	if err := writeFile(ctx, &g, gone, false, write("x"), warned.warn); err == nil || err.Error() != "OUTPUT "+gone+
		": no such file or directory" {
		t.Errorf("a failed rename: %v", err)
	}
	// So does a rename that refuses to replace a file, here for the same reason.
	renameNew = func(tmp, path string) error { return cmp.Or(os.Remove(tmp), renameNoReplace(tmp, path)) }
	if err := writeFile(ctx, &g, gone, false, write("x"), warned.warn); err == nil || err.Error() != "OUTPUT "+gone+
		": no such file or directory" {
		t.Errorf("a failed rename that refuses to replace: %v", err)
	}

	if len(warned) > 0 || !slices.Equal(files(t, dir), []string{"linked", "out", "renamed"}) {
		t.Errorf("warnings %q, and left behind: %v", warned, files(t, dir))
	}
}

func TestFlush(t *testing.T) {
	var warned warnings
	flush(nil, "out", warned.warn) // a directory lce couldn't open: nothing to do
	d, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	flush(d, "out", warned.warn)
	if len(warned) != 0 || d.Close() == nil {
		t.Fatalf("flushing a directory: warnings %q, and it's still open", warned)
	}
	flush(d, "out", warned.warn) // closed already, so flushing it fails
	if len(warned) != 1 || !strings.HasPrefix(warned[0], "OUTPUT out is written, but flushing its directory to disk failed: ") {
		t.Errorf("a failed flush: %q", warned)
	}
}

func TestSettled(t *testing.T) {
	// Not parallel: it changes settle. At the end of the input, a settled reader waits for settle, or until the
	// context is done.
	defer func(d time.Duration) { settle = d }(settle)
	settle = time.Hour
	done, cancel := context.WithCancel(t.Context())
	cancel()
	if n, err := (settled{done, strings.NewReader("")}).Read(make([]byte, 8)); n != 0 || !errors.Is(err, io.EOF) {
		t.Errorf("a done context: %d, %v", n, err)
	}
	settle = 20 * time.Millisecond
	start := time.Now()
	got, err := io.ReadAll(settled{t.Context(), iotest.OneByteReader(strings.NewReader("abc"))})
	if string(got) != "abc" || err != nil || time.Since(start) < settle {
		t.Errorf("read %q, %v, in %v", got, err, time.Since(start))
	}
}

func TestPipedInput(t *testing.T) {
	// Encrypting from a pipe waits a moment at its end, and then gives the whole message.
	t.Parallel()
	_, key := workspace(t)
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	if _, err := w.WriteString("through a pipe"); err != nil || w.Close() != nil {
		t.Fatal(err)
	}
	var enc bytes.Buffer
	if status, stderr := runTo(t, r, &enc, "e", "-k", key); status != ExitOK {
		t.Fatalf("status %d, %s", status, stderr)
	}
	if back := runIn(t.Context(), &enc, rand.Reader, "d", "-k", key); back.stdout != "through a pipe" {
		t.Errorf("%+v", back)
	}
}

func TestOutputError(t *testing.T) {
	other := errors.New("other")
	for _, c := range []struct {
		err  error
		want string
	}{
		{&fs.PathError{Op: "write", Path: ".lce-1.tmp", Err: syscall.ENOSPC}, "OUTPUT out: " + syscall.ENOSPC.Error()},
		{&os.LinkError{Op: "rename", Old: ".lce-1.tmp", New: "out", Err: syscall.EACCES}, "OUTPUT out: " + syscall.EACCES.Error()},
		{other, "OUTPUT out: other"},
	} {
		if err := outputError("out", c.err); err.Error() != c.want || !errors.Is(err, errors.Unwrap(c.err)) &&
			!errors.Is(err, other) {
			t.Errorf("%v: %v", c.err, err)
		}
	}
	if outputError("out", nil) != nil {
		t.Error("no error became one")
	}
}

func TestGuard(t *testing.T) {
	dir := t.TempDir()
	var g Guard
	create := func() *os.File {
		f, err := g.create(filepath.Join(dir, "out"))
		if err != nil {
			t.Fatal(err)
		}
		return f
	}
	a, b, c := create(), create(), create()
	g.discard(a)
	if err := g.publish(t.Context(), c, func() error { return os.Rename(c.Name(), filepath.Join(dir, "c")) }); err != nil {
		t.Fatal(err)
	}
	g.Stop() // removes b, and leaves c, which has its name now
	g.Stop()
	if !slices.Equal(files(t, dir), []string{"c"}) {
		t.Errorf("after Stop: %v", files(t, dir))
	}
	// Once stopped, a Guard creates no file, and publishes nothing. It doesn't remove a file twice: a file that took
	// the name of one Stop removed stays.
	if f, err := g.create(filepath.Join(dir, "out")); f != nil || !errors.Is(err, context.Canceled) {
		t.Errorf("a stopped Guard created a file: %v", err)
	}
	put(t, b.Name(), []byte("another file"))
	g.discard(b)
	if err := g.publish(t.Context(), b, func() error { t.Error("published"); return nil }); !errors.Is(err, context.Canceled) {
		t.Errorf("publishing after Stop: %v", err)
	}
	if !slices.Equal(files(t, dir), []string{filepath.Base(b.Name()), "c"}) {
		t.Errorf("at the end: %v", files(t, dir))
	}
}

func TestHeld(t *testing.T) {
	data := make([]byte, 3*heldChunk+5)
	_, _ = rand.Read(data)
	var h held
	for p, n := data, 1; len(p) > 0; n = n*7%100_003 + 1 {
		k := min(n, len(p))
		if w, err := h.Write(p[:k]); w != k || err != nil {
			t.Fatalf("Write: %d, %v", w, err)
		}
		p = p[k:]
	}
	// The plaintext sits in chunks that never grew, so no copy of it was left behind.
	if len(h.chunks) != 4 {
		t.Fatalf("%d chunks", len(h.chunks))
	}
	for _, c := range h.chunks {
		if cap(c) != heldChunk {
			t.Fatalf("a chunk of capacity %d", cap(c))
		}
	}
	var out bytes.Buffer
	if err := h.writeTo(&out); err != nil || !bytes.Equal(out.Bytes(), data) {
		t.Fatalf("writeTo: %v", err)
	}
	if err := h.writeTo(brokenWriter{}); err == nil {
		t.Error("writeTo a broken writer succeeded")
	}
	h.wipe()
	for _, c := range h.chunks {
		if slices.ContainsFunc(c[:cap(c)], func(b byte) bool { return b != 0 }) {
			t.Fatal("wipe left plaintext")
		}
	}
}

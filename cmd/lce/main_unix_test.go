//go:build (amd64 || arm64) && unix

package main

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/t3spe/life-cipher-runner/internal/cli"
)

// waitFor polls until ok reports true, and fails the test if that takes more than a minute.
func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for deadline := time.Now().Add(time.Minute); !ok(); time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
	}
}

// tempFile returns the size of lce's temporary file in dir, or -1 if there's none.
func tempFile(t *testing.T, dir string) int64 {
	t.Helper()
	names, err := filepath.Glob(filepath.Join(dir, ".lce-*.tmp"))
	if err != nil || len(names) == 0 {
		return -1
	}
	info, err := os.Stat(names[0])
	if err != nil {
		return -1
	}
	return info.Size()
}

func names(t *testing.T, dir string) []string {
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

// encrypted returns n random bytes and their encryption in the binary form under the demo key.
func encrypted(t *testing.T, key string, n int) (plaintext, file []byte) {
	t.Helper()
	plaintext = make([]byte, n)
	_, _ = rand.Read(plaintext)
	var out, stderr bytes.Buffer
	env := cli.Env{Stdin: bytes.NewReader(plaintext), Stdout: &out, Stderr: &stderr, Rand: rand.Reader}
	if status := run([]string{"encrypt", "-b", "-k", key}, env); status != 0 {
		t.Fatalf("encrypt: status %d, %s", status, stderr.String())
	}
	return plaintext, out.Bytes()
}

// skipIfIgnored skips the test if the test process started out ignoring sig: lce would then ignore it too.
func skipIfIgnored(t *testing.T, sigs ...os.Signal) {
	t.Helper()
	for _, sig := range sigs {
		if signal.Ignored(sig) {
			t.Skipf("the tests run with %v ignored", sig)
		}
	}
}

func TestSignalStopsTheRun(t *testing.T) {
	// A signal while decrypt waits for input removes the temporary file, which holds plaintext whose tag isn't
	// checked yet, and ends lce by the same signal.
	skipIfIgnored(t, syscall.SIGTERM)
	dir, key := workspace(t)
	_, file := encrypted(t, key, 300_000)
	stdin, feed, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = stdin.Close(), feed.Close() }()
	defer func(f func(os.Signal) int) { raise = f }(raise)
	raised := make(chan os.Signal, 1)
	raise = func(sig os.Signal) int { raised <- sig; return 199 }

	status := make(chan int)
	go func() {
		var stderr bytes.Buffer
		status <- run([]string{"decrypt", "-k", key, "-o", filepath.Join(dir, "out")},
			cli.Env{Stdin: stdin, Stdout: io.Discard, Stderr: &stderr, Rand: rand.Reader})
	}()
	if _, err := feed.Write(file[:200_000]); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "unverified plaintext in the temporary file", func() bool { return tempFile(t, dir) > 0 })
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if got := <-status; got != 199 || <-raised != syscall.SIGTERM {
		t.Errorf("status %d", got)
	}
	if got := names(t, dir); !slices.Equal(got, []string{"key.txt"}) {
		t.Errorf("left behind: %v", got)
	}
}

func TestRaiseSignal(t *testing.T) {
	// SIGWINCH ends no process, so raiseSignal waits, and returns the status a shell would report.
	defer func(d time.Duration) { raiseWait = d }(raiseWait)
	raiseWait = 10 * time.Millisecond
	if got := raiseSignal(syscall.SIGWINCH); got != 128+int(syscall.SIGWINCH) {
		t.Errorf("status %d", got)
	}
}

// lceCommand returns a command that runs the test binary as lce, as a child process.
func lceCommand(args ...string) *exec.Cmd {
	cmd := exec.Command(os.Args[0], args...)
	cmd.Env = append(os.Environ(), asLce+"=1")
	return cmd
}

// diedBy reports whether a child process's Wait error says it died by sig.
func diedBy(err error, sig syscall.Signal) bool {
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		return false
	}
	ws, ok := exitErr.Sys().(syscall.WaitStatus)
	return ok && ws.Signaled() && ws.Signal() == sig
}

func TestSignalsEndLce(t *testing.T) {
	// The real thing: lce as a process, stopped by signals while it waits for more input.
	if testing.Short() {
		t.Skip("starts processes")
	}
	skipIfIgnored(t, syscall.SIGHUP, syscall.SIGTERM, syscall.SIGINT)
	_, key := workspace(t)
	_, file := encrypted(t, key, 300_000)
	for _, c := range []struct {
		name string
		sig  syscall.Signal
		args []string
		in   []byte
	}{
		{"SIGHUP while decrypting", syscall.SIGHUP, []string{"d"}, file[:200_000]},
		{"SIGTERM while decrypting", syscall.SIGTERM, []string{"d"}, file[:200_000]},
		{"SIGINT while encrypting", syscall.SIGINT, []string{"e"}, []byte("the first half")},
		{"SIGTERM while encrypting", syscall.SIGTERM, []string{"e", "-b"}, []byte("the first half")},
	} {
		dir := t.TempDir()
		out := filepath.Join(dir, "out")
		cmd := lceCommand(slices.Concat(c.args, []string{"-k", key, "-o", out})...)
		feed, err := cmd.StdinPipe()
		if err != nil {
			t.Fatal(err)
		}
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		if _, err := feed.Write(c.in); err != nil {
			t.Fatal(err)
		}
		waitFor(t, "the temporary file", func() bool { return tempFile(t, dir) >= 0 })
		if c.args[0] == "d" {
			waitFor(t, "unverified plaintext", func() bool { return tempFile(t, dir) > 0 })
		}
		// The signal, and then the end of the input, as when the signal stops whatever writes it too.
		if err := cmd.Process.Signal(c.sig); err != nil {
			t.Fatal(err)
		}
		_ = feed.Close()
		if err := cmd.Wait(); !diedBy(err, c.sig) {
			t.Errorf("%s: lce ended with %v", c.name, err)
		}
		if got := names(t, dir); len(got) != 0 {
			t.Errorf("%s: left behind %v", c.name, got)
		}
	}
}

func TestIgnoredSignalsStayIgnored(t *testing.T) {
	// Signals that lce starts out ignoring, as after "trap '' HUP INT" or in a background job, don't stop it.
	if testing.Short() {
		t.Skip("starts processes")
	}
	dir, key := workspace(t)
	plaintext, file := encrypted(t, key, 300_000)
	out := filepath.Join(dir, "out")
	cmd := exec.Command("sh", "-c", `trap '' HUP INT; exec "$0" "$@"`, os.Args[0], "d", "-k", key, "-o", out)
	cmd.Env = append(os.Environ(), asLce+"=1")
	feed, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	if _, err := feed.Write(file[:200_000]); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "unverified plaintext", func() bool { return tempFile(t, dir) > 0 })
	for _, sig := range []os.Signal{syscall.SIGHUP, syscall.SIGINT} {
		if err := cmd.Process.Signal(sig); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(100 * time.Millisecond)
	if _, err := feed.Write(file[200_000:]); err != nil {
		t.Fatal(err)
	}
	if err := feed.Close(); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("lce ended with %v", err)
	}
	if data, err := os.ReadFile(out); err != nil || !bytes.Equal(data, plaintext) {
		t.Errorf("OUTPUT: %d bytes, %v", len(data), err)
	}
}

func TestInterruptedPipeline(t *testing.T) {
	// Ctrl-C in "producer | lce e -k KEYFILE > out.lce" signals the whole pipeline, so lce sees its input end as the
	// signal arrives. That must not make a truncated plaintext look whole: lce dies by the signal, and out.lce gets
	// no tag. Run many times, since the order of the two events varies.
	if testing.Short() {
		t.Skip("starts processes")
	}
	skipIfIgnored(t, syscall.SIGINT)
	dir, key := workspace(t)
	for i := range 20 {
		out := filepath.Join(dir, "out.lce")
		stdout, err := os.Create(out)
		if err != nil {
			t.Fatal(err)
		}
		// Enough for lce to write some text, and then nothing until the signal.
		producer := exec.Command("sh", "-c", "head -c 100000 /dev/zero; exec sleep 60")
		producer.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		pipe, err := producer.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		if err := producer.Start(); err != nil {
			t.Fatal(err)
		}
		lce := lceCommand("e", "-k", key)
		lce.Stdin, lce.Stdout = pipe, stdout
		lce.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pgid: producer.Process.Pid}
		if err := lce.Start(); err != nil {
			t.Fatal(err)
		}
		_ = stdout.Close()
		waitFor(t, "the message's start", func() bool {
			data, err := os.ReadFile(out)
			return err == nil && strings.Contains(string(data), "-----CIPHERTEXT")
		})
		if err := syscall.Kill(-producer.Process.Pid, syscall.SIGINT); err != nil {
			t.Fatal(err)
		}
		lceErr, producerErr := lce.Wait(), producer.Wait()
		if !diedBy(lceErr, syscall.SIGINT) || !diedBy(producerErr, syscall.SIGINT) {
			t.Fatalf("run %d: lce ended with %v, the producer with %v", i, lceErr, producerErr)
		}
		if data, err := os.ReadFile(out); err != nil || strings.Contains(string(data), "-----TAG") {
			t.Fatalf("run %d: an interrupted encryption got a tag: %v\n%s", i, err, data)
		}
	}
}

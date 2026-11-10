//go:build (amd64 || arm64) && (unix || windows)

// Command lce encrypts and decrypts files with the Life Cipher, an experimental authenticated cipher built on
// Conway's Game of Life. Run "lce help" for its usage.
//
// lce builds only for 64-bit x86 and ARM processors, where the multiplication the cipher relies on can run in constant
// time (see the README), and only for Unix and Windows.
package main

import (
	"context"
	"crypto/rand"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/t3spe/life-cipher-runner/internal/cli"
)

// signals are the signals that stop lce: an interrupt (Ctrl-C), a request to terminate or to quit (Ctrl-\), and a
// hang-up, from a closed terminal or a dropped connection.
var signals = []os.Signal{os.Interrupt, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGHUP}

var (
	exit      = os.Exit     // replaced in tests
	raise     = raiseSignal // replaced in tests, which a signal mustn't end
	raiseWait = time.Second // how long raiseSignal waits for its signal to end the process
)

func main() {
	exit(run(os.Args[1:], cli.Env{Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr, Rand: rand.Reader}))
}

// run runs the command line args, and returns its exit status. A signal stops the run wherever it is, even while it
// waits for input: lce removes its temporary file, which may hold plaintext whose tag isn't checked yet, and then
// ends as the signal would have ended it, as the shell expects. An interrupt or a hang-up that the process started
// out ignoring, as a background job in a script or under nohup does, stays ignored. Go's runtime can't keep an
// ignored SIGTERM or SIGQUIT ignored, so lce can't either.
func run(args []string, env cli.Env) int {
	var caught []os.Signal
	for _, s := range signals {
		if !signal.Ignored(s) {
			caught = append(caught, s)
		}
	}
	stop := make(chan os.Signal, 1)
	if len(caught) > 0 { // Notify with no signals would relay every one
		signal.Notify(stop, caught...)
		defer signal.Stop(stop)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	env.Guard = new(cli.Guard)
	done := make(chan int, 1)
	go func() { done <- cli.Run(ctx, args, env) }()
	select {
	case status := <-done:
		return status
	case sig := <-stop:
		cancel()
		env.Guard.Stop()
		return raise(sig)
	}
}

// raiseSignal ends the process by sig, as if lce had never caught it. Where that's impossible, as on Windows, it
// returns 128 plus the signal's number, the status a shell reports for a death by that signal.
func raiseSignal(sig os.Signal) int {
	signal.Reset(sig)
	if p, err := os.FindProcess(os.Getpid()); err == nil && p.Signal(sig) == nil {
		time.Sleep(raiseWait) // a signal to the process itself arrives at once, so this only waits if it's ignored
	}
	return 128 + int(sig.(syscall.Signal))
}

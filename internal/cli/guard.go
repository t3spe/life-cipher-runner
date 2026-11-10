package cli

import (
	"context"
	"os"
	"path/filepath"
	"sync"
)

// A Guard lets a signal handler stop a run safely wherever the run is, even blocked on its input. Stop removes the
// temporary file the run writes OUTPUT to, which may hold plaintext whose tag isn't checked yet, and keeps the run from
// giving any file OUTPUT's name afterwards. The zero Guard is ready to use.
type Guard struct {
	mu      sync.Mutex
	stopped bool
	files   map[*os.File]bool // the temporary files that exist
}

// Stop removes the temporary files of the runs g guards, and keeps them from publishing a file from then on. It's safe
// to call from any goroutine, and more than once.
func (g *Guard) Stop() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.stopped = true
	for f := range g.files {
		remove(f)
	}
	clear(g.files)
}

// create makes the temporary file for OUTPUT, path, in path's directory, and guards it. If g is stopped, it makes
// nothing, and returns context.Canceled. It holds g's lock throughout, so Stop can't come between the file's creation
// and its guarding.
func (g *Guard) create(path string) (*os.File, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.stopped {
		return nil, context.Canceled
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".lce-*.tmp")
	if err != nil {
		return nil, outputError(path, err)
	}
	if g.files == nil {
		g.files = map[*os.File]bool{}
	}
	g.files[f] = true
	return f, nil
}

// discard removes the temporary file f, unless Stop has.
func (g *Guard) discard(f *os.File) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.files[f] {
		delete(g.files, f)
		remove(f)
	}
}

// publish runs do, which gives the temporary file f its final name, unless g is stopped or ctx is done: then the input
// may have ended only because an interrupt stopped whatever wrote it, so it isn't the whole input.
func (g *Guard) publish(ctx context.Context, f *os.File, do func() error) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	switch {
	case g.stopped:
		return context.Canceled
	case ctx.Err() != nil:
		return ctx.Err()
	}
	err := do()
	if err == nil {
		delete(g.files, f)
	}
	return err
}

// remove closes and removes a temporary file. Windows can't remove a file that's open.
func remove(f *os.File) {
	_ = f.Close()
	_ = os.Remove(f.Name())
}

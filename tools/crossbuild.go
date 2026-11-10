//go:build ignore

// Crossbuild checks that the code, tests included, compiles and vets for every target platform, then builds the
// lce command for each into dist/.
//
//	go run tools/crossbuild.go
package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// targets are the platforms lce is built for: 64-bit x86 and ARM only, as cmd/lce's build constraint says. The
// selector's 32-bit multiplication must take the same time for any operands (SPEC.md §14), which those cores can
// promise: ARM cores with their DIT mode on, which lce does, and Intel cores with their DOITM mode on, which only the
// operating system can do. The README has the details.
var targets = []struct{ goos, goarch string }{
	{"linux", "amd64"},
	{"linux", "arm64"},
	{"darwin", "amd64"},
	{"darwin", "arm64"},
	{"windows", "amd64"},
	{"windows", "arm64"},
}

func main() {
	for _, t := range targets {
		env := append(os.Environ(), "GOOS="+t.goos, "GOARCH="+t.goarch, "CGO_ENABLED=0")
		run(env, "go", "vet", "./...")
		out := filepath.Join("dist", fmt.Sprintf("lce-%s-%s", t.goos, t.goarch))
		if t.goos == "windows" {
			out += ".exe"
		}
		run(env, "go", "build", "-trimpath", "-o", out, "./cmd/lce")
		fmt.Println(out)
	}
}

func run(env []string, name string, args ...string) {
	cmd := exec.Command(name, args...)
	cmd.Env, cmd.Stdout, cmd.Stderr = env, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "crossbuild: %s %s: %v\n", name, strings.Join(args, " "), err)
		os.Exit(1)
	}
}

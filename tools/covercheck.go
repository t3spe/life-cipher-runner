//go:build ignore

// Covercheck reads a Go coverage profile and fails unless every statement in it ran. It merges the blocks that
// several test binaries report for the same code, as `go test -coverpkg=./... ./...` produces them.
//
//	go run tools/covercheck.go coverage.out
package main

import (
	"bufio"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: go run tools/covercheck.go PROFILE")
		os.Exit(2)
	}
	f, err := os.Open(os.Args[1])
	if err != nil {
		fail(err)
	}
	defer f.Close()

	type block struct {
		statements int
		ran        bool
	}
	blocks := map[string]*block{} // by position: file.go:line.column,line.column
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "mode:") {
			continue
		}
		fields := strings.Fields(line) // position, statements, count
		if len(fields) != 3 {
			fail(fmt.Errorf("not a coverage profile line: %q", line))
		}
		statements, err1 := strconv.Atoi(fields[1])
		count, err2 := strconv.Atoi(fields[2])
		if err1 != nil || err2 != nil {
			fail(fmt.Errorf("not a coverage profile line: %q", line))
		}
		b := blocks[fields[0]]
		if b == nil {
			b = &block{statements: statements}
			blocks[fields[0]] = b
		}
		b.ran = b.ran || count > 0
	}
	if err := scanner.Err(); err != nil {
		fail(err)
	}

	total, ran := 0, 0
	var missed []string
	for position, b := range blocks {
		total += b.statements
		if b.ran {
			ran += b.statements
		} else {
			missed = append(missed, position)
		}
	}
	slices.Sort(missed)
	for _, position := range missed {
		fmt.Println("not covered:", position)
	}
	if total == 0 {
		fail(fmt.Errorf("%s covers no statements", os.Args[1]))
	}
	fmt.Printf("coverage: %d of %d statements, %.1f%%\n", ran, total, 100*float64(ran)/float64(total))
	if ran != total {
		os.Exit(1)
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "covercheck:", err)
	os.Exit(1)
}

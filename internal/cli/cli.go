// Package cli implements the lce command: its subcommands and options, its messages, and its exit statuses.
package cli

import (
	"bufio"
	"cmp"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"time"

	"github.com/t3spe/life-cipher-runner/internal/armor"
	"github.com/t3spe/life-cipher-runner/internal/container"
	"github.com/t3spe/life-cipher-runner/internal/keyfile"
	"github.com/t3spe/life-cipher-runner/lifecipher"
)

// Env is what Run uses of the process it runs in.
type Env struct {
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
	Rand   io.Reader // where IVs come from: crypto/rand.Reader
	Guard  *Guard    // lets a signal handler stop the run; nil for none
}

// The exit statuses Run returns.
const (
	ExitOK      = 0 // success
	ExitFailure = 1 // the run failed: a file, the key check, the tag check, or reading or writing
	ExitUsage   = 2 // a command line that can't be run
)

const mainUsage = `lce encrypts and decrypts files with the Life Cipher, an experimental
authenticated cipher built on Conway's Game of Life (SPEC.md draft 0.4,
algorithm version 1). It's an experiment: don't use it to protect real data.

Usage:
  lce encrypt|e -k KEYFILE [-o OUTPUT] [-f] [-b] [INPUT]
  lce decrypt|d -k KEYFILE [-o OUTPUT] [-f] [INPUT]
  lce version
  lce help [COMMAND]

e and d are short for encrypt and decrypt. INPUT defaults to standard input,
and OUTPUT to standard output. Encrypted files are text, or binary with -b.

Before using a key, both commands run the spec's key check (SPEC.md §6.1),
which refuses a key whose first 6000 generations aren't all distinct. A key
must also have passed vetting (SPEC.md §9), which this tool doesn't do.

Run "lce help encrypt" or "lce help decrypt" for their options.

Exit status: 0 on success; 1 if the run fails, as for a file that can't be
read or written, an OUTPUT that exists, or a failed key check or tag check;
2 for a command line that can't be run. A signal ends lce as it ends other
programs, once lce has removed its temporary file.
`

const encryptUsage = `Usage: lce encrypt|e -k KEYFILE [-o OUTPUT] [-f] [-b] [INPUT]

Encrypts INPUT under the key in KEYFILE with a fresh random IV, using the
recommended parameter set (T = 6000, S = 16, k = 30, R = 24). The output is
text: a BEGIN line, the parameters, and then the IV, the ciphertext and the
16-byte tag in base64, each under its own divider, and an END line. With -b,
it's the same message in binary: 176 bytes longer than INPUT.

INPUT is a file. Without one, or with -, encrypt reads standard input.

An OUTPUT file appears only once it's complete, readable by its owner only.
Standard output gets the message as it's encrypted, so if encrypt fails or
is interrupted, what it wrote there has no tag, and decrypt refuses it.

Options:
  -k, --key KEYFILE    the key: 256 hex digits (32 row words, as SPEC.md
                       writes keys), 1,024 binary digits, or 128 raw bytes
  -o, --output OUTPUT  the encrypted file (default: standard output, which
                       - also names)
  -f, --force          replace OUTPUT if it exists, as long as it's a
                       regular file with no other links
  -b, --binary         write the binary form instead of text
  -h, --help           show this help
`

const decryptUsage = `Usage: lce decrypt|d -k KEYFILE [-o OUTPUT] [-f] [INPUT]

Decrypts INPUT, a file from "lce encrypt" in either form, under the key in
KEYFILE, and checks its tag. Text may come with other text around it, as in
an email: everything before its BEGIN line and after its END line is ignored.
Nothing is released unless the tag matches: the plaintext goes to a temporary
file that becomes OUTPUT only after the check, or, for standard output, is
held in memory until then.

INPUT is a file. Without one, or with -, decrypt reads standard input.

Options:
  -k, --key KEYFILE    the key, in any form encrypt accepts
  -o, --output OUTPUT  the decrypted file, readable by its owner only
                       (default: standard output, which - also names)
  -f, --force          replace OUTPUT if it exists, as long as it's a
                       regular file with no other links
  -h, --help           show this help
`

const versionUsage = `Usage: lce version

Prints the tool's version, the specification and parameter set it implements,
its file format, and the Go toolchain and platform it was built for.
`

// A command is encrypt or decrypt.
type command struct {
	name    string
	usage   string
	encrypt bool
}

var (
	encryptCommand = &command{name: "encrypt", usage: encryptUsage, encrypt: true}
	decryptCommand = &command{name: "decrypt", usage: decryptUsage}

	// commands finds a command by its name or its one-letter short form.
	commands = map[string]*command{
		"encrypt": encryptCommand, "e": encryptCommand,
		"decrypt": decryptCommand, "d": decryptCommand,
	}
)

// Run runs the lce command line args, without the program's name, and returns the exit status.
func Run(ctx context.Context, args []string, env Env) int {
	if len(args) == 0 {
		say(env.Stderr, mainUsage)
		return ExitUsage
	}
	switch args[0] {
	case "help", "-h", "-help", "--help":
		return help(args[1:], env)
	case "version", "-version", "--version":
		return version(args[1:], env)
	}
	cmd, ok := commands[args[0]]
	if !ok {
		return usageError(env, fmt.Sprintf("unknown command %q", args[0]), `Run "lce help" for usage.`)
	}
	env.Guard = cmp.Or(env.Guard, new(Guard))
	return cmd.run(ctx, args[1:], env)
}

// say writes s to w. The command has nowhere to report a failure to write its messages, so it doesn't try.
func say(w io.Writer, s string) {
	_, _ = io.WriteString(w, s)
}

func usageError(env Env, problem, hint string) int {
	say(env.Stderr, "lce: "+problem+"\n"+hint+"\n")
	return ExitUsage
}

func help(args []string, env Env) int {
	switch {
	case len(args) == 0:
		say(env.Stdout, mainUsage)
	case len(args) == 1 && args[0] == "version":
		say(env.Stdout, versionUsage)
	case len(args) == 1 && commands[args[0]] != nil:
		say(env.Stdout, commands[args[0]].usage)
	default:
		return usageError(env, fmt.Sprintf("no help for %q", strings.Join(args, " ")),
			`Run "lce help" for the commands.`)
	}
	return ExitOK
}

func version(args []string, env Env) int {
	if len(args) > 0 {
		return usageError(env, "version takes no arguments", `Run "lce help version" for its usage.`)
	}
	say(env.Stdout, fmt.Sprintf("lce %s\n"+
		"cipher:      the Life Cipher, SPEC.md draft 0.4, algorithm version %d\n"+
		"parameters:  %v, the recommended set\n"+
		"file format: %d\n"+
		"built with:  %s for %s/%s\n",
		versionOf(debug.ReadBuildInfo()), lifecipher.Recommended().Version, lifecipher.Recommended(),
		container.FormatVersion, runtime.Version(), runtime.GOOS, runtime.GOARCH))
	return ExitOK
}

// versionOf returns the tool's version from its build information: the version go build records from the version
// control system, or go install from the module, or "(devel)" without either.
func versionOf(info *debug.BuildInfo, ok bool) string {
	if ok && info.Main.Version != "" {
		return info.Main.Version
	}
	return "(devel)"
}

// options are an encrypt or decrypt command line's.
type options struct {
	key, input, output string
	force, binary      bool
}

func (c *command) run(ctx context.Context, args []string, env Env) int {
	o, err := c.parse(args)
	switch {
	case errors.Is(err, flag.ErrHelp):
		say(env.Stdout, c.usage)
		return ExitOK
	case err != nil:
		say(env.Stderr, fmt.Sprintf("lce %s: %v\nRun \"lce help %s\" for its options.\n", c.name, err, c.name))
		return ExitUsage
	}
	switch err := c.crypt(ctx, o, env); {
	case errors.Is(err, context.Canceled):
		say(env.Stderr, fmt.Sprintf("lce %s: interrupted\n", c.name))
		return ExitFailure
	case err != nil:
		say(env.Stderr, fmt.Sprintf("lce %s: %v\n", c.name, err))
		return ExitFailure
	}
	return ExitOK
}

func (c *command) parse(args []string) (options, error) {
	var o options
	fs := flag.NewFlagSet(c.name, flag.ContinueOnError)
	fs.SetOutput(io.Discard) // Run prints its own messages
	for _, name := range []string{"k", "key"} {
		fs.StringVar(&o.key, name, "", "")
	}
	for _, name := range []string{"o", "output"} {
		fs.StringVar(&o.output, name, "-", "") // standard output by default
	}
	for _, name := range []string{"f", "force"} {
		fs.BoolVar(&o.force, name, false, "")
	}
	if c.encrypt {
		for _, name := range []string{"b", "binary"} {
			fs.BoolVar(&o.binary, name, false, "")
		}
	}
	inputs, err := parseArgs(fs, args)
	o.input = "-" // standard input by default
	if len(inputs) == 1 {
		o.input = inputs[0]
	}
	switch {
	case err != nil:
		return o, err
	case o.key == "":
		return o, errors.New("no key: give the key file with -k")
	case len(inputs) > 1:
		return o, fmt.Errorf("expected at most one INPUT, but got %d", len(inputs))
	case o.input == "":
		return o, errors.New("an empty INPUT: give a file name, or - for standard input")
	case o.output == "":
		return o, errors.New("an empty OUTPUT: give a file name, or - for standard output")
	}
	return o, nil
}

// parseArgs parses args with fs and returns the arguments that aren't options. Options may come after them too, as
// in "INPUT -k KEYFILE"; everything after a "--" that ends the options is an argument.
func parseArgs(fs *flag.FlagSet, args []string) ([]string, error) {
	var rest []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		left := fs.Args()
		if ended(fs, args[:len(args)-len(left)]) {
			return append(rest, left...), nil
		}
		if len(left) == 0 {
			return rest, nil
		}
		rest = append(rest, left[0])
		args = left[1:]
	}
}

// ended reports whether the arguments fs parsed end the options with "--", rather than with an option's value, as
// "-o --" does. An option that isn't a boolean takes the next argument as its value unless it has one after "=".
func ended(fs *flag.FlagSet, parsed []string) bool {
	for i := 0; i < len(parsed); i++ {
		switch arg := parsed[i]; {
		case arg == "--":
			return true
		case !strings.Contains(arg, "=") && !isBool(fs.Lookup(strings.TrimLeft(arg, "-"))):
			i++ // skip the option's value
		}
	}
	return false
}

func isBool(f *flag.Flag) bool {
	b, ok := f.Value.(interface{ IsBoolFlag() bool })
	return ok && b.IsBoolFlag()
}

// crypt runs an encrypt or decrypt command line. It looks at the files before setting the key up, so that a problem
// with one of them shows at once.
func (c *command) crypt(ctx context.Context, o options, env Env) error {
	key, err := keyfile.Read(o.key)
	if err != nil {
		return fmt.Errorf("reading the key: %w", err)
	}
	defer clear(key)
	in, name, closeIn, err := openInput(o.input, env.Stdin)
	if err != nil {
		return err
	}
	defer closeIn()
	if err = checkFiles(o, env, in); err != nil {
		return err
	}
	k, err := setUpKey(o.key, key)
	if err != nil {
		return err
	}
	defer eraseKey(k)

	process := func(w io.Writer) error {
		r, err := binaryForm(in)
		if err != nil {
			return err
		}
		return container.Decrypt(ctx, k, r, w)
	}
	if c.encrypt {
		iv := make([]byte, lifecipher.IVSize)
		if _, err := io.ReadFull(env.Rand, iv); err != nil {
			return fmt.Errorf("drawing a random IV: %w", err)
		}
		if f, ok := in.(*os.File); ok {
			if _, regular := regularFile(f); !regular {
				in = settled{ctx, f}
			}
		}
		process = func(w io.Writer) error {
			if o.binary {
				return container.Encrypt(ctx, k, iv, in, w)
			}
			text := armor.NewWriter(w)
			if err := container.Encrypt(ctx, k, iv, in, text); err != nil {
				return err
			}
			return text.Close()
		}
	}
	warn := func(msg string) { say(env.Stderr, fmt.Sprintf("lce %s: warning: %s\n", c.name, msg)) }
	return output(ctx, o, env, !c.encrypt, warn, func(w io.Writer) error {
		err := process(w)
		closeIn() // before OUTPUT replaces a file, which may be INPUT itself
		return explain(name, err)
	})
}

// openInput opens INPUT, or returns standard input for "-". It returns the input, its name for messages, and a
// function that closes it, which may be called again.
func openInput(path string, stdin io.Reader) (io.Reader, string, func(), error) {
	if path == "-" {
		return stdin, "standard input", func() {}, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, "", nil, err
	}
	closeIn := func() { _ = f.Close() } // only read from, so closing can't lose data
	if info, err := f.Stat(); err != nil || info.IsDir() {
		closeIn()
		return nil, "", nil, cmp.Or(err, fmt.Errorf("INPUT %s is a directory", path))
	}
	return f, path, closeIn, nil
}

// settle is how long encrypt waits, when its input is a pipe or a terminal and ends, for a signal that may have ended
// it. An interrupt that stops lce usually stops whatever writes its input too, and that ends the input. If the end of
// the input won the race, a truncated plaintext would get a tag.
var settle = 200 * time.Millisecond

// settled reads r, and when r ends, waits for settle or until ctx is done.
type settled struct {
	ctx context.Context
	r   io.Reader
}

func (s settled) Read(p []byte) (int, error) {
	n, err := s.r.Read(p)
	if errors.Is(err, io.EOF) {
		timer := time.NewTimer(settle)
		defer timer.Stop()
		select {
		case <-s.ctx.Done():
		case <-timer.C:
		}
	}
	return n, err
}

// checkFiles refuses an output that the run must not write: an OUTPUT that's the key file or that checkOutput refuses,
// or a standard output that's redirected to the key file or to INPUT.
func checkFiles(o options, env Env, in io.Reader) error {
	if o.output != "-" {
		if sameFile(o.output, o.key) {
			return fmt.Errorf("OUTPUT %s is the key file", o.output)
		}
		return checkOutput(o.output, o.force)
	}
	// Standard output may be a file too, as with "lce e -k KEYFILE INPUT >> INPUT".
	out, ok := regularFile(env.Stdout)
	if !ok {
		return nil
	}
	if info, ok := regularFile(in); ok && os.SameFile(info, out) {
		return errors.New("standard output is INPUT")
	}
	if info, err := os.Stat(o.key); err == nil && os.SameFile(info, out) {
		return errors.New("standard output is the key file")
	}
	return nil
}

// regularFile returns the information of the file behind v, if v is an *os.File for a regular file.
func regularFile(v any) (fs.FileInfo, bool) {
	f, ok := v.(*os.File)
	if !ok {
		return nil, false
	}
	info, err := f.Stat()
	return info, err == nil && info.Mode().IsRegular()
}

// sameFile reports whether the paths a and b name the same existing file.
func sameFile(a, b string) bool {
	ia, errA := os.Stat(a)
	ib, errB := os.Stat(b)
	return errA == nil && errB == nil && os.SameFile(ia, ib)
}

// checkOutput refuses OUTPUT if it exists and force isn't set, and also, with force, if it's anything but a regular
// file with no other links. Replacing a symbolic link or a file with other hard links would leave the file the link
// points to, or the file's other names, as they were. A device or a pipe would stop being one.
func checkOutput(path string, force bool) error {
	info, err := os.Lstat(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil
	case err != nil:
		return outputError(path, err)
	case info.Mode()&fs.ModeSymlink != 0:
		return fmt.Errorf("OUTPUT %s is a symbolic link: name the file it points to", path)
	case info.IsDir():
		return fmt.Errorf("OUTPUT %s is a directory", path)
	case !info.Mode().IsRegular():
		return fmt.Errorf("OUTPUT %s isn't a regular file", path)
	case !force:
		return exists(path)
	}
	return soleLink(path, info)
}

func exists(path string) error {
	return fmt.Errorf("OUTPUT %s exists: use -f to replace it", path)
}

func otherLinks(path string) error {
	return fmt.Errorf("OUTPUT %s has other hard links, which replacing it would leave as they are", path)
}

// binaryForm returns an encrypted file read from r in its binary form. The file may be in either form: a binary one
// starts with the magic and a zero byte, the first of its format version, and anything else is read as text.
func binaryForm(r io.Reader) (io.Reader, error) {
	br := bufio.NewReader(r)
	head, err := br.Peek(len(container.Magic) + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if string(head) == container.Magic+"\x00" {
		return br, nil
	}
	return armor.NewReader(br), nil
}

// newKey and eraseKey are lifecipher.NewKey and (*lifecipher.Key).Erase. The tests replace them: they set each key
// up only once, and share it, so they never erase it.
var (
	newKey   = lifecipher.NewKey
	eraseKey = (*lifecipher.Key).Erase
)

// setUpKey sets the key from the file at path up for the recommended parameter set. Setup runs the key check
// (SPEC.md §6.1) before anything uses the key.
func setUpKey(path string, key []byte) (*lifecipher.Key, error) {
	k, err := newKey(lifecipher.Recommended(), key)
	if errors.Is(err, lifecipher.ErrKeyCheck) {
		return nil, fmt.Errorf("the key in %s fails the key check (SPEC.md §6.1): its first %d generations "+
			"aren't all distinct, so it can't be a vetted key", path, lifecipher.Recommended().Generations)
	}
	return k, err
}

// explain describes an error from encrypting or decrypting the input name for the user.
func explain(name string, err error) error {
	var params *container.ParamsError
	switch {
	case errors.Is(err, lifecipher.ErrOpen):
		return fmt.Errorf("%s: the tag doesn't match: the file was changed or damaged, or this isn't its key. "+
			"Nothing was written", name)
	case errors.As(err, &params):
		return fmt.Errorf("%s: the file was encrypted under %v, and lce uses %v", name, params.File, params.Key)
	case errors.Is(err, container.ErrNotEncrypted), errors.Is(err, container.ErrTruncated),
		errors.Is(err, container.ErrFormatVersion), errors.Is(err, armor.ErrFormat):
		return fmt.Errorf("%s: %w", name, err)
	}
	return err // nil, or an I/O error, which names its file
}

// output runs fill with a writer for OUTPUT. A file appears only if fill succeeds: writeFile has the details.
// Standard output gets the data as fill writes it, unless hold is set: then the data waits in memory, and is written
// only if fill succeeds.
func output(ctx context.Context, o options, env Env, hold bool, warn func(string), fill func(io.Writer) error) error {
	if o.output != "-" {
		return writeFile(ctx, env.Guard, o.output, o.force, fill, warn)
	}
	if !hold {
		return fill(env.Stdout)
	}
	var h held
	defer h.wipe()
	if err := fill(&h); err != nil {
		return err
	}
	return h.writeTo(env.Stdout)
}

// heldChunk is the size of the chunks that hold plaintext in memory.
const heldChunk = 64 << 10

// held is plaintext held in memory until its tag is checked. It grows a chunk at a time, so no byte of it is ever
// copied to a new place and left behind there, and wipe can clear every byte.
type held struct{ chunks [][]byte }

func (h *held) Write(p []byte) (int, error) {
	n := len(p)
	for len(p) > 0 {
		if len(h.chunks) == 0 || len(h.chunks[len(h.chunks)-1]) == heldChunk {
			h.chunks = append(h.chunks, make([]byte, 0, heldChunk))
		}
		last := &h.chunks[len(h.chunks)-1]
		k := min(heldChunk-len(*last), len(p))
		*last, p = append(*last, p[:k]...), p[k:]
	}
	return n, nil
}

func (h *held) writeTo(w io.Writer) error {
	for _, c := range h.chunks {
		if _, err := w.Write(c); err != nil {
			return err
		}
	}
	return nil
}

func (h *held) wipe() {
	for _, c := range h.chunks {
		clear(c[:cap(c)])
	}
}

// writeFile writes the file at path through fill. fill writes to a temporary file in path's directory, which takes
// path's name once fill and flushing the file to disk succeed. Otherwise, or if g is stopped or ctx is done first, the
// temporary file is removed, and path stays as it was. Without force, writeFile never replaces a file: not even one
// that appears while fill runs. Once path has its new contents, nothing fails the run: a problem after that, such as
// flushing the directory to disk, goes to warn.
func writeFile(ctx context.Context, g *Guard, path string, force bool, fill func(io.Writer) error,
	warn func(string)) (err error) {
	tmp, err := g.create(path)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			g.discard(tmp)
		}
	}()
	// Each step runs only if every earlier one succeeded.
	err = fill(outputFile{tmp, path})
	if err == nil {
		err = outputError(path, cmp.Or(tmp.Sync(), tmp.Close()))
	}
	if err != nil {
		return err
	}
	dir := openDir(filepath.Dir(path)) // now: once path has its new contents, nothing may fail
	err = g.publish(ctx, tmp, func() error { return publish(tmp.Name(), path, force, warn) })
	if err != nil {
		if dir != nil {
			_ = dir.Close()
		}
		return err
	}
	flush(dir, path, warn)
	return nil
}

// flush flushes the directory dir, where OUTPUT, path, just took its new name, to disk, and closes it. dir is nil where
// lce couldn't open it. A failure is only a warning: OUTPUT has its new contents already.
func flush(dir *os.File, path string, warn func(string)) {
	if dir == nil {
		return
	}
	if err := cmp.Or(dir.Sync(), dir.Close()); err != nil {
		warn(fmt.Sprintf("OUTPUT %s is written, but flushing its directory to disk failed: %v", path, err))
	}
}

// outputFile is OUTPUT's temporary file, whose errors name OUTPUT: the user never named the temporary file.
type outputFile struct {
	f    *os.File
	path string
}

func (o outputFile) Write(p []byte) (int, error) {
	n, err := o.f.Write(p)
	return n, outputError(o.path, err)
}

// outputError describes an error from OUTPUT's temporary file, or the steps that give it OUTPUT's name, as one with
// OUTPUT itself. It returns nil for nil.
func outputError(path string, err error) error {
	if err == nil {
		return nil
	}
	var pathErr *fs.PathError
	var linkErr *os.LinkError
	switch {
	case errors.As(err, &pathErr):
		err = pathErr.Err
	case errors.As(err, &linkErr):
		err = linkErr.Err
	}
	return fmt.Errorf("OUTPUT %s: %w", path, err)
}

// renameNew and link are renameNoReplace and os.Link. The tests replace them, to act as systems without them.
var (
	renameNew = renameNoReplace
	link      = os.Link
)

// publish gives the temporary file tmp OUTPUT's name, path. With force, it checks path again, and renames tmp over
// it. Without force, it must not replace a file, not even one that appeared since the run started. Where the system
// can, it renames tmp only if path is free, in one step. Elsewhere it links tmp to path, which fails if path exists,
// and removes tmp's own name. A file system that can do neither, such as FAT on macOS, leaves a gap: publish checks
// that path is free, and renames tmp, which would replace a file that appeared in between.
func publish(tmp, path string, force bool, warn func(string)) error {
	if !force {
		err := renameNew(tmp, path)
		switch {
		case errors.Is(err, fs.ErrExist):
			return exists(path)
		case !errors.Is(err, errors.ErrUnsupported):
			return outputError(path, err)
		}
		err = link(tmp, path)
		switch {
		case err == nil:
			if err = os.Remove(tmp); err != nil {
				warn(fmt.Sprintf("OUTPUT %s is written, but its temporary file stays, a second name for it: %v",
					path, err))
			}
			return nil
		case errors.Is(err, fs.ErrExist):
			return exists(path)
		}
	}
	if err := checkOutput(path, force); err != nil {
		return err
	}
	return outputError(path, os.Rename(tmp, path))
}

# life-cipher-runner

`lce` encrypts and decrypts files with the [Life Cipher](https://github.com/t3spe/life-cipher), an
experimental authenticated cipher built on Conway's Game of Life. This repository holds the command and a Go
implementation of the cipher: SPEC.md draft 0.4, algorithm version 1, with the recommended parameter set (T = 6,000,
S = 16, k = 30, R = 24).

The Life Cipher is an experiment. Nothing about it is proven, nobody outside its project has analyzed it yet, and it
must not protect real data.

## Using it

```
lce encrypt|e -k KEYFILE [-o OUTPUT] [-f] [-b] [INPUT]
lce decrypt|d -k KEYFILE [-o OUTPUT] [-f] [INPUT]
lce version
lce help [COMMAND]
```

`e` and `d` are short for `encrypt` and `decrypt`. INPUT defaults to standard input, and OUTPUT to standard output, so
the commands work as filters:

```
lce e -k my.key < notes.txt > notes.lce
lce d -k my.key notes.lce                # prints the plaintext
lce e -k my.key -o notes.lce notes.txt   # the same, with files named
tar c photos | lce e -k my.key > photos.tar.lce
```

| Option | Meaning |
|---|---|
| `-k`, `--key KEYFILE` | the key file (required) |
| `-o`, `--output OUTPUT` | the output file (default: standard output, which `-` also names) |
| `-f`, `--force` | replace OUTPUT if it exists, as long as it's a regular file with no other links |
| `-b`, `--binary` | encrypt only: write the binary form instead of text |
| `-h`, `--help` | the command's help |

INPUT is a file. Without one, or with `-`, the commands read standard input. Options may also follow INPUT, and `--`
ends them. An empty INPUT or OUTPUT, as from an unset shell variable, is refused. Encrypted files are text unless `-b`
asks for binary, and decrypt reads either.

### What it promises

- **An OUTPUT file appears only once it's complete.** lce writes a hidden temporary file, `.lce-*.tmp`, in OUTPUT's
  directory, flushes it to disk, gives it OUTPUT's name, and then flushes the directory, where it can read the
  directory. If anything fails before OUTPUT has its new name, or a signal stops lce, the temporary file goes and
  OUTPUT stays as it was. Only `kill -9` or a crash can leave a temporary file behind. Once OUTPUT has its new name,
  nothing fails the run: if flushing the directory fails then, lce only warns.
- **Decryption releases nothing unverified.** It checks the tag before its temporary file becomes OUTPUT. To standard
  output, it holds the plaintext in memory until the tag checks, in 64 KiB chunks that it wipes afterwards, so a
  file larger than the free memory needs `-o`.
- **Encryption to standard output streams.** If reading INPUT fails, or lce is interrupted, what it wrote has no tag,
  and decrypt refuses it.
- **An interrupted pipeline doesn't pass for a whole one.** Ctrl-C stops every program in a pipeline at once, so lce
  may see its input end just before the interrupt reaches it. When a pipe or a terminal ends, encrypt waits 200 ms
  before writing the tag, so that the interrupt comes first, and a truncated plaintext gets no tag.
- **OUTPUT is never replaced by surprise.** Without `-f`, lce refuses an OUTPUT that exists, even one that appears
  while it runs: it gives the temporary file OUTPUT's name in a way that fails if the name is taken. That's a rename
  that never replaces on Linux and Windows, and a hard link elsewhere. The one gap is a file system without hard
  links outside Linux and Windows, such as FAT on macOS: there lce checks that the name is free, and then renames.
  With `-f`, OUTPUT must be a regular file with no other hard links. lce refuses a symbolic link, a file with other
  hard links, a directory, a device or a pipe, even with `-f`: replacing one would leave the file it points to, or
  the file's other names, as they were. INPUT may be OUTPUT, with `-f`: the file is replaced once the run is done.
- **The key and INPUT are safe from the output.** lce refuses OUTPUT if it's the key file, and standard output if
  it's redirected to the key file or to INPUT, as in `lce e -k KEYFILE big.bin >> big.bin`.
- **New files are readable and writable by their owner only** (mode 0600), whatever the umask, and so is a file that
  `-f` replaces. On Windows, the file takes its permissions from its directory.
- **Every file gets a fresh random IV**, from the operating system's secure random source.
- **A signal ends lce at once, cleanly.** An interrupt (Ctrl-C), SIGTERM, SIGHUP (a closed terminal or a dropped
  connection) or SIGQUIT stops lce wherever it is, even while it waits for input. lce removes its temporary file,
  and then ends as the signal would have ended it, so the shell sees the usual status and a script's loop stops.
  An interrupt or a hang-up that lce starts out ignoring, as in a script's background job or under `nohup`, stays
  ignored. Go's runtime can't keep an ignored SIGTERM or SIGQUIT ignored, so lce can't either.

### Exit status

| Status | Meaning |
|---|---|
| 0 | success, perhaps with a warning about what came after OUTPUT had its new contents |
| 1 | the run failed: a file couldn't be read or written, OUTPUT exists or mustn't be replaced, or the key check or the tag check failed |
| 2 | a command line that can't be run; also Go's own fatal errors, such as running out of memory, and SIGQUIT (`Ctrl-\`), after which Go prints a stack dump |
| 128 + n | death by signal n, as for any program: 129 for SIGHUP, 130 for Ctrl-C, 141 for a closed pipe on standard output, 143 for SIGTERM |

## Keys

A key file holds a 32 × 32 grid in one of three forms:

- 256 hex digits: the 32 row words, as SPEC.md writes keys
- 1,024 binary digits: the cells in row order, 1 for a live cell
- exactly 128 raw bytes, in the byte layout of SPEC.md §2.2

A text key may have ASCII whitespace anywhere (spaces, tabs, line breaks, vertical tabs and form feeds), Windows line
endings, and a UTF-8 byte-order mark at its start. The digits are decoded without branching on their values or using
them as table indexes. lce reads the key file into one buffer, and wipes it, the key, and the key's expansion when the
run is done, as far as Go allows.

Before using a key, both commands run the spec's key check (SPEC.md §6.1), and refuse a key whose first 6,000
generations aren't all distinct. That catches random bytes and other keys that fall into a short cycle, nearly all
grids. The spec asks for more than the tool checks:

- **A key must have passed vetting** (SPEC.md §9): at least 6,000 distinct generations, a complexity score of at least
  10,000, and 64 to 960 live cells. Vetting runs offline, once per key, and this tool doesn't do it.
- **A key must never have been published.** The demo key in SPEC.md Appendix B is burned, and so are the
  challenge's keys once they're revealed.
- **Keys must be independent:** never derive one from another by a torus shift, rotation, reflection or edited cells.
- **A key may absorb at most 2^48 blocks,** in encryption and decryption together (SPEC.md §4.4). The tool doesn't
  count them across runs.

## Encrypted files

An encrypted file comes in two forms that hold the same message. Either can be rebuilt from the other without the
key, though lce has no command for that. decrypt tells them apart by their start: the binary form starts with
`LIFECIPH` and a zero byte, and anything else is read as text.

### Text, the default

```
-----BEGIN LIFE CIPHER MESSAGE----------------------------------
Version: 1
T: 6000
S: 16
k: 30
R: 24
-----IV---------------------------------------------------------
T0lbEdMCeJJUbbCInJV+6OSfXcGMBCGi8Y4b0bLwuE3Eo/7LjmBMmdCZ1hwXAbsq
H8/Ejc17GUO39UzNdjFDz7d3Q4nVg5Qi77yY7ydig7tVW8EdK9DCaEFbaLKAjjdH
WtdBlbA5w0Hk8KzSe8I+oEuV0VB3UQBVU6h7ACD3xSk=
-----CIPHERTEXT-------------------------------------------------
Tss8BMss8isf7g1DpChO
-----TAG--------------------------------------------------------
n4mIyB8hpaS8z4TD5AxqNQ==
-----END LIFE CIPHER MESSAGE------------------------------------
```

This is "attack at dawn" and a newline, 15 bytes, under the burned demo key.

- **The header lines** give the algorithm version and the parameters T, S, k and R, as decimal numbers.
- **The IV, the ciphertext and the tag** follow in standard base64 with padding, 64 characters to a line, and the
  last line of each may be shorter. An empty message has no ciphertext lines.
- **Every divider** is `-----`, a label, and dashes to 64 characters. Every line ends in a newline.

Every character comes from the binary form, so the tag covers all of it. Changing any of it, a parameter, the IV, the
ciphertext or the tag, makes decryption fail. Each message has exactly one text form, and decrypt refuses any other
text, saying why and at which line. Text with no BEGIN line is simply "not a file encrypted by lce". decrypt allows
three exceptions, for what transport does to text:

- lines may end in CRLF
- anything before the BEGIN line or after the END line is ignored, such as an email around the message, and so is a
  byte-order mark at the very start
- the END line may lack its final newline

### Binary, with `-b`

| Offset | Size | Field |
|---|---|---|
| 0 | 8 | the magic, `LIFECIPH` |
| 8 | 4 | the format version, 1 |
| 12 | 20 | the parameter words T, k, S, R and the algorithm version, in the order of SPEC.md §6.2 |
| 32 | 128 | the IV |
| 160 | n | the ciphertext, as long as the plaintext |
| 160 + n | 16 | the tag |

Integers are big-endian 32-bit words. The 32-byte header is the message's associated data, so the tag covers the
whole file: header, IV and ciphertext. A binary file is 176 bytes longer than its plaintext, and its text form is
about a third longer still. The text form's BEGIN line stands for the magic and the format version.

## Building

The tools come from `mise.toml`: Go, golangci-lint and gh (for releases), pinned, with Go's caches kept inside the
repository.

```
mise install          # once
mise run build        # bin/lce, for this machine
mise run cross        # dist/: Linux, macOS and Windows, each on x86-64 and ARM64
```

The command is pure Go with no dependencies outside the standard library, built without cgo. It needs Go 1.27 or
later.

`cmd/lce` builds only for 64-bit x86 and ARM, because the selector's 32-bit multiplication must take the same time
for any operands (SPEC.md §14), and those cores can promise that:

- **64-bit ARM cores** promise it with their DIT mode (data-independent timing) on. lce turns it on for all of its
  cryptographic work, through Go's `crypto/subtle.WithDataIndependentTiming`.
- **Intel cores that have the DOITM mode**, such as the i5-1240P, promise it only with that mode on, and only the
  operating system can turn it on. Linux leaves it off by default.

## Developing

| Task | What it does |
|---|---|
| `mise run test` | every test |
| `mise run cover` | every test, with coverage of all packages, failing below 100% |
| `mise run lint` | golangci-lint, with go vet, staticcheck, gosec and revive (`.golangci.yml`) |
| `mise run fmt` | formats the code |
| `mise run fuzz` | each fuzz target for 30 seconds, or `FUZZTIME` |
| `mise run race` | every test under the race detector, which needs cgo and a C compiler |
| `mise run cross` | vets the code, tests included, for every target, and builds each |
| `mise run check` | lint, cover and cross: what must pass before a commit |

### How it's tested

- **The published vectors.** The `lifecipher` package reproduces every value in all three of the spec's vector files.
  A test checks the copies in `lifecipher/testdata/` against SPEC.md §15's digests. Decoding them is strict: it
  refuses a field the tests don't check, a field named twice, a name in another case, and anything after the JSON.
- **More known answers from the reference implementation**, for cases the published vectors miss: associated data of
  128 bytes or more, messages of several blocks, and IVs with other offsets (`lifecipher/testdata/README.md`).
- **The spec's definitions, checked directly:**
  - Life against the rule evaluated cell by cell
  - shift and fold against their definitions
  - Mix run backwards
  - the selectors moving with each of B's 1,024 cells
  - the setup constant against π, computed with Machin's formula
  - the sorting network against a plain sort, for sizes that aren't powers of two too, ties included
  - each shuffle against the rule of §6.5–§6.6
  - the parameter checks, at and past every limit
- **The AEAD:** round trips over many lengths, in place and appended, a rejection of every kind of change, the end
  marker, the separator, and the API's misuses: wrong sizes, use after Finish or Erase, an erased key, and buffers
  that partly overlap.
- **The text form:**
  - its exact layout, built independently of the code that writes it
  - round trips at every line boundary
  - the exceptions it allows, and a table of near-misses it refuses, each with its line number
  - allocations that don't grow with the message
  - the documentation's example, which must decrypt, and match its copies here and in `internal/armor`
- **Fuzzing** of Life, Seal and Open, the incremental API, key parsing, decryption, and both directions of the text
  form. Whatever text the reader accepts must be exactly what the writer writes.
- **The command** from end to end, in-process: every option form, refusal, I/O failure and interruption, checking
  each time that no partial file is left behind. Also as a separate process, stopped by real signals while it waits
  for input: no temporary file may stay, lce must end by the signal, and Ctrl-C to a whole pipeline must never leave
  a truncated encryption with a tag. An interrupt and a hang-up that lce starts out ignoring must stay ignored.
- **100% statement coverage** across all packages, `main` included.

## Layout

| Path | What it is |
|---|---|
| `cmd/lce/` | the command's `main` |
| `internal/cli/` | the commands, their options and messages, and how OUTPUT gets written |
| `internal/container/` | the binary form of encrypted files, streamed in 64 KiB chunks |
| `internal/armor/` | the text form, which converts to and from the binary form as it streams |
| `internal/keyfile/` | reading key files |
| `lifecipher/` | the cipher: key setup, a `crypto/cipher.AEAD`, and an incremental API for long messages |
| `tools/` | the coverage gate and the cross builds, run by the mise tasks |

## Speed

On an Intel Core i5-1240P:

- **Encryption:** about 15 MB/s with the recommended set, on one core. The C implementation reaches about 55 MB/s
  there, with AVX2.
- **Key setup:** about 0.1 seconds, once per run, using every core: it sorts its 30 shuffles in parallel, while the
  setup run that makes them goes on.

## Constant time

The code follows SPEC.md §14, so no secret decides a branch or a memory address:

- **The Life step** is bit-parallel.
- **The table read** touches all 16 entries of the public group and keeps one with masks.
- **The shift** moves rows in five masked steps, and rotates each row through variable shifts and masks.
- **The shuffles** are a bitonic sorting network that carries the generations with their tags.
- **The key check and the tag comparison** run in full every time.
- **Key files** are decoded with `crypto/subtle`'s constant-time functions.
- **All of it runs with data-independent timing on**, where the processor has such a mode (see Building).

Go makes no promise about the machine code it generates, though, and this implementation hasn't been through the
timing and Valgrind checks the C implementation passed.

## License

lce is under the GNU Affero General Public License, version 3 (`LICENSE`): the code and the documentation alike. The
one exception is the three published test vector files in `lifecipher/testdata/`, copies of the Life Cipher
repository's, which stay under CC BY 4.0 there (`lifecipher/testdata/README.md`).

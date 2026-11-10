package armor

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"math/rand/v2"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/iotest"

	"github.com/t3spe/life-cipher-runner/internal/container"
	"github.com/t3spe/life-cipher-runner/lifecipher"
)

// demoKey is the burned demo key of SPEC.md Appendix B. It must never protect anything.
const demoKey = "6B3028A8DB46016A318DA71385D82A926489431E9A2B00E11CB1E6844106B26D" +
	"90FC90AC77361985884930EB551A3B5281186009E814409482842900D88996D1" +
	"9514CC133A81EC3447580B9DF304B45184A2B2742412283808F6D9343A69CBB8" +
	"6A04296A5F54D36A425497691420992C30F902067215518A1CE02869BA961C3B"

// docExample is the message in the package's documentation: "attack at dawn\n" under the demo key.
const docExample = `-----BEGIN LIFE CIPHER MESSAGE----------------------------------
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
`

var demo = sync.OnceValues(func() (*lifecipher.Key, error) {
	key, err := hex.DecodeString(demoKey)
	if err != nil {
		return nil, err
	}
	return lifecipher.NewKey(lifecipher.Recommended(), key)
})

func key(t testing.TB) *lifecipher.Key {
	t.Helper()
	k, err := demo()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func randomBytes(seed uint64, n int) []byte {
	rng := rand.New(rand.NewPCG(seed, seed))
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(rng.Uint32())
	}
	return b
}

// message returns an encrypted file in the binary form, with a fixed IV.
func message(t testing.TB, pt []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	if err := container.Encrypt(context.Background(), key(t), randomBytes(99, lifecipher.IVSize), bytes.NewReader(pt), &out); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

// render writes the binary form through a Writer, piece bytes at a time.
func render(t testing.TB, bin []byte, piece int) string {
	t.Helper()
	var out bytes.Buffer
	a := NewWriter(&out)
	for len(bin) > 0 {
		n := min(piece, len(bin))
		if _, err := a.Write(bin[:n]); err != nil {
			t.Fatal(err)
		}
		bin = bin[n:]
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	return out.String()
}

func parse(r io.Reader) ([]byte, error) {
	return io.ReadAll(NewReader(r))
}

// lines writes b in base64, 64 characters to a line: the text form's sections, built independently of the Writer.
func lines(b []byte) []string {
	var out []string
	for s := base64.StdEncoding.EncodeToString(b); s != ""; s = s[min(64, len(s)):] {
		out = append(out, s[:min(64, len(s))])
	}
	return out
}

func TestDividers(t *testing.T) {
	for label, line := range map[string]string{
		"BEGIN LIFE CIPHER MESSAGE": beginLine, "IV": ivLine, "CIPHERTEXT": ciphertextLine, "TAG": tagLine,
		"END LIFE CIPHER MESSAGE": endLine,
	} {
		if len(line) != 64 || line != "-----"+label+strings.Repeat("-", 59-len(label)) {
			t.Errorf("%s: %q", label, line)
		}
	}
}

func TestWriterLayout(t *testing.T) {
	for _, n := range []int{0, 15, 48, 100} {
		bin := message(t, randomBytes(uint64(n), n))
		iv, ct, tag := bin[32:160], bin[160:len(bin)-16], bin[len(bin)-16:]
		want := slices.Concat([]string{beginLine, "Version: 1", "T: 6000", "S: 16", "k: 30", "R: 24", ivLine},
			lines(iv), []string{ciphertextLine}, lines(ct), []string{tagLine}, lines(tag), []string{endLine})
		if got := render(t, bin, len(bin)); got != strings.Join(want, "\n")+"\n" {
			t.Errorf("%d bytes:\n%s\nwant\n%s", n, got, strings.Join(want, "\n"))
		}
	}
}

func TestDocExample(t *testing.T) {
	// The package's documentation and the README show this example, which is a real message.
	src, err := os.ReadFile("armor.go")
	if err != nil {
		t.Fatal(err)
	}
	var doc strings.Builder
	for line := range strings.Lines(docExample) {
		doc.WriteString("//\t" + line)
	}
	if !strings.Contains(string(src), doc.String()) {
		t.Error("armor.go's documentation shows another example")
	}
	readme, err := os.ReadFile(filepath.Join("..", "..", "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(readme), "```\n"+docExample+"```\n") {
		t.Error("README.md shows another example")
	}

	bin, err := parse(strings.NewReader(docExample))
	if err != nil {
		t.Fatal(err)
	}
	var pt bytes.Buffer
	if err := container.Decrypt(context.Background(), key(t), bytes.NewReader(bin), &pt); err != nil || pt.String() != "attack at dawn\n" {
		t.Fatalf("it decrypts to %q, %v", pt.String(), err)
	}
	if got := render(t, bin, 1000); got != docExample {
		t.Errorf("rendering it again gives\n%s", got)
	}
}

func TestRoundTrip(t *testing.T) {
	for _, n := range []int{0, 1, 47, 48, 49, 95, 96, 97, 1000, 100_000} {
		bin := message(t, randomBytes(uint64(n), n))
		text := render(t, bin, len(bin))
		for _, piece := range []int{1, 7, 100, 4096} {
			if render(t, bin, piece) != text {
				t.Fatalf("%d bytes: writing %d bytes at a time gives other text", n, piece)
			}
		}
		for name, r := range map[string]io.Reader{
			"whole": strings.NewReader(text), "a byte at a time": iotest.OneByteReader(strings.NewReader(text)),
			"half reads": iotest.HalfReader(strings.NewReader(text)),
		} {
			got, err := parse(r)
			if err != nil || !bytes.Equal(got, bin) {
				t.Fatalf("%d bytes, read %s: %v", n, name, err)
			}
		}
		for _, line := range strings.Split(strings.TrimSuffix(text, "\n"), "\n") {
			if len(line) > 64 {
				t.Fatalf("%d bytes: a line of %d characters", n, len(line))
			}
		}
	}
}

func TestReaderTolerates(t *testing.T) {
	bin := message(t, []byte("tolerance"))
	text := render(t, bin, len(bin))
	for name, variant := range map[string]string{
		"CRLF line endings":                 strings.ReplaceAll(text, "\n", "\r\n"),
		"text before and after":             "From: someone\nSubject: the figures\n\n" + text + "\n-- \nsent from my phone\n",
		"no newline after the END line":     strings.TrimSuffix(text, "\n"),
		"a long line before the BEGIN line": strings.Repeat("x", 3*maxLine) + "\n" + text,
		"another BEGIN line after the END":  text + beginLine + "\n",
		"a byte-order mark first":           "\uFEFF" + text,
		"a byte-order mark and CRLFs":       "\uFEFF" + strings.ReplaceAll(text, "\n", "\r\n"),
		"a byte-order mark, then a preface": "\uFEFFDear Bob,\n" + text,
		"CRLFs and no final newline":        strings.TrimSuffix(strings.ReplaceAll(text, "\n", "\r\n"), "\r\n"),
	} {
		got, err := parse(strings.NewReader(variant))
		if err != nil || !bytes.Equal(got, bin) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestReaderRefuses(t *testing.T) {
	bin := message(t, randomBytes(5, 100)) // three lines of ciphertext: 64, 64 and 8 characters
	text := render(t, bin, len(bin))
	ls := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	// with replaces line i, or removes it if line is empty, or inserts a line before it if insert is set.
	with := func(i int, line string) string {
		c := slices.Clone(ls)
		if line == "" {
			c = slices.Delete(c, i, i+1)
		} else {
			c[i] = line
		}
		return strings.Join(c, "\n") + "\n"
	}
	insert := func(i int, line string) string {
		return strings.Join(slices.Insert(slices.Clone(ls), i, line), "\n") + "\n"
	}
	upTo := func(i int) string { return strings.Join(ls[:i], "\n") + "\n" }
	const (
		begin, version, tLine, rLine, iv, iv1, iv2, iv3, ct, ct1, ct2, ct3, tag, tag1, end = 0, 1, 2, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16
	)
	if ls[end] != endLine || ls[ct3] != base64.StdEncoding.EncodeToString(bin[160+96:len(bin)-16]) {
		t.Fatal("the test's line numbers are wrong")
	}
	for name, c := range map[string]struct {
		text string
		want error
		says string
	}{
		"empty":                          {"", container.ErrNotEncrypted, ""},
		"no BEGIN line":                  {"just some text\n", container.ErrNotEncrypted, ""},
		"a BEGIN line one dash short":    {with(begin, beginLine[:63]), container.ErrNotEncrypted, ""},
		"a BOM, but not at the start":    {"noise\n\uFEFF" + text, container.ErrNotEncrypted, ""},
		"two BOMs":                       {"\uFEFF\uFEFF" + text, container.ErrNotEncrypted, ""},
		"only the BEGIN line":            {upTo(1), container.ErrTruncated, "the text stops at line 1, before its END line"},
		"cut in the header":              {upTo(tLine), container.ErrTruncated, "stops at line 2,"},
		"cut in the IV":                  {upTo(iv2), container.ErrTruncated, "stops at line 8,"},
		"cut in the ciphertext":          {upTo(ct2), container.ErrTruncated, "stops at line 12,"},
		"cut before the tag":             {upTo(tag), container.ErrTruncated, "stops at line 14,"},
		"cut before the END line":        {upTo(end), container.ErrTruncated, "stops at line 16,"},
		"cut after the TAG divider":      {upTo(tag1), container.ErrTruncated, "stops at line 15,"},
		"cut in the middle of a line":    {upTo(ct1) + ls[ct1][:20], container.ErrTruncated, "stops at line 12,"},
		"cut in the END line":            {text[:len(text)-10], container.ErrTruncated, "stops at line 17,"},
		"a lone CR after the END line":   {strings.TrimSuffix(text, "\n") + "\r", container.ErrTruncated, "line 17,"},
		"a tag that isn't base64":        {with(tag1, "not base64!"), ErrFormat, "line 16: expected the 16-byte tag"},
		"Version: 01":                    {with(version, "Version: 01"), ErrFormat, `line 2: expected "Version:" and a number`},
		"Version:1":                      {with(version, "Version:1"), ErrFormat, "line 2"},
		"a trailing space":               {with(tLine, "T: 6000 "), ErrFormat, `line 3: expected "T:" and a number`},
		"a lowercase label":              {with(tLine, "t: 6000"), ErrFormat, "line 3"},
		"a number over 32 bits":          {with(tLine, "T: 4294967296"), ErrFormat, "line 3"},
		"a header line missing":          {with(rLine, ""), ErrFormat, `line 6: expected "R:" and a number`},
		"an extra header line":           {insert(iv, "Comment: hello"), ErrFormat, "line 7: expected the IV's divider"},
		"a divider one dash long":        {with(iv, ivLine+"-"), ErrFormat, "line 7: expected the IV's divider"},
		"the IV a line short":            {with(iv2, ""), ErrFormat, "line 10: the IV is 80 bytes, not 128"},
		"the IV a line long":             {insert(ct, ls[iv1]), ErrFormat, "line 11: expected the ciphertext's divider"},
		"the IV's lines swapped":         {with(iv3, ls[iv1]), ErrFormat, "line 10: the IV is longer than 128 bytes"},
		"the ciphertext's divider cut":   {with(ct, ""), ErrFormat, "line 11: expected the ciphertext's divider"},
		"base64 wrapped at 76":           {with(ct1, ls[ct1]+ls[ct2][:12]), ErrFormat, "line 12: expected a line of base64"},
		"a space in base64":              {with(ct1, ls[ct1][:10]+" "+ls[ct1][11:]), ErrFormat, "line 12"},
		"a CR in base64":                 {with(ct3, ls[ct3][:4]+"\r"+ls[ct3][4:]), ErrFormat, "line 14: expected a line of base64"},
		"an empty line of base64":        {insert(ct2, ""), ErrFormat, "line 13: expected a line of base64"},
		"padding bits set":               {with(ct3, ls[ct3][:len(ls[ct3])-3]+"B=="), ErrFormat, "line 14"},
		"a short line, then another":     {insert(tag, ls[ct3]), ErrFormat, "line 15: expected the tag's divider"},
		"a short line, then a bad one":   {with(tag, "-----TAG-----"), ErrFormat, "line 15: expected the tag's divider"},
		"no tag":                         {with(tag1, ""), ErrFormat, "line 16: expected the 16-byte tag"},
		"a 15-byte tag":                  {with(tag1, base64.StdEncoding.EncodeToString(bin[len(bin)-15:])), ErrFormat, "line 16: expected the 16-byte tag"},
		"a line after the tag":           {insert(end, "extra"), ErrFormat, "line 17: expected the END line"},
		"a line longer than maxLine":     {with(ct1, strings.Repeat("A", maxLine+10)), ErrFormat, "line 12: the line is longer than 4096 bytes"},
		"an END line with a space":       {with(end, endLine+" "), ErrFormat, "line 17: expected the END line"},
		"an END line with a lone CR, LF": {with(end, endLine+"\r\r"), ErrFormat, "line 17: expected the END line"},
	} {
		_, err := parse(strings.NewReader(c.text))
		if !errors.Is(err, c.want) || !strings.Contains(err.Error(), c.says) {
			t.Errorf("%s: got %v, want %v saying %q", name, err, c.want, c.says)
		}
	}

	// After a full line of base64, a mangled divider is neither base64 nor the divider.
	full := strings.Split(render(t, message(t, randomBytes(5, 96)), 1000), "\n")
	full[12] = "-----TAG-----"
	if _, err := parse(strings.NewReader(strings.Join(full, "\n"))); !errors.Is(err, ErrFormat) ||
		!strings.Contains(err.Error(), "line 13: expected a line of base64, at most 64 characters, or the tag's divider") {
		t.Errorf("a mangled divider after a full line: %v", err)
	}

	// A canonical change is no format error: the tag catches it.
	changed := with(iv1, "U"+ls[iv1][1:])
	got, err := parse(strings.NewReader(changed))
	if err != nil {
		t.Fatal(err)
	}
	if err := container.Decrypt(context.Background(), key(t), bytes.NewReader(got), io.Discard); !errors.Is(err, lifecipher.ErrOpen) {
		t.Errorf("a changed IV: %v", err)
	}
}

// failingWriter fails once it has accepted limit bytes.
type failingWriter struct{ limit int }

func (w *failingWriter) Write(p []byte) (int, error) {
	if len(p) > w.limit {
		n := w.limit
		w.limit = 0
		return n, errBroken
	}
	w.limit -= len(p)
	return len(p), nil
}

var errBroken = errors.New("broken")

func TestWriterErrors(t *testing.T) {
	bin := message(t, randomBytes(6, 20_000))

	// Bytes that aren't the binary form, or too few of them.
	for name, c := range map[string]struct {
		bin  []byte
		want error
	}{
		"another magic":          {append([]byte("NOTLIFE!"), bin[8:]...), container.ErrNotEncrypted},
		"format version 2":       {slices.Concat(bin[:11], []byte{2}, bin[12:]), container.ErrFormatVersion},
		"part of the header":     {bin[:20], container.ErrTruncated},
		"no tag":                 {bin[:170], container.ErrTruncated},
		"the header and IV only": {bin[:160], container.ErrTruncated},
	} {
		var out bytes.Buffer
		a := NewWriter(&out)
		_, err := a.Write(c.bin)
		if err == nil {
			err = a.Close()
		} else if _, again := a.Write([]byte{0}); !errors.Is(again, c.want) {
			t.Errorf("%s: a later Write gives %v", name, again)
		}
		if !errors.Is(err, c.want) || out.Len() != 0 {
			t.Errorf("%s: %v, and %d bytes written", name, err, out.Len())
		}
		// The error stays: Close returns it, however often it's called, and a closed Writer takes nothing more.
		for range 2 {
			if again := a.Close(); !errors.Is(again, c.want) {
				t.Errorf("%s: Close gives %v", name, again)
			}
		}
		if _, again := a.Write([]byte{0}); !errors.Is(again, errClosed) {
			t.Errorf("%s: Write after Close gives %v", name, again)
		}
	}

	// The underlying writer fails: at the end, for a short text, which the buffer holds until Close, or during Write.
	a := NewWriter(&failingWriter{0})
	if _, err := a.Write(bin[:200]); err != nil {
		t.Fatal(err)
	}
	if err := a.Close(); !errors.Is(err, errBroken) {
		t.Errorf("a short text: %v", err)
	}
	a = NewWriter(&failingWriter{100})
	if _, err := a.Write(bin); !errors.Is(err, errBroken) {
		t.Errorf("a long text: %v", err)
	}
	if err := a.Close(); !errors.Is(err, errBroken) {
		t.Errorf("Close after a failed Write: %v", err)
	}

	// After Close, the Writer refuses more.
	a = NewWriter(io.Discard)
	if _, err := a.Write(bin); err != nil {
		t.Fatal(err)
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Write(bin); !errors.Is(err, errClosed) {
		t.Errorf("Write after Close: %v", err)
	}
	if err := a.Close(); err != nil {
		t.Errorf("Close twice: %v", err)
	}
}

func TestNoAllocationPerLine(t *testing.T) {
	// Writing and reading take the same allocations for a message of one line as for one of 2,000 lines.
	short, long := message(t, randomBytes(10, 40)), message(t, randomBytes(11, 2000*lineBytes))
	allocs := func(bin []byte) (write, read float64) {
		text := render(t, bin, len(bin))
		write = testing.AllocsPerRun(5, func() {
			a := NewWriter(io.Discard)
			if _, err := a.Write(bin); err != nil || a.Close() != nil {
				t.Fatal("writing failed")
			}
		})
		buf := make([]byte, 4096) // not io.Discard, whose buffers come from a sync.Pool
		read = testing.AllocsPerRun(5, func() {
			r := NewReader(strings.NewReader(text))
			for {
				_, err := r.Read(buf)
				if errors.Is(err, io.EOF) {
					break
				}
				if err != nil {
					t.Fatal(err)
				}
			}
		})
		return write, read
	}
	shortWrite, shortRead := allocs(short)
	longWrite, longRead := allocs(long)
	if shortWrite != longWrite || shortRead != longRead {
		t.Errorf("allocations for 1 line and 2,000: writing %v and %v, reading %v and %v",
			shortWrite, longWrite, shortRead, longRead)
	}
}

func TestReaderErrors(t *testing.T) {
	text := render(t, message(t, []byte("errors")), 1000)
	for _, at := range []int{0, 30, 200, len(text) - 40} {
		r := io.MultiReader(strings.NewReader(text[:at]), iotest.ErrReader(errBroken))
		if _, err := parse(r); !errors.Is(err, errBroken) {
			t.Errorf("an input that fails after %d bytes: %v", at, err)
		}
	}
	a := NewReader(strings.NewReader(text))
	if n, err := a.Read(nil); n != 0 || err != nil {
		t.Errorf("an empty Read: %d, %v", n, err)
	}
}

func FuzzReader(f *testing.F) {
	f.Add([]byte(docExample))
	f.Add([]byte(strings.ReplaceAll(docExample, "\n", "\r\n")))
	f.Add([]byte("noise\n" + docExample[:300]))
	f.Add([]byte(strings.TrimSuffix(docExample, "\n") + "\r")) // a lone CR for the last newline
	f.Add([]byte("\uFEFF" + docExample))
	f.Fuzz(func(t *testing.T, data []byte) {
		bin, err := parse(bytes.NewReader(data))
		if err != nil {
			if !errors.Is(err, ErrFormat) && !errors.Is(err, container.ErrNotEncrypted) && !errors.Is(err, container.ErrTruncated) {
				t.Fatalf("an unexpected error: %v", err)
			}
			return
		}
		// Text the Reader accepts is the Writer's rendering of what it read, in the input after CRLFs become LFs and
		// without a byte-order mark at the start.
		text := render(t, bin, len(bin))
		input := strings.TrimPrefix(string(data), "\uFEFF")
		if !strings.Contains(strings.ReplaceAll(input, "\r\n", "\n")+"\n", text) {
			t.Fatalf("accepted text that the Writer doesn't write:\n%q", data)
		}
	})
}

func FuzzWriter(f *testing.F) {
	f.Add([]byte{}, uint16(1))
	f.Add(randomBytes(7, 500), uint16(13))
	f.Fuzz(func(t *testing.T, body []byte, piece uint16) {
		// Any bytes after a valid header and IV render, and read back exactly; the last 16 are the tag.
		bin := slices.Concat(container.Header(lifecipher.Recommended()), randomBytes(8, lifecipher.IVSize), body,
			randomBytes(9, lifecipher.TagSize))
		got, err := parse(strings.NewReader(render(t, bin, 1+int(piece))))
		if err != nil || !bytes.Equal(got, bin) {
			t.Fatalf("the round trip fails: %v", err)
		}
	})
}

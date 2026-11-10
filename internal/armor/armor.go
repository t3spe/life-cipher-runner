// Package armor writes and reads the text form of the files lce encrypts. The text form is an exact rendering of the
// binary form that package container describes, so either converts into the other without the key, and the tag
// covers every character of the text:
//
//	-----BEGIN LIFE CIPHER MESSAGE----------------------------------
//	Version: 1
//	T: 6000
//	S: 16
//	k: 30
//	R: 24
//	-----IV---------------------------------------------------------
//	T0lbEdMCeJJUbbCInJV+6OSfXcGMBCGi8Y4b0bLwuE3Eo/7LjmBMmdCZ1hwXAbsq
//	H8/Ejc17GUO39UzNdjFDz7d3Q4nVg5Qi77yY7ydig7tVW8EdK9DCaEFbaLKAjjdH
//	WtdBlbA5w0Hk8KzSe8I+oEuV0VB3UQBVU6h7ACD3xSk=
//	-----CIPHERTEXT-------------------------------------------------
//	Tss8BMss8isf7g1DpChO
//	-----TAG--------------------------------------------------------
//	n4mIyB8hpaS8z4TD5AxqNQ==
//	-----END LIFE CIPHER MESSAGE------------------------------------
//
// The BEGIN line stands for the binary header's magic and its format version, 1, and the header lines give its
// algorithm version and its parameter words, as decimal numbers. The IV, the ciphertext and the tag follow in
// standard base64 with padding, 64 characters to a line, the last line of each shorter if need be; an empty
// ciphertext has no lines. Every divider is "-----", a label, and dashes to 64 characters. Every line ends in a newline.
//
// A Reader accepts exactly that text, with three exceptions for what transport does to text: lines may end in CRLF,
// whatever comes before the BEGIN line or after the END line is ignored, including a byte-order mark that starts the
// input, and the END line may lack its newline.
package armor

import (
	"bufio"
	"bytes"
	"cmp"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/t3spe/life-cipher-runner/internal/container"
	"github.com/t3spe/life-cipher-runner/lifecipher"
)

const (
	// Width is the width of every divider, and of every full line of base64.
	Width = 64

	lineBytes = Width / 4 * 3                            // the bytes a full line of base64 holds
	headSize  = container.HeaderSize + lifecipher.IVSize // the binary form up to its ciphertext
	window    = lineBytes + lifecipher.TagSize           // what a Writer holds: a line, and what may be the tag
	maxLine   = 4096                                     // the longest line a Reader looks at
	bom       = "\uFEFF"                                 // a byte-order mark, which a Reader skips at the start
)

// labels are the header lines' labels, in order.
var labels = [...]string{"Version", "T", "S", "k", "R"}

// The dividers.
var (
	beginLine      = divider("BEGIN LIFE CIPHER MESSAGE")
	ivLine         = divider("IV")
	ciphertextLine = divider("CIPHERTEXT")
	tagLine        = divider("TAG")
	endLine        = divider("END LIFE CIPHER MESSAGE")
)

// divider returns "-----", the label, and dashes to Width characters.
func divider(label string) string {
	return "-----" + label + strings.Repeat("-", Width-5-len(label))
}

var (
	// ErrFormat is returned, wrapped with the line and the reason, for text that isn't exactly the text form.
	ErrFormat = errors.New("not in lce's text form")

	errClosed = errors.New("armor: the Writer is closed")
)

// A Writer turns an encrypted file in the binary form, written to it, into the text form, written to the underlying
// writer. It holds back the last 16 bytes written, which may be the tag, until more arrive. Close writes them as the
// tag, and ends the text.
type Writer struct {
	w      *bufio.Writer
	buf    []byte          // the header and the IV until both have arrived, then ciphertext and what may be the tag
	text   [Width + 1]byte // a line of base64 and its newline
	body   bool            // the header and the IV are written
	closed bool
	err    error // the first error, which every later call returns
}

// NewWriter returns a Writer that writes the text form to w.
func NewWriter(w io.Writer) *Writer {
	return &Writer{w: bufio.NewWriter(w), buf: make([]byte, 0, max(headSize, window))}
}

// Write takes the next part of the binary form.
func (a *Writer) Write(p []byte) (int, error) {
	switch {
	case a.closed:
		return 0, errClosed
	case a.err != nil:
		return 0, a.err
	}
	n := len(p)
	if !a.body {
		k := min(headSize-len(a.buf), len(p))
		a.buf, p = append(a.buf, p[:k]...), p[k:]
		if len(a.buf) < headSize {
			return n, nil
		}
		a.writeHead()
		a.buf, a.body = a.buf[:0], true
	}
	// Bytes with at least TagSize more after them are ciphertext, written a line at a time.
	for len(p) > 0 && a.err == nil {
		k := min(window-len(a.buf), len(p))
		a.buf, p = append(a.buf, p[:k]...), p[k:]
		if len(a.buf) == window {
			a.line(a.buf[:lineBytes])
			a.buf = a.buf[:copy(a.buf, a.buf[lineBytes:])]
		}
	}
	if a.err != nil {
		return 0, a.err
	}
	return n, nil
}

// Close writes the tag and the END line, and flushes the text to the underlying writer. It fails if fewer bytes
// were written than the shortest binary form holds. Calling Close again returns the same result.
func (a *Writer) Close() error {
	if !a.closed {
		a.closed = true
		a.finish()
	}
	return a.err
}

// finish writes the end of the text: the last line of ciphertext, the tag and the END line.
func (a *Writer) finish() {
	switch {
	case a.err != nil:
		return
	case !a.body || len(a.buf) < lifecipher.TagSize:
		a.err = container.ErrTruncated
		return
	}
	tag := len(a.buf) - lifecipher.TagSize
	if tag > 0 {
		a.line(a.buf[:tag])
	}
	a.put(tagLine)
	a.line(a.buf[tag:])
	a.put(endLine)
	a.err = cmp.Or(a.err, a.w.Flush())
}

// writeHead writes the text up to the ciphertext: the BEGIN line, the header lines and the IV.
func (a *Writer) writeHead() {
	p, err := container.ParseHeader(a.buf[:container.HeaderSize])
	if err != nil {
		a.err = err
		return
	}
	a.put(beginLine)
	for i, v := range headerValues(p) {
		a.put(labels[i] + ": " + strconv.FormatUint(uint64(v), 10))
	}
	a.put(ivLine)
	for iv := a.buf[container.HeaderSize:]; len(iv) > 0; iv = iv[min(lineBytes, len(iv)):] {
		a.line(iv[:min(lineBytes, len(iv))])
	}
	a.put(ciphertextLine)
}

// line writes b, at most a line's worth of bytes, as a line of base64.
func (a *Writer) line(b []byte) {
	n := base64.StdEncoding.EncodedLen(len(b))
	base64.StdEncoding.Encode(a.text[:], b)
	a.text[n] = '\n'
	_, err := a.w.Write(a.text[:n+1])
	a.err = cmp.Or(a.err, err)
}

// put writes the line s.
func (a *Writer) put(s string) {
	_, _ = a.w.WriteString(s) // bufio.Writer keeps the first error, and returns it from every later call
	a.err = cmp.Or(a.err, a.w.WriteByte('\n'))
}

// headerValues returns p's values in the order of the header lines.
func headerValues(p lifecipher.Params) [len(labels)]uint32 {
	return [...]uint32{p.Version, p.Generations, p.GroupSize, p.Shuffles, p.Rounds}
}

// A Reader turns the text form, read from the underlying reader, back into the binary form. It reads the text
// strictly: a line that isn't exactly what a Writer writes is an error wrapping ErrFormat, a text that ends before its
// END line is one wrapping container.ErrTruncated, and one with no BEGIN line is container.ErrNotEncrypted. Each
// error gives the line where the text went wrong, but for the last.
type Reader struct {
	r     *bufio.Reader
	n     int          // the number of lines read, for messages
	out   []byte       // binary form not yet returned
	step  func() error // reads the next part of the text
	short bool         // the last line of base64 was short, so its section must end
	iv    [lifecipher.IVSize]byte
	ivLen int
	bin   [lineBytes]byte // a line of base64's bytes
	text  [Width]byte     // a line of base64, encoded again to check it
	err   error
}

// NewReader returns a Reader that reads the text form from r.
func NewReader(r io.Reader) *Reader {
	a := &Reader{r: bufio.NewReaderSize(r, maxLine)}
	a.step = a.begin
	return a
}

// Read returns the next part of the binary form.
func (a *Reader) Read(p []byte) (int, error) {
	for len(a.out) == 0 && a.err == nil {
		a.err = a.step()
	}
	if len(a.out) > 0 {
		n := copy(p, a.out)
		a.out = a.out[n:]
		return n, nil
	}
	return 0, a.err
}

// begin skips everything before the BEGIN line.
func (a *Reader) begin() error {
	for {
		line, err := a.r.ReadSlice('\n')
		for errors.Is(err, bufio.ErrBufferFull) { // a long line, which can't be the BEGIN line
			_, err = a.r.ReadSlice('\n')
			line = nil
		}
		if a.n == 0 {
			line = bytes.TrimPrefix(line, []byte(bom))
		}
		a.n++
		if l, _ := trimEOL(line); string(l) == beginLine {
			a.step = a.header
			return nil
		}
		switch {
		case errors.Is(err, io.EOF):
			return container.ErrNotEncrypted
		case err != nil:
			return err
		}
	}
}

// header reads the header lines and the IV's divider, and gives back the binary header.
func (a *Reader) header() error {
	var v [len(labels)]uint32
	for i, label := range labels {
		line, err := a.line()
		if err != nil {
			return err
		}
		digits, ok := bytes.CutPrefix(line, []byte(label+": "))
		n, perr := strconv.ParseUint(string(digits), 10, 32)
		if !ok || perr != nil || strconv.FormatUint(n, 10) != string(digits) {
			return a.errorf("expected %q and a number", label+":")
		}
		v[i] = uint32(n)
	}
	if err := a.expect(ivLine, "the IV's divider"); err != nil {
		return err
	}
	a.out = container.Header(lifecipher.Params{Version: v[0], Generations: v[1], GroupSize: v[2], Shuffles: v[3],
		Rounds: v[4]})
	a.step = a.ivLines
	return nil
}

// ivLines reads the IV and the ciphertext's divider, and gives back the IV.
func (a *Reader) ivLines() error {
	for {
		b, done, err := a.base64Line(ciphertextLine, "the ciphertext's divider")
		if err != nil {
			return err
		}
		if done {
			break
		}
		if a.ivLen+len(b) > lifecipher.IVSize {
			return a.errorf("the IV is longer than %d bytes", lifecipher.IVSize)
		}
		a.ivLen += copy(a.iv[a.ivLen:], b)
	}
	if a.ivLen != lifecipher.IVSize {
		return a.errorf("the IV is %d bytes, not %d", a.ivLen, lifecipher.IVSize)
	}
	a.out = a.iv[:]
	a.step = a.ciphertext
	return nil
}

// ciphertext reads one line of the ciphertext, or the tag's divider.
func (a *Reader) ciphertext() error {
	b, done, err := a.base64Line(tagLine, "the tag's divider")
	switch {
	case err != nil:
		return err
	case done:
		a.step = a.tag
	}
	a.out = b
	return nil
}

// tag reads the tag and the END line, and gives back the tag.
func (a *Reader) tag() error {
	line, err := a.line()
	if err != nil {
		return err
	}
	if n, ok := a.decode(line); !ok || n != lifecipher.TagSize {
		return a.errorf("expected the %d-byte tag", lifecipher.TagSize)
	}
	if err := a.expect(endLine, "the END line"); err != nil {
		return err
	}
	a.out = a.bin[:lifecipher.TagSize]
	a.step = func() error { return io.EOF }
	return nil
}

// base64Line reads one line of a section of base64 that ends at the divider, which what describes. It returns the
// line's bytes, which the next line read replaces, or done if the line is the divider.
func (a *Reader) base64Line(divider, what string) (b []byte, done bool, err error) {
	line, err := a.line()
	switch {
	case err != nil:
		return nil, false, err
	case string(line) == divider:
		a.short = false
		return nil, true, nil
	case a.short: // a short line ends its section
		return nil, false, a.errorf("expected %s", what)
	}
	n, ok := a.decode(line)
	if !ok {
		return nil, false, a.errorf("expected a line of base64, at most %d characters, or %s", Width, what)
	}
	a.short = n < lineBytes
	return a.bin[:n], false, nil
}

// decode decodes a line of base64 into a.bin. It reports whether the line is one a Writer writes: at most Width
// characters, which are the standard encoding of their bytes. Decoding alone would also skip CRs, and allow padding
// bits that are set.
func (a *Reader) decode(line []byte) (int, bool) {
	if len(line) == 0 || len(line) > Width {
		return 0, false
	}
	n, err := base64.StdEncoding.Decode(a.bin[:], line)
	return n, err == nil && bytes.Equal(base64.StdEncoding.AppendEncode(a.text[:0], a.bin[:n]), line)
}

// expect reads one line, which must be the divider.
func (a *Reader) expect(divider, what string) error {
	line, err := a.line()
	if err == nil && string(line) != divider {
		err = a.errorf("expected %s", what)
	}
	return err
}

// line reads the next line, without its line ending. The line is valid until the next read. The end of the input
// before the END line, even in the middle of a line, means the text is truncated.
func (a *Reader) line() ([]byte, error) {
	b, err := a.r.ReadSlice('\n')
	switch {
	case errors.Is(err, bufio.ErrBufferFull):
		a.n++
		return nil, a.errorf("the line is longer than %d bytes", maxLine)
	case err != nil && !errors.Is(err, io.EOF):
		return nil, err
	case len(b) == 0:
		return nil, a.truncated()
	}
	a.n++
	line, ended := trimEOL(b)
	if !ended && string(line) != endLine { // only the END line may lack its newline
		return nil, a.truncated()
	}
	return line, nil
}

func (a *Reader) errorf(format string, args ...any) error {
	return fmt.Errorf("%w: line %d: %s", ErrFormat, a.n, fmt.Sprintf(format, args...))
}

func (a *Reader) truncated() error {
	return fmt.Errorf("%w: the text stops at line %d, before its END line", container.ErrTruncated, a.n)
}

// trimEOL returns a line without its LF or CRLF, and whether it had one: a CR without an LF stays.
func trimEOL(b []byte) ([]byte, bool) {
	b, ok := bytes.CutSuffix(b, []byte("\n"))
	if ok {
		b, _ = bytes.CutSuffix(b, []byte("\r"))
	}
	return b, ok
}

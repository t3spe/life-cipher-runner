// Package keyfile reads Life Cipher keys from files.
//
// A key is a 32 × 32 grid, 128 bytes in the byte layout of SPEC.md §2.2. A key file holds it in one of three forms:
//
//   - exactly 128 bytes: the key itself
//   - text with 256 hex digits: the key's bytes, as SPEC.md writes keys (32 row words of 8 digits)
//   - text with 1,024 binary digits: the cells in row order, one digit per cell, live cells as 1
//
// ASCII whitespace (space, tab, newline, vertical tab, form feed, carriage return) anywhere in a text key is ignored,
// and so is a UTF-8 byte-order mark at its start. The digits are decoded without branching on their values or using
// them as table indexes, so the decoding's timing and memory accesses don't depend on the key. Read holds the file in
// one buffer and wipes it, and Parse wipes its own copies; the caller wipes the key.
package keyfile

import (
	"bytes"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/t3spe/life-cipher-runner/lifecipher"
)

// MaxSize is the largest key file Read accepts. A text key, even with generous whitespace, is a few kilobytes.
const MaxSize = 64 << 10

// ErrFormat is returned, wrapped with the reason, for data that doesn't hold a key in any of the accepted forms.
var ErrFormat = errors.New("not a key")

// Read returns the key in the file at path.
func Read(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }() // only read from, so closing it can't lose data
	// One buffer that never grows, so no copy of the key is left behind unwiped.
	buf := make([]byte, MaxSize+1)
	defer clear(buf)
	n, err := io.ReadFull(f, buf)
	switch {
	case err == nil:
		return nil, fmt.Errorf("%s: %w: the file is larger than %d bytes", path, ErrFormat, MaxSize)
	case !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF):
		return nil, err
	}
	key, err := Parse(buf[:n])
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return key, nil
}

// Parse returns the key in data, in any of the forms the package describes.
func Parse(data []byte) ([]byte, error) {
	if len(data) == lifecipher.KeySize {
		return bytes.Clone(data), nil
	}
	text := bytes.TrimPrefix(data, []byte("\uFEFF"))
	digits := make([]byte, 0, len(text))
	defer func() { clear(digits) }()
	for _, c := range text {
		if space(c) == 0 { // the same branch for every digit, whatever its value
			digits = append(digits, c)
		}
	}

	key := make([]byte, lifecipher.KeySize)
	bad := 0
	switch len(digits) {
	case 2 * lifecipher.KeySize:
		for i := range key {
			hi, hiOK := hexDigit(digits[2*i])
			lo, loOK := hexDigit(digits[2*i+1])
			key[i] = byte(hi<<4 | lo)
			bad |= hiOK&loOK ^ 1
		}
	case 8 * lifecipher.KeySize:
		for i, c := range digits {
			one := subtle.ConstantTimeByteEq(c, '1')
			bad |= (one | subtle.ConstantTimeByteEq(c, '0')) ^ 1
			key[i/8] |= byte(one) << (7 - i%8)
		}
	default:
		return nil, fmt.Errorf("%w: expected 128 bytes, or text with 256 hex digits or 1,024 binary digits, "+
			"but found %d bytes, %d of them not ASCII whitespace", ErrFormat, len(data), len(digits))
	}
	if bad != 0 {
		clear(key)
		if len(digits) == 2*lifecipher.KeySize {
			return nil, fmt.Errorf("%w: 256 bytes besides whitespace, but not all of them hex digits", ErrFormat)
		}
		return nil, fmt.Errorf("%w: 1,024 bytes besides whitespace, but not all of them 0 or 1", ErrFormat)
	}
	return key, nil
}

// space returns 1 if c is ASCII whitespace (space, tab, newline, vertical tab, form feed, carriage return) and 0
// otherwise, in constant time.
func space(c byte) int {
	return subtle.ConstantTimeByteEq(c, ' ') | between(c, '\t', '\r')
}

// hexDigit returns the value of the hex digit c and 1, or 0 and 0 if c isn't a hex digit, in constant time.
func hexDigit(c byte) (value, ok int) {
	lower := c | 0x20 // 'a' … 'f' for 'a' … 'f' and 'A' … 'F', and for nothing else
	isDigit, isLetter := between(c, '0', '9'), between(lower, 'a', 'f')
	value = subtle.ConstantTimeSelect(isDigit, int(c-'0'), 0) |
		subtle.ConstantTimeSelect(isLetter, int(lower-'a'+10), 0)
	return value, isDigit | isLetter
}

// between returns 1 if lo ≤ c ≤ hi and 0 otherwise, in constant time.
func between(c, lo, hi byte) int {
	return subtle.ConstantTimeLessOrEq(int(lo), int(c)) & subtle.ConstantTimeLessOrEq(int(c), int(hi))
}

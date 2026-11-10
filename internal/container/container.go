// Package container reads and writes the files lce encrypts. A file is a 32-byte header, the 128-byte IV, the
// ciphertext, exactly as long as the plaintext, and the 16-byte tag:
//
//	offset   size  field
//	0        8     the magic, "LIFECIPH"
//	8        4     the format version, 1
//	12       20    the parameter words T, k, S, R and the algorithm version, in the order SPEC.md §6.2 uses
//	32       128   the IV
//	160      n     the ciphertext
//	160 + n  16    the tag
//
// Integers are big-endian 32-bit words. The header is the message's associated data, so the tag covers it as well as
// the IV and the ciphertext: a change anywhere in the file makes decryption fail. Package armor writes and reads the
// same file as text.
package container

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/t3spe/life-cipher-runner/lifecipher"
)

const (
	// Magic starts every encrypted file.
	Magic = "LIFECIPH"
	// FormatVersion is the version of the layout the package describes.
	FormatVersion = 1
	// HeaderSize is the size of the header: the magic, the format version and five parameter words.
	HeaderSize = len(Magic) + 4 + 5*4
	// Overhead is how much longer an encrypted file is than its plaintext.
	Overhead = HeaderSize + lifecipher.IVSize + lifecipher.TagSize

	// chunkSize is how much data the package encrypts or decrypts at a time: a whole number of blocks.
	chunkSize = 512 * lifecipher.BlockSize
)

var (
	// ErrNotEncrypted is returned for a file that doesn't start with the magic.
	ErrNotEncrypted = errors.New("not a file encrypted by lce")
	// ErrTruncated is returned for a file that ends before its tag.
	ErrTruncated = errors.New("the file is truncated")
	// ErrFormatVersion is returned, wrapped, for a file in a format version this package doesn't read.
	ErrFormatVersion = errors.New("unsupported format version")
	// ErrParams is what a *ParamsError matches.
	ErrParams = errors.New("the file was encrypted under another parameter set")
)

// A ParamsError reports a file encrypted under another parameter set than the key's. It matches ErrParams.
type ParamsError struct {
	File, Key lifecipher.Params // the set the file's header names, and the set the key is set up for
}

func (e *ParamsError) Error() string {
	return fmt.Sprintf("%v: %v, not %v", ErrParams, e.File, e.Key)
}

// Unwrap returns ErrParams.
func (e *ParamsError) Unwrap() error { return ErrParams }

// Header returns the header of a file encrypted under p.
func Header(p lifecipher.Params) []byte {
	h := make([]byte, 0, HeaderSize)
	h = append(h, Magic...)
	for _, w := range []uint32{FormatVersion, p.Generations, p.Shuffles, p.GroupSize, p.Rounds, p.Version} {
		h = binary.BigEndian.AppendUint32(h, w)
	}
	return h
}

// ParseHeader returns the parameter set a header names. h must be HeaderSize bytes. It returns ErrNotEncrypted if h
// doesn't start with the magic, and an error wrapping ErrFormatVersion for a format version other than FormatVersion.
func ParseHeader(h []byte) (lifecipher.Params, error) {
	if string(h[:len(Magic)]) != Magic {
		return lifecipher.Params{}, ErrNotEncrypted
	}
	if v := binary.BigEndian.Uint32(h[len(Magic):]); v != FormatVersion {
		return lifecipher.Params{}, fmt.Errorf("%w %d", ErrFormatVersion, v)
	}
	word := func(i int) uint32 { return binary.BigEndian.Uint32(h[len(Magic)+4+4*i:]) }
	return lifecipher.Params{Generations: word(0), Shuffles: word(1), GroupSize: word(2), Rounds: word(3),
		Version: word(4)}, nil
}

// Encrypt reads plaintext from r until it ends, and writes the encrypted file to w: the header for k's parameter set,
// iv, the ciphertext and the tag. iv must be lifecipher.IVSize bytes and never used before with k.
//
// Encrypt stops with ctx's error if ctx is done, even once the input has ended: an interrupt may have stopped whatever
// wrote the input as well, so the input isn't taken for the whole plaintext, and gets no tag.
func Encrypt(ctx context.Context, k *lifecipher.Key, iv []byte, r io.Reader, w io.Writer) error {
	hdr := Header(k.Params())
	e := k.NewEncryptor(iv, hdr)
	defer e.Erase() // wipes the cipher's state, whichever way Encrypt returns
	if _, err := w.Write(append(hdr, iv...)); err != nil {
		return err
	}
	buf := make([]byte, chunkSize+lifecipher.TagSize) // room for the last piece and the tag
	defer clear(buf)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, err := io.ReadFull(r, buf[:chunkSize])
		if err == nil { // a whole chunk, and maybe more to come
			e.EncryptBlocks(buf[:chunkSize], buf[:chunkSize])
			if _, err = w.Write(buf[:chunkSize]); err != nil {
				return err
			}
			continue
		}
		if !isEOF(err) {
			return err
		}
		if err = ctx.Err(); err != nil {
			return err
		}
		// The end of the plaintext: n < chunkSize bytes, its last part shorter than a block.
		whole := n / lifecipher.BlockSize * lifecipher.BlockSize
		e.EncryptBlocks(buf[:whole], buf[:whole])
		tag := e.Finish(buf[whole:n], buf[whole:n])
		_, err = w.Write(append(buf[:n], tag[:]...))
		return err
	}
}

// Decrypt reads an encrypted file from r, and writes its plaintext to w. It returns lifecipher.ErrOpen if the tag
// doesn't match, a *ParamsError if the file needs another parameter set than k's, and ctx's error if ctx is done, as
// Encrypt does.
//
// The plaintext reaches w as it's decrypted, before the tag at the end of the file is checked. If Decrypt returns
// an error, the caller must discard everything written to w.
func Decrypt(ctx context.Context, k *lifecipher.Key, r io.Reader, w io.Writer) error {
	head := make([]byte, HeaderSize+lifecipher.IVSize)
	if n, err := io.ReadFull(r, head); err != nil {
		switch {
		case !isEOF(err):
			return err
		case n < len(Magic) || string(head[:len(Magic)]) != Magic:
			return ErrNotEncrypted
		}
		return ErrTruncated
	}
	p, err := ParseHeader(head[:HeaderSize])
	if err != nil {
		return err
	}
	if p != k.Params() {
		return &ParamsError{File: p, Key: k.Params()}
	}
	d := k.NewDecryptor(head[HeaderSize:], head[:HeaderSize])
	defer d.Erase()

	// Everything after the IV is ciphertext and then the tag, so the last TagSize bytes read are held back until
	// more arrive or the file ends.
	buf := make([]byte, chunkSize+lifecipher.TagSize)
	defer clear(buf)
	held := 0
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, err := io.ReadFull(r, buf[held:])
		held += n
		if err == nil { // the buffer is full: decrypt a chunk, and keep the last TagSize bytes
			d.DecryptBlocks(buf[:chunkSize], buf[:chunkSize])
			if _, err = w.Write(buf[:chunkSize]); err != nil {
				return err
			}
			held = copy(buf, buf[chunkSize:])
			continue
		}
		if !isEOF(err) {
			return err
		}
		if err = ctx.Err(); err != nil {
			return err
		}
		if held < lifecipher.TagSize {
			return ErrTruncated
		}
		ct, tag := buf[:held-lifecipher.TagSize], buf[held-lifecipher.TagSize:held]
		whole := len(ct) / lifecipher.BlockSize * lifecipher.BlockSize
		d.DecryptBlocks(ct[:whole], ct[:whole])
		if err = d.Finish(ct[whole:], ct[whole:], tag); err != nil {
			return err
		}
		_, err = w.Write(ct)
		return err
	}
}

// isEOF reports whether err from io.ReadFull means the input ended, rather than failed.
func isEOF(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
}

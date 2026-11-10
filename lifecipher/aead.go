package lifecipher

import (
	"crypto/cipher"
	"crypto/subtle"
	"errors"
	"unsafe"
)

const (
	// BlockSize is the size of a message block: data is absorbed one grid at a time (§7).
	BlockSize = gridBytes
	// IVSize is the size of the IV, the cipher's nonce (§3.1).
	IVSize = gridBytes
	// TagSize is the size of the tag (§3.1).
	TagSize = 16

	// marker is the end marker absorbed after the last byte of the associated data and of the message (§7.2, §7.4).
	marker = 0x80
)

// ErrOpen is returned when a tag doesn't match: the message, its IV or its associated data were changed, or the
// key is wrong (§8).
var ErrOpen = errors.New("lifecipher: message authentication failed")

var _ cipher.AEAD = (*Key)(nil)

// NonceSize returns IVSize, the size of the IV. A Key is a crypto/cipher.AEAD whose nonce is the IV.
func (k *Key) NonceSize() int { return IVSize }

// Overhead returns TagSize: Seal appends the tag to the ciphertext.
func (k *Key) Overhead() int { return TagSize }

// begin runs Init (§7.1), absorbs the associated data (§7.2) and flips the separator (§7.3): everything before the
// message. It panics if the key was erased or the IV isn't IVSize bytes.
func (k *Key) begin(iv, ad []byte) state {
	switch {
	case k.w == nil:
		panic("lifecipher: the key was erased")
	case len(iv) != IVSize:
		panic("lifecipher: the IV must be 128 bytes")
	}
	R := uint64(k.p.Rounds)
	ivg := gridFromBytes(iv)
	st := state{b: k.k, o: fold(&ivg) % (k.p.Generations / k.p.GroupSize)}
	for r := range st.a {
		st.a[r] = ivg[r] ^ k.m[r]
	}
	st.rounds(k.w, 2*R)

	// The associated data, one block at a time. The last block is shorter than BlockSize, possibly empty, and the end
	// marker follows it. With no associated data, the step is skipped entirely, marker and all.
	for off := 0; len(ad) > 0 && off <= len(ad); off += BlockSize {
		L := min(BlockSize, len(ad)-off)
		for i, v := range ad[off : off+L] {
			st.b.xorByte(i, v)
		}
		if L < BlockSize {
			st.b.xorByte(L, marker)
		}
		st.rounds(k.w, R)
	}

	st.a[31] ^= 1 // the separator: cell (31, 31), the last cell of A
	return st
}

// end absorbs the end marker after the message's last L bytes, runs the finish (§7.5), and returns the tag, the
// first TagSize bytes of B. It erases the state.
func (st *state) end(k *Key, L int) [TagSize]byte {
	st.b.xorByte(L, marker)
	st.rounds(k.w, 2*uint64(k.p.Rounds))
	var tag [TagSize]byte
	for i := range tag {
		tag[i] = st.b.byteAt(i)
	}
	*st = state{}
	return tag
}

// checkBlocks panics unless src is whole blocks, dst is at least as long without partly overlapping src, and the
// message isn't finished.
func checkBlocks(done bool, dst, src []byte) {
	switch {
	case done:
		panic("lifecipher: the message is already finished")
	case len(src)%BlockSize != 0:
		panic("lifecipher: input isn't a whole number of blocks")
	case len(dst) < len(src):
		panic("lifecipher: output smaller than input")
	case inexactOverlap(dst[:len(src)], src):
		panic("lifecipher: invalid buffer overlap")
	}
}

// checkFinish panics unless src is shorter than a block, dst is at least as long without partly overlapping src, and
// the message isn't finished.
func checkFinish(done bool, dst, src []byte) {
	switch {
	case done:
		panic("lifecipher: the message is already finished")
	case len(src) >= BlockSize:
		panic("lifecipher: the end of a message is shorter than a block")
	case len(dst) < len(src):
		panic("lifecipher: output smaller than input")
	case inexactOverlap(dst[:len(src)], src):
		panic("lifecipher: invalid buffer overlap")
	}
}

// inexactOverlap reports whether x and y share memory without starting at the same place, so that writing x would
// overwrite parts of y not yet read. Exact overlap, the same start, is how in-place work is done, and is allowed.
func inexactOverlap(x, y []byte) bool {
	if len(x) == 0 || len(y) == 0 || &x[0] == &y[0] {
		return false
	}
	xs := uintptr(unsafe.Pointer(&x[0])) //nolint:gosec // only compared, never turned back into a pointer
	ys := uintptr(unsafe.Pointer(&y[0])) //nolint:gosec // only compared, never turned back into a pointer
	return xs < ys+uintptr(len(y)) && ys < xs+uintptr(len(x))
}

// An Encryptor encrypts one message incrementally (§7). Pass the message's whole blocks to EncryptBlocks, in as many
// calls as suits, then the rest, shorter than a block and possibly empty, to Finish, which returns the tag. The
// output is exactly what Seal gives. The work runs with the processor's data-independent timing mode on, where it has
// one (crypto/subtle.WithDataIndependentTiming), as for every method that uses the key.
type Encryptor struct {
	k    *Key
	st   state
	done bool
}

// NewEncryptor starts encrypting a message under the IV iv, which must be IVSize bytes and never used before with
// this key, and the associated data ad, which the tag covers but which isn't encrypted. It panics if the IV isn't
// IVSize bytes, or if the key was erased.
func (k *Key) NewEncryptor(iv, ad []byte) (e *Encryptor) {
	subtle.WithDataIndependentTiming(func() { e = &Encryptor{k: k, st: k.begin(iv, ad)} })
	return e
}

// EncryptBlocks encrypts whole blocks of the message into dst. len(src) must be a multiple of BlockSize, and dst at
// least as long as src. dst and src may be the same slice, but must not otherwise overlap; EncryptBlocks panics if
// they do.
func (e *Encryptor) EncryptBlocks(dst, src []byte) {
	checkBlocks(e.done, dst, src)
	subtle.WithDataIndependentTiming(func() {
		R := uint64(e.k.p.Rounds)
		for off := 0; off < len(src); off += BlockSize {
			c := gridFromBytes(src[off:])
			c.xor(&e.st.b) // the ciphertext: the plaintext XOR the pad, B
			e.st.b = c     // absorbed into B (§7.4)
			c.putBytes(dst[off:])
			e.st.rounds(e.k.w, R)
		}
	})
}

// Finish encrypts the end of the message, src, shorter than BlockSize and possibly empty, into dst, and returns the
// tag. dst must be at least as long as src; dst and src may be the same slice, but must not otherwise overlap. The
// Encryptor can't be used after it.
func (e *Encryptor) Finish(dst, src []byte) (tag [TagSize]byte) {
	checkFinish(e.done, dst, src)
	subtle.WithDataIndependentTiming(func() {
		for i, p := range src {
			c := p ^ e.st.b.byteAt(i)
			e.st.b.setByte(i, c)
			dst[i] = c
		}
		e.done = true
		tag = e.st.end(e.k, len(src))
	})
	return tag
}

// Erase overwrites the Encryptor's state with zeros, for a message abandoned before Finish. The Encryptor can't be
// used afterwards.
func (e *Encryptor) Erase() {
	e.st = state{}
	e.done = true
}

// A Decryptor decrypts one message incrementally (§8), the counterpart of an Encryptor. Its plaintext isn't authentic
// until Finish has checked the tag: until then the caller must not release or use any of it, and if Finish fails, the
// caller must erase all of it.
type Decryptor struct {
	k    *Key
	st   state
	done bool
}

// NewDecryptor starts decrypting a message encrypted under the IV iv and the associated data ad. It panics if the IV
// isn't IVSize bytes, or if the key was erased.
func (k *Key) NewDecryptor(iv, ad []byte) (d *Decryptor) {
	subtle.WithDataIndependentTiming(func() { d = &Decryptor{k: k, st: k.begin(iv, ad)} })
	return d
}

// DecryptBlocks decrypts whole blocks of the ciphertext into dst. len(src) must be a multiple of BlockSize, and dst
// at least as long as src. dst and src may be the same slice, but must not otherwise overlap; DecryptBlocks panics if
// they do. The plaintext isn't authentic until Finish returns nil.
func (d *Decryptor) DecryptBlocks(dst, src []byte) {
	checkBlocks(d.done, dst, src)
	subtle.WithDataIndependentTiming(func() {
		R := uint64(d.k.p.Rounds)
		for off := 0; off < len(src); off += BlockSize {
			c := gridFromBytes(src[off:])
			p := c
			p.xor(&d.st.b) // the plaintext: the ciphertext XOR the pad, B
			d.st.b = c     // the ciphertext is absorbed exactly as the sender absorbed it (§8)
			p.putBytes(dst[off:])
			d.st.rounds(d.k.w, R)
		}
	})
}

// Finish decrypts the end of the ciphertext, src, shorter than BlockSize and possibly empty, into dst, and compares
// the tag it computes with tag over all 16 bytes, in constant time (§8). If they differ, it erases dst[:len(src)]
// and returns ErrOpen, and the caller must erase all the plaintext DecryptBlocks gave. dst must be at least as long
// as src; dst and src may be the same slice, but must not otherwise overlap. The Decryptor can't be used after it.
func (d *Decryptor) Finish(dst, src, tag []byte) (err error) {
	checkFinish(d.done, dst, src)
	subtle.WithDataIndependentTiming(func() {
		for i, c := range src {
			dst[i] = c ^ d.st.b.byteAt(i)
			d.st.b.setByte(i, c)
		}
		d.done = true
		want := d.st.end(d.k, len(src))
		if subtle.ConstantTimeCompare(want[:], tag) != 1 {
			clear(dst[:len(src)])
			err = ErrOpen
		}
	})
	return err
}

// Erase overwrites the Decryptor's state with zeros, for a message abandoned before Finish. The Decryptor can't be
// used afterwards.
func (d *Decryptor) Erase() {
	d.st = state{}
	d.done = true
}

// Seal encrypts and authenticates plaintext under the IV iv, authenticates the associated data ad, and appends the
// ciphertext and then the tag to dst (§7). The IV must be IVSize bytes and never used before with this key; Seal
// panics if it's the wrong size. To encrypt in place, pass plaintext[:0] as dst; otherwise dst's spare capacity must
// not overlap plaintext, and Seal panics if it does.
func (k *Key) Seal(dst, iv, plaintext, ad []byte) []byte {
	ret, out := sliceForAppend(dst, len(plaintext)+TagSize)
	if inexactOverlap(out, plaintext) {
		panic("lifecipher: invalid buffer overlap")
	}
	e := k.NewEncryptor(iv, ad)
	whole := len(plaintext) &^ (BlockSize - 1)
	e.EncryptBlocks(out[:whole], plaintext[:whole])
	tag := e.Finish(out[whole:len(plaintext)], plaintext[whole:])
	copy(out[len(plaintext):], tag[:])
	return ret
}

// Open decrypts and authenticates ciphertext, the output of Seal, and if its tag matches, appends the plaintext to
// dst (§8). Otherwise it returns ErrOpen and appends nothing. It panics if the IV isn't IVSize bytes. To decrypt in
// place, pass ciphertext[:0] as dst; otherwise dst's spare capacity must not overlap ciphertext, and Open panics if
// it does.
func (k *Key) Open(dst, iv, ciphertext, ad []byte) ([]byte, error) {
	if len(iv) != IVSize {
		panic("lifecipher: the IV must be 128 bytes")
	}
	if len(ciphertext) < TagSize {
		return nil, ErrOpen
	}
	n := len(ciphertext) - TagSize
	var tag [TagSize]byte
	copy(tag[:], ciphertext[n:])
	ret, out := sliceForAppend(dst, n)
	if inexactOverlap(out, ciphertext) {
		panic("lifecipher: invalid buffer overlap")
	}
	d := k.NewDecryptor(iv, ad)
	whole := n &^ (BlockSize - 1)
	d.DecryptBlocks(out[:whole], ciphertext[:whole])
	if err := d.Finish(out[whole:], ciphertext[whole:n], tag[:]); err != nil {
		clear(out)
		return nil, err
	}
	return ret, nil
}

// sliceForAppend extends in by n bytes, reusing its capacity when it can. It returns the whole slice and the n new
// bytes.
func sliceForAppend(in []byte, n int) (whole, tail []byte) {
	if total := len(in) + n; cap(in) >= total {
		whole = in[:total]
	} else {
		whole = make([]byte, total)
		copy(whole, in)
	}
	return whole, whole[len(in):]
}

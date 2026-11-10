package lifecipher

import (
	"bytes"
	"errors"
	"testing"
)

func FuzzLife(f *testing.F) {
	f.Add(make([]byte, gridBytes))
	f.Add(demoKeyBytes())
	f.Add(bytes.Repeat([]byte{0xFF}, gridBytes))
	f.Fuzz(func(t *testing.T, b []byte) {
		b = append(b, make([]byte, gridBytes)...) // short inputs become grids with dead cells
		g := gridFromBytes(b)
		if got, want := life(&g), lifeByRule(&g); got != want {
			t.Fatalf("grid %s:\n got %s\nwant %s", words(g), words(got), words(want))
		}
	})
}

func FuzzSealOpen(f *testing.F) {
	f.Add([]byte("an IV"), []byte("to: bob"), []byte("attack at dawn"), uint16(0))
	f.Add([]byte{}, []byte{}, []byte{}, uint16(5))
	f.Add(bytes.Repeat([]byte{0xFF}, IVSize), make([]byte, 300), make([]byte, 257), uint16(4000))
	f.Fuzz(func(t *testing.T, ivSeed, ad, pt []byte, flip uint16) {
		k := setupKey(t, Demo())
		iv := make([]byte, IVSize)
		copy(iv, ivSeed)
		sealed := k.Seal(nil, iv, pt, ad)
		got, err := k.Open(nil, iv, sealed, ad)
		if err != nil || !bytes.Equal(got, pt) {
			t.Fatalf("a %d-byte message with %d bytes of AD doesn't round-trip: %v", len(pt), len(ad), err)
		}
		bit := int(flip) % (8 * len(sealed))
		sealed[bit/8] ^= 1 << (bit % 8)
		if _, err := k.Open(nil, iv, sealed, ad); !errors.Is(err, ErrOpen) {
			t.Fatalf("Open accepted the message with bit %d flipped", bit)
		}
	})
}

func FuzzStreaming(f *testing.F) {
	f.Add(make([]byte, 1000), uint8(1), uint8(3))
	f.Add([]byte("short"), uint8(0), uint8(0))
	f.Fuzz(func(t *testing.T, pt []byte, cut1, cut2 uint8) {
		k := setupKey(t, Demo())
		iv := make([]byte, IVSize)
		sealed := k.Seal(nil, iv, pt, nil)
		// Pass the whole blocks in three pieces, cut at two points the fuzzer picks.
		blocks := len(pt) / BlockSize
		a := int(cut1) % (blocks + 1)
		b := a + int(cut2)%(blocks-a+1)
		e, d := k.NewEncryptor(iv, nil), k.NewDecryptor(iv, nil)
		ct, back := make([]byte, len(pt)), make([]byte, len(pt))
		for _, piece := range [][2]int{{0, a}, {a, b}, {b, blocks}} {
			lo, hi := piece[0]*BlockSize, piece[1]*BlockSize
			e.EncryptBlocks(ct[lo:hi], pt[lo:hi])
			d.DecryptBlocks(back[lo:hi], ct[lo:hi])
		}
		whole := blocks * BlockSize
		tag := e.Finish(ct[whole:], pt[whole:])
		if !bytes.Equal(append(ct, tag[:]...), sealed) {
			t.Fatal("the Encryptor differs from Seal")
		}
		if err := d.Finish(back[whole:], ct[whole:], tag[:]); err != nil || !bytes.Equal(back, pt) {
			t.Fatalf("the Decryptor doesn't give the plaintext back: %v", err)
		}
	})
}

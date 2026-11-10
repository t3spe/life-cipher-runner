package container

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"io"
	"math/rand/v2"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/iotest"

	"github.com/t3spe/life-cipher-runner/lifecipher"
)

// demoKey is the burned demo key of SPEC.md Appendix B. It must never protect anything.
const demoKey = "6B3028A8DB46016A318DA71385D82A926489431E9A2B00E11CB1E6844106B26D" +
	"90FC90AC77361985884930EB551A3B5281186009E814409482842900D88996D1" +
	"9514CC133A81EC3447580B9DF304B45184A2B2742412283808F6D9343A69CBB8" +
	"6A04296A5F54D36A425497691420992C30F902067215518A1CE02869BA961C3B"

var keys = sync.OnceValues(func() (map[lifecipher.Params]*lifecipher.Key, error) {
	key, err := hex.DecodeString(demoKey)
	if err != nil {
		return nil, err
	}
	m := map[lifecipher.Params]*lifecipher.Key{}
	for _, p := range []lifecipher.Params{lifecipher.Recommended(), lifecipher.Demo()} {
		if m[p], err = lifecipher.NewKey(p, key); err != nil {
			return nil, err
		}
	}
	return m, nil
})

func keyFor(t testing.TB, p lifecipher.Params) *lifecipher.Key {
	t.Helper()
	m, err := keys()
	if err != nil {
		t.Fatal(err)
	}
	return m[p]
}

func testIV() []byte {
	iv := make([]byte, lifecipher.IVSize)
	for i := range iv {
		iv[i] = byte(13 + 7*i)
	}
	return iv
}

func randomBytes(seed uint64, n int) []byte {
	rng := rand.New(rand.NewPCG(seed, seed))
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(rng.Uint32())
	}
	return b
}

func encrypt(t testing.TB, k *lifecipher.Key, pt []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	if err := Encrypt(context.Background(), k, testIV(), bytes.NewReader(pt), &out); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func decrypt(k *lifecipher.Key, r io.Reader) ([]byte, error) {
	var out bytes.Buffer
	err := Decrypt(context.Background(), k, r, &out)
	return out.Bytes(), err
}

func TestHeader(t *testing.T) {
	want, _ := hex.DecodeString("4c4946454349504800000001" + "00001770" + "0000001e" + "00000010" + "00000018" + "00000001")
	if got := Header(lifecipher.Recommended()); !bytes.Equal(got, want) {
		t.Errorf("the recommended set's header is %x, want %x", got, want)
	}
	for _, p := range []lifecipher.Params{lifecipher.Recommended(), lifecipher.Demo()} {
		got, err := ParseHeader(Header(p))
		if err != nil || got != p {
			t.Errorf("%v: the header parses as %v, %v", p, got, err)
		}
	}
	if HeaderSize != 32 || Overhead != 176 {
		t.Errorf("HeaderSize %d and Overhead %d", HeaderSize, Overhead)
	}
}

func TestEncryptIsSeal(t *testing.T) {
	// A file is the header, the IV, and Seal's output with the header as the associated data.
	k := keyFor(t, lifecipher.Recommended())
	iv, hdr := testIV(), Header(lifecipher.Recommended())
	for _, n := range []int{0, 1, 127, 128, 129, chunkSize - 1, chunkSize, chunkSize + 1, 3*chunkSize + 200} {
		pt := randomBytes(uint64(n), n)
		want := slices.Concat(hdr, iv, k.Seal(nil, iv, pt, hdr))
		if got := encrypt(t, k, pt); !bytes.Equal(got, want) {
			t.Fatalf("%d bytes: the file isn't header ‖ IV ‖ Seal(plaintext, AD = header)", n)
		}
		if len(want) != n+Overhead {
			t.Fatalf("%d bytes: the file is %d bytes", n, len(want))
		}
	}
}

func TestDecryptRoundTrip(t *testing.T) {
	k := keyFor(t, lifecipher.Recommended())
	for _, n := range []int{0, 1, 128, chunkSize - lifecipher.TagSize, chunkSize, chunkSize + 1, 2*chunkSize + 17} {
		pt := randomBytes(uint64(n)+1, n)
		file := encrypt(t, k, pt)
		for name, r := range map[string]io.Reader{
			"whole":         bytes.NewReader(file),
			"a byte a time": iotest.OneByteReader(bytes.NewReader(file)),
			"half reads":    iotest.HalfReader(bytes.NewReader(file)),
			"data with EOF": iotest.DataErrReader(bytes.NewReader(file)),
		} {
			got, err := decrypt(k, r)
			if err != nil || !bytes.Equal(got, pt) {
				t.Fatalf("%d bytes, %s: %v", n, name, err)
			}
		}
	}
}

func TestDecryptRefuses(t *testing.T) {
	k := keyFor(t, lifecipher.Recommended())
	file := encrypt(t, k, randomBytes(3, 1000))
	change := func(i int) []byte {
		c := slices.Clone(file)
		c[i] ^= 1
		return c
	}
	withHeader := func(p lifecipher.Params) []byte {
		return slices.Concat(Header(p), file[HeaderSize:])
	}
	version2 := slices.Clone(file)
	version2[11] = 2
	for name, c := range map[string]struct {
		file []byte
		want error
	}{
		"empty":                        {nil, ErrNotEncrypted},
		"shorter than the magic":       {[]byte("LIFE"), ErrNotEncrypted},
		"another magic":                {change(0), ErrNotEncrypted},
		"text":                         {[]byte(strings.Repeat("plain text, not encrypted\n", 20)), ErrNotEncrypted},
		"only the magic":               {[]byte(Magic), ErrTruncated},
		"header and part of the IV":    {file[:HeaderSize+100], ErrTruncated},
		"no tag":                       {file[:HeaderSize+lifecipher.IVSize], ErrTruncated},
		"15 bytes of tag":              {file[:HeaderSize+lifecipher.IVSize+15], ErrTruncated},
		"format version 2":             {version2, ErrFormatVersion},
		"the demo set's header":        {withHeader(lifecipher.Demo()), ErrParams},
		"a parameter word changed":     {change(HeaderSize - 1), ErrParams},
		"the IV changed":               {change(HeaderSize + 5), lifecipher.ErrOpen},
		"the ciphertext changed":       {change(HeaderSize + lifecipher.IVSize + 999), lifecipher.ErrOpen},
		"the tag changed":              {change(len(file) - 1), lifecipher.ErrOpen},
		"a byte cut from the end":      {file[:len(file)-1], lifecipher.ErrOpen},
		"a byte added at the end":      {append(slices.Clone(file), 0), lifecipher.ErrOpen},
		"no ciphertext, 16 bytes left": {file[:HeaderSize+lifecipher.IVSize+lifecipher.TagSize], lifecipher.ErrOpen},
	} {
		if _, err := decrypt(k, bytes.NewReader(c.file)); !errors.Is(err, c.want) {
			t.Errorf("%s: got %v, want %v", name, err, c.want)
		}
	}
	// A file encrypted under the demo set needs a key set up for it.
	demoFile := encrypt(t, keyFor(t, lifecipher.Demo()), []byte("demo"))
	_, err := decrypt(k, bytes.NewReader(demoFile))
	var pe *ParamsError
	if !errors.As(err, &pe) || pe.File != lifecipher.Demo() || pe.Key != lifecipher.Recommended() || err.Error() !=
		"the file was encrypted under another parameter set: T = 6000, S = 16, k = 4, R = 16, version 1, "+
			"not T = 6000, S = 16, k = 30, R = 24, version 1" {
		t.Errorf("a demo-set file: %v", err)
	}
	if got, err := decrypt(keyFor(t, lifecipher.Demo()), bytes.NewReader(demoFile)); err != nil || string(got) != "demo" {
		t.Errorf("a demo-set file under a demo-set key: %q, %v", got, err)
	}
}

// failingWriter fails once it has accepted limit bytes.
type failingWriter struct {
	limit int
	err   error
}

func (w *failingWriter) Write(p []byte) (int, error) {
	if len(p) > w.limit {
		n := w.limit
		w.limit = 0
		return n, w.err
	}
	w.limit -= len(p)
	return len(p), nil
}

func TestIOErrors(t *testing.T) {
	k := keyFor(t, lifecipher.Recommended())
	boom := errors.New("boom")
	pt := randomBytes(4, 2*chunkSize+5)
	file := encrypt(t, k, pt)
	ctx := context.Background()

	// Encrypt: the input fails, and the output fails while writing the header, a chunk, or the end.
	if err := Encrypt(ctx, k, testIV(), iotest.ErrReader(boom), io.Discard); !errors.Is(err, boom) {
		t.Errorf("Encrypt, a failing input: %v", err)
	}
	for _, limit := range []int{0, HeaderSize + lifecipher.IVSize + 10, len(file) - 3} {
		w := &failingWriter{limit, boom}
		if err := Encrypt(ctx, k, testIV(), bytes.NewReader(pt), w); !errors.Is(err, boom) {
			t.Errorf("Encrypt, an output that fails after %d bytes: %v", limit, err)
		}
	}

	// Decrypt: the input fails in the header or later, and the output fails while writing a chunk or the end.
	for _, at := range []int{0, 50, HeaderSize + lifecipher.IVSize + 3*lifecipher.BlockSize} {
		r := io.MultiReader(bytes.NewReader(file[:at]), iotest.ErrReader(boom))
		if _, err := decrypt(k, r); !errors.Is(err, boom) {
			t.Errorf("Decrypt, an input that fails after %d bytes: %v", at, err)
		}
	}
	for _, limit := range []int{10, len(pt) - 3} {
		w := &failingWriter{limit, boom}
		if err := Decrypt(ctx, k, bytes.NewReader(file), w); !errors.Is(err, boom) {
			t.Errorf("Decrypt, an output that fails after %d bytes: %v", limit, err)
		}
	}
}

func TestCancel(t *testing.T) {
	k := keyFor(t, lifecipher.Recommended())
	file := encrypt(t, k, randomBytes(5, chunkSize+1))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var out bytes.Buffer
	if err := Encrypt(ctx, k, testIV(), bytes.NewReader(file), &out); !errors.Is(err, context.Canceled) {
		t.Errorf("Encrypt: %v", err)
	}
	if err := Decrypt(ctx, k, bytes.NewReader(file), &out); !errors.Is(err, context.Canceled) {
		t.Errorf("Decrypt: %v", err)
	}
}

// cancelAtEOF reads r, and cancels a context when r ends: an interrupt that stops lce stops whatever writes its input
// too, and that looks like the end of the input.
type cancelAtEOF struct {
	r      io.Reader
	cancel context.CancelFunc
}

func (c cancelAtEOF) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	if errors.Is(err, io.EOF) {
		c.cancel()
	}
	return n, err
}

func TestCancelAtEOF(t *testing.T) {
	// Input that ends because of an interrupt isn't the whole message: no tag for a plaintext cut short, and no
	// plaintext from a file cut short.
	k := keyFor(t, lifecipher.Recommended())
	for _, n := range []int{0, 100, chunkSize + 100} {
		pt := randomBytes(6, n)
		ctx, cancel := context.WithCancel(context.Background())
		var out bytes.Buffer
		err := Encrypt(ctx, k, testIV(), cancelAtEOF{bytes.NewReader(pt), cancel}, &out)
		whole := n / chunkSize * chunkSize // the chunks written before the input ended
		if !errors.Is(err, context.Canceled) || out.Len() != HeaderSize+lifecipher.IVSize+whole {
			t.Errorf("Encrypt, %d bytes: %v, and %d bytes written", n, err, out.Len())
		}

		ctx, cancel = context.WithCancel(context.Background())
		out.Reset()
		err = Decrypt(ctx, k, cancelAtEOF{bytes.NewReader(encrypt(t, k, pt)), cancel}, &out)
		if !errors.Is(err, context.Canceled) || out.Len() != whole {
			t.Errorf("Decrypt, %d bytes: %v, and %d bytes written", n, err, out.Len())
		}
	}
}

func FuzzDecrypt(f *testing.F) {
	k := keyFor(f, lifecipher.Recommended())
	file := encrypt(f, k, []byte("attack at dawn"))
	f.Add(file)
	f.Add(file[:HeaderSize])
	f.Add([]byte(Magic))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		got, err := decrypt(k, bytes.NewReader(data))
		if err == nil && !bytes.Equal(data, file) {
			t.Fatalf("a file other than the one encrypted was accepted: %x", data)
		}
		if err == nil && string(got) != "attack at dawn" {
			t.Fatalf("the plaintext came back as %q", got)
		}
	})
}

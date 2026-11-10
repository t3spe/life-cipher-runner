package keyfile

import (
	"bytes"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// demoKey is the burned demo key of SPEC.md Appendix B, as SPEC.md writes it.
const demoKey = "6B3028A8 DB46016A 318DA713 85D82A92 6489431E 9A2B00E1 1CB1E684 4106B26D " +
	"90FC90AC 77361985 884930EB 551A3B52 81186009 E8144094 82842900 D88996D1 " +
	"9514CC13 3A81EC34 47580B9D F304B451 84A2B274 24122838 08F6D934 3A69CBB8 " +
	"6A04296A 5F54D36A 42549769 1420992C 30F90206 7215518A 1CE02869 BA961C3B"

func demoKeyBytes(t testing.TB) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(demoKey, " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// bitString writes a key as 1,024 binary digits, the cells in row order.
func bitString(key []byte) string {
	var s strings.Builder
	for _, b := range key {
		for i := 7; i >= 0; i-- {
			s.WriteByte('0' + b>>i&1)
		}
	}
	return s.String()
}

func TestParseForms(t *testing.T) {
	key := demoKeyBytes(t)
	lowerHex := hex.EncodeToString(key)
	bits := bitString(key)
	for name, data := range map[string]string{
		"raw bytes":                    string(key),
		"row words, as SPEC.md writes": demoKey,
		"row words, one per line":      strings.ReplaceAll(demoKey, " ", "\n") + "\n",
		"row words, Windows lines":     strings.ReplaceAll(demoKey, " ", "\r\n") + "\r\n",
		"hex, lowercase":               lowerHex,
		"hex, tabs and form feeds":     lowerHex[:100] + "\t\f\v" + lowerHex[100:],
		"hex after a byte-order mark":  "\uFEFF" + demoKey + "\n",
		"binary digits":                bits,
		"binary digits, in rows":       strings.Join(splitEvery(bits, 32), "\n") + "\n",
		"binary digits after a BOM":    "\uFEFF" + bits,
	} {
		got, err := Parse([]byte(data))
		if err != nil || !bytes.Equal(got, key) {
			t.Errorf("%s: got %x, %v", name, got, err)
		}
	}
	// The cells of the binary form: cell (0, 1) is the second digit, bit 6 of byte 0 (SPEC.md §2.2).
	got, err := Parse([]byte("01" + strings.Repeat("0", 1022)))
	if err != nil || got[0] != 0x40 || !bytes.Equal(got[1:], make([]byte, 127)) {
		t.Errorf("one live cell at (0, 1): got %x, %v", got, err)
	}
}

func splitEvery(s string, n int) []string {
	var parts []string
	for len(s) > n {
		parts = append(parts, s[:n])
		s = s[n:]
	}
	return append(parts, s)
}

func TestParseRefuses(t *testing.T) {
	key := demoKeyBytes(t)
	lowerHex := hex.EncodeToString(key)
	bits := bitString(key)
	for name, c := range map[string]struct{ data, why string }{
		"empty":                   {"", "found 0 bytes, 0 of them not ASCII whitespace"},
		"only whitespace":         {" \n\t\r\n", "found 5 bytes, 0 of them not ASCII whitespace"},
		"non-ASCII spaces":        {"\u00a0" + lowerHex[2:] + "\u2028", "found 259 bytes, 259 of them"},
		"127 raw bytes":           {string(key[:127]), "expected 128 bytes"},
		"129 raw bytes":           {string(key) + "\x00", "expected 128 bytes"},
		"255 hex digits":          {lowerHex[:255], "found 255 bytes, 255 of them"},
		"257 hex digits":          {lowerHex + "0", "found 257 bytes, 257 of them"},
		"254 hex digits, a NUL":   {lowerHex[:254] + "\x00\x00", "256 bytes besides whitespace, but not all of them hex"},
		"a g among hex digits":    {"g" + lowerHex[1:], "not all of them hex digits"},
		"0x prefixes":             {"0x" + lowerHex[2:], "not all of them hex digits"},
		"a non-ASCII byte in hex": {"\xe9" + lowerHex[1:], "not all of them hex digits"},
		"1,023 binary digits":     {bits[:1023], "found 1023 bytes, 1023 of them"},
		"a 2 among binary digits": {"2" + bits[1:], "not all of them 0 or 1"},
		"a / among binary digits": {"/" + bits[1:], "not all of them 0 or 1"},
		"a BOM in the middle":     {lowerHex[:128] + "\uFEFF" + lowerHex[128:], "259 of them"},
		"two BOMs":                {"\uFEFF\uFEFF" + lowerHex, "259 of them"},
	} {
		got, err := Parse([]byte(c.data))
		if !errors.Is(err, ErrFormat) || !strings.Contains(err.Error(), c.why) || got != nil {
			t.Errorf("%s: got %x, %v; want an error saying %q", name, got, err, c.why)
		}
	}
}

func TestHexDigit(t *testing.T) {
	for c := range 256 {
		want, wantErr := hex.DecodeString(string([]byte{'0', byte(c)}))
		value, ok := hexDigit(byte(c))
		if (ok == 1) != (wantErr == nil) || ok == 1 && value != int(want[0]) {
			t.Errorf("hexDigit(%#02x) = %d, %d", c, value, ok)
		}
		if ok == 0 && value != 0 {
			t.Errorf("hexDigit(%#02x) returns the value %d for a non-digit", c, value)
		}
	}
}

func TestSpace(t *testing.T) {
	for c := range 256 {
		want := 0
		if strings.ContainsRune(" \t\n\v\f\r", rune(c)) {
			want = 1
		}
		if got := space(byte(c)); got != want {
			t.Errorf("space(%#02x) = %d, want %d", c, got, want)
		}
	}
}

func TestRead(t *testing.T) {
	dir := t.TempDir()
	write := func(name, data string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	key := demoKeyBytes(t)
	got, err := Read(write("key.txt", demoKey+"\n"))
	if err != nil || !bytes.Equal(got, key) {
		t.Errorf("a key file: got %x, %v", got, err)
	}
	got, err = Read(write("key.bin", string(key)))
	if err != nil || !bytes.Equal(got, key) {
		t.Errorf("a raw key file: got %x, %v", got, err)
	}

	if _, err := Read(filepath.Join(dir, "missing")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a missing file: %v", err)
	}
	if _, err := Read(dir); err == nil || errors.Is(err, ErrFormat) {
		t.Errorf("a directory: %v", err)
	}
	// The largest file Read accepts, and one byte more.
	padded := demoKey + strings.Repeat(" ", MaxSize-len(demoKey))
	if got, err := Read(write("full.txt", padded)); err != nil || !bytes.Equal(got, key) {
		t.Errorf("a file of MaxSize bytes: got %x, %v", got, err)
	}
	big := write("big.txt", padded+" ")
	if _, err := Read(big); !errors.Is(err, ErrFormat) || err.Error() != big+": not a key: the file is larger than 65536 bytes" {
		t.Errorf("a file over MaxSize: %v", err)
	}
	if _, err := Read(write("empty", "")); !errors.Is(err, ErrFormat) || !strings.Contains(err.Error(), "found 0 bytes") {
		t.Errorf("an empty file: %v", err)
	}
	bad := write("bad.txt", "not a key")
	if _, err := Read(bad); !errors.Is(err, ErrFormat) || !strings.HasPrefix(err.Error(), bad+": ") {
		t.Errorf("a malformed key: %v", err)
	}
}

func FuzzParse(f *testing.F) {
	f.Add([]byte(demoKey))
	f.Add([]byte(strings.Repeat("01", 512)))
	f.Add(make([]byte, 128))
	f.Add([]byte("\uFEFF" + strings.Repeat("f", 256)))
	f.Fuzz(func(t *testing.T, data []byte) {
		key, err := Parse(data)
		if err != nil {
			if key != nil || !errors.Is(err, ErrFormat) {
				t.Fatalf("an error must be ErrFormat with no key: %x, %v", key, err)
			}
			return
		}
		if len(key) != 128 {
			t.Fatalf("a %d-byte key", len(key))
		}
		// Whatever form the key came in, its hex and binary forms give it back.
		for _, form := range []string{hex.EncodeToString(key), bitString(key)} {
			if again, err := Parse([]byte(form)); err != nil || !bytes.Equal(again, key) {
				t.Fatalf("the key %x doesn't survive another form: %v", key, err)
			}
		}
	})
}

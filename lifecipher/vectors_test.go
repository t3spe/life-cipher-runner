package lifecipher

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// The published vector files' SHA-256 digests, from SPEC.md §15.
var publishedDigests = map[string]string{
	"demo-v1.json":        "5d1538e5070c80ba4d0df27602add802561040624772c9aca7c3ea678ce0fcf1",
	"recommended-v1.json": "4bd29e0ada05c9fd3814f2c2619376e313932363523dcf72993648b39055c580",
	"key-check-v1.json":   "1924cc8b6b9e834791d419cc6bda52dc6b532b36d8396895231ce77c801f3430",
}

// demoKeyGrid is the burned demo key of SPEC.md Appendix B, which the vectors use. It must never protect anything.
var demoKeyGrid = grid{
	0x6B3028A8, 0xDB46016A, 0x318DA713, 0x85D82A92, 0x6489431E, 0x9A2B00E1, 0x1CB1E684, 0x4106B26D,
	0x90FC90AC, 0x77361985, 0x884930EB, 0x551A3B52, 0x81186009, 0xE8144094, 0x82842900, 0xD88996D1,
	0x9514CC13, 0x3A81EC34, 0x47580B9D, 0xF304B451, 0x84A2B274, 0x24122838, 0x08F6D934, 0x3A69CBB8,
	0x6A04296A, 0x5F54D36A, 0x42549769, 0x1420992C, 0x30F90206, 0x7215518A, 0x1CE02869, 0xBA961C3B,
}

func demoKeyBytes() []byte {
	b := make([]byte, KeySize)
	demoKeyGrid.putBytes(b)
	return b
}

// Key setup is the slow part of most tests, so each parameter set's setup of the demo key runs once.
var (
	demoSetup        = sync.OnceValues(func() (*Key, error) { return NewKey(Demo(), demoKeyBytes()) })
	recommendedSetup = sync.OnceValues(func() (*Key, error) { return NewKey(Recommended(), demoKeyBytes()) })
)

func setupKey(t testing.TB, p Params) *Key {
	t.Helper()
	setup := map[Params]func() (*Key, error){Demo(): demoSetup, Recommended(): recommendedSetup}[p]
	k, err := setup()
	if err != nil {
		t.Fatalf("key setup: %v", err)
	}
	return k
}

// parseWords reads a grid written as 32 row words in hex (§15).
func parseWords(t testing.TB, s string) grid {
	t.Helper()
	fields := strings.Fields(s)
	if len(fields) != 32 {
		t.Fatalf("a grid has 32 row words, not %d: %q", len(fields), s)
	}
	var g grid
	for r, f := range fields {
		w, err := strconv.ParseUint(f, 16, 32)
		if err != nil {
			t.Fatalf("row word %d: %v", r, err)
		}
		g[r] = uint32(w)
	}
	return g
}

// words writes a grid as 32 row words in hex, as the vector files do.
func words(g grid) string {
	s := make([]string, len(g))
	for r, w := range g {
		s[r] = fmt.Sprintf("%08X", w)
	}
	return strings.Join(s, " ")
}

func unhex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex: %v", err)
	}
	return b
}

// readVectors decodes a vector file into v strictly: it refuses any field v doesn't name, so no field goes unchecked,
// and also a field named twice, a name that matches only when case is ignored, and anything after the JSON value.
func readVectors(t testing.TB, name string, v any) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	if err := decodeVectors(data, v); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
}

func decodeVectors(data []byte, v any) error {
	return json.Unmarshal(data, v, json.RejectUnknownMembers(true))
}

func TestDecodeVectorsIsStrict(t *testing.T) {
	var v struct {
		Key string `json:"key"`
		N   uint32 `json:"n"`
	}
	if err := decodeVectors([]byte(`{"key": "6B30", "n": 7}`), &v); err != nil || v.Key != "6B30" || v.N != 7 {
		t.Fatalf("a good file: %+v, %v", v, err)
	}
	for _, data := range []string{
		`{"key": "6B30", "n": 7, "extra": 1}`, // a field the layout doesn't name
		`{"key": "6B30", "key": "0000"}`,      // a field named twice
		`{"Key": "6B30"}`,                     // a name that matches only when case is ignored
		`{"key": "6B30"} {"key": "0000"}`,     // something after the value
		`{"key": "6B30", "n": -1}`,            // a number out of range
	} {
		if err := decodeVectors([]byte(data), &v); err == nil {
			t.Errorf("accepted %s", data)
		}
	}
}

// tableDigest is the SHA-256 of a table's entries in order, 128 bytes each, as in the key_setup vectors.
func tableDigest(tab []packedGrid) string {
	h := sha256.New()
	b := make([]byte, gridBytes)
	for i := range tab {
		g := tab[i].unpack()
		g.putBytes(b)
		h.Write(b)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func TestVectorFilesAreThePublishedOnes(t *testing.T) {
	for name, want := range publishedDigests {
		data, err := os.ReadFile(filepath.Join("testdata", name))
		if err != nil {
			t.Fatal(err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(data)); got != want {
			t.Errorf("%s: SHA-256 %s, but SPEC.md §15 publishes %s", name, got, want)
		}
	}
}

// parameterSetVectors is the layout of demo-v1.json and recommended-v1.json.
type parameterSetVectors struct {
	Description      string `json:"description"`
	Status           string `json:"status"`
	Spec             string `json:"spec"`
	AlgorithmVersion uint32 `json:"algorithm_version"`
	Parameters       struct {
		T      uint32 `json:"T"`
		S      uint32 `json:"S"`
		K      uint32 `json:"k"`
		R      uint32 `json:"R"`
		RInit  uint32 `json:"R_init"`
		RFinal uint32 `json:"R_final"`
	} `json:"parameters"`
	Conventions string `json:"conventions"`
	Key         string `json:"key"`
	IV          string `json:"iv"`
	Life        []struct {
		Name   string `json:"name"`
		Input  string `json:"input"`
		After1 string `json:"after_1"`
		After4 string `json:"after_4"`
	} `json:"life"`
	Shift []struct {
		Input  string `json:"input"`
		DX     uint32 `json:"dx"`
		DY     uint32 `json:"dy"`
		Output string `json:"output"`
	} `json:"shift"`
	Fold []struct {
		Input  string `json:"input"`
		Output string `json:"output"`
	} `json:"fold"`
	Selectors []struct {
		B  string `json:"B"`
		R  uint64 `json:"r"`
		O  uint32 `json:"o"`
		G  int    `json:"g"`
		J  uint32 `json:"j"`
		DX uint32 `json:"dx"`
		DY uint32 `json:"dy"`
	} `json:"selectors"`
	IVOffset uint32 `json:"iv_offset"`
	MixRound struct {
		A      string `json:"A"`
		B      string `json:"B"`
		R      uint64 `json:"r"`
		O      uint32 `json:"o"`
		G      int    `json:"g"`
		J      uint32 `json:"j"`
		DX     uint32 `json:"dx"`
		DY     uint32 `json:"dy"`
		AAfter string `json:"A_after"`
		BAfter string `json:"B_after"`
	} `json:"mix_round"`
	KeySetup map[string]string `json:"key_setup"`
	AEAD     []aeadVector      `json:"aead"`
}

// aeadVector is one message's known answer: the IV is the file's unless the case names its own.
type aeadVector struct {
	IV         string `json:"iv,omitempty"`
	AD         string `json:"ad"`
	Plaintext  string `json:"plaintext"`
	Ciphertext string `json:"ciphertext"`
	Tag        string `json:"tag"`
}

func TestParameterSetVectors(t *testing.T) {
	for _, c := range []struct {
		file string
		p    Params
	}{
		{"demo-v1.json", Demo()},
		{"recommended-v1.json", Recommended()},
	} {
		t.Run(c.file, func(t *testing.T) {
			var v parameterSetVectors
			readVectors(t, c.file, &v)
			checkParameterSetVectors(t, &v, c.p)
		})
	}
}

func checkParameterSetVectors(t *testing.T, v *parameterSetVectors, p Params) {
	ps := v.Parameters
	if got := (Params{Generations: ps.T, GroupSize: ps.S, Shuffles: ps.K, Rounds: ps.R, Version: v.AlgorithmVersion}); got != p {
		t.Fatalf("the file's parameters are %v, not %v", got, p)
	}
	if ps.RInit != 2*p.Rounds || ps.RFinal != 2*p.Rounds {
		t.Errorf("R_init = %d and R_final = %d, not 2R = %d", ps.RInit, ps.RFinal, 2*p.Rounds)
	}
	for _, s := range []string{v.Description, v.Status, v.Spec, v.Conventions} {
		if s == "" {
			t.Error("a descriptive field is empty")
		}
	}
	key, iv := parseWords(t, v.Key), gridFromBytes(unhex(t, v.IV))
	if key != demoKeyGrid {
		t.Fatal("the vectors' key isn't the demo key of Appendix B")
	}
	gridOf := func(s string) grid {
		switch s {
		case "key":
			return key
		case "iv":
			return iv
		}
		return parseWords(t, s)
	}
	groups := int(p.Generations / p.GroupSize)
	k := setupKey(t, p)

	t.Run("life", func(t *testing.T) {
		for _, c := range v.Life {
			in := gridOf(c.Input)
			g := life(&in)
			if want := parseWords(t, c.After1); g != want {
				t.Errorf("%s, one step:\n got %s\nwant %s", c.Name, words(g), words(want))
			}
			if c.After4 == "" {
				continue
			}
			for range 3 {
				g = life(&g)
			}
			if want := parseWords(t, c.After4); g != want {
				t.Errorf("%s, four steps:\n got %s\nwant %s", c.Name, words(g), words(want))
			}
		}
	})
	t.Run("shift", func(t *testing.T) {
		for _, c := range v.Shift {
			in := gridOf(c.Input)
			p := pack(&in)
			moved := shift(&p, c.DX, c.DY)
			if got, want := moved.unpack(), parseWords(t, c.Output); got != want {
				t.Errorf("shift by (%d, %d):\n got %s\nwant %s", c.DX, c.DY, words(got), words(want))
			}
		}
	})
	t.Run("fold", func(t *testing.T) {
		for _, c := range v.Fold {
			in := gridOf(c.Input)
			if got := fmt.Sprintf("%08X", fold(&in)); got != c.Output {
				t.Errorf("F(%s) = %s, want %s", c.Input, got, c.Output)
			}
		}
	})
	t.Run("selectors", func(t *testing.T) {
		for _, c := range v.Selectors {
			b := gridOf(c.B)
			s := selectorBits(&b, c.R)
			g, j, dx, dy := group(c.R, c.O, groups), s&15, s>>4&31, s>>9
			if g != c.G || j != c.J || dx != c.DX || dy != c.DY {
				t.Errorf("r = %d: (g, j, dx, dy) = (%d, %d, %d, %d), want (%d, %d, %d, %d)",
					c.R, g, j, dx, dy, c.G, c.J, c.DX, c.DY)
			}
		}
	})
	t.Run("iv_offset", func(t *testing.T) {
		if o := fold(&iv) % uint32(groups); o != v.IVOffset {
			t.Errorf("o = %d, want %d", o, v.IVOffset)
		}
	})
	t.Run("mix_round", func(t *testing.T) {
		m := v.MixRound
		st := state{a: parseWords(t, m.A), b: parseWords(t, m.B), r: m.R, o: m.O}
		var init grid // the vector is Init's first round: A = IV ⊕ M and B = K (§7.1)
		for r := range init {
			init[r] = iv[r] ^ k.m[r]
		}
		if st.a != init || st.b != k.k || m.R != 0 || m.O != v.IVOffset {
			t.Error("the state before isn't Init's: A = IV ⊕ M, B = K, r = 0, o = F(IV) mod T/S")
		}
		s := selectorBits(&st.b, st.r)
		if g, j, dx, dy := group(st.r, st.o, groups), s&15, s>>4&31, s>>9; g != m.G || j != m.J || dx != m.DX || dy != m.DY {
			t.Errorf("(g, j, dx, dy) = (%d, %d, %d, %d), want (%d, %d, %d, %d)", g, j, dx, dy, m.G, m.J, m.DX, m.DY)
		}
		st.round(k.w)
		if want := parseWords(t, m.AAfter); st.a != want {
			t.Errorf("A after:\n got %s\nwant %s", words(st.a), words(want))
		}
		if want := parseWords(t, m.BAfter); st.b != want {
			t.Errorf("B after:\n got %s\nwant %s", words(st.b), words(want))
		}
	})
	t.Run("key_setup", func(t *testing.T) {
		G := keyTable(&key, int(p.Generations))
		H := setupTable(G, int(p.Shuffles))
		got := map[string]string{
			"H[0]":           words(H[0].unpack()),
			"H[1]":           words(H[1].unpack()),
			"H_sha256":       tableDigest(H),
			"setup_constant": words(setupConstant(p)),
			"M":              words(k.m),
			"W[0]":           words(k.w[0].unpack()),
			"W[1]":           words(k.w[1].unpack()),
			"W[5999]":        words(k.w[5999].unpack()),
			"W_sha256":       tableDigest(k.w),
		}
		for _, name := range slices.Sorted(maps.Keys(v.KeySetup)) {
			if _, ok := got[name]; !ok {
				t.Errorf("the file has %s, which this test doesn't check", name)
			}
		}
		for name, value := range got {
			if want, ok := v.KeySetup[name]; !ok {
				t.Errorf("the file has no %s", name)
			} else if value != want {
				t.Errorf("%s:\n got %s\nwant %s", name, value, want)
			}
		}
	})
	t.Run("aead", func(t *testing.T) {
		for _, c := range v.AEAD {
			checkAEADVector(t, k, unhex(t, v.IV), c)
		}
	})
}

// checkAEADVector checks one message's known answer through Seal and Open, and through the incremental API with
// the message cut into pieces of every few sizes.
func checkAEADVector(t *testing.T, k *Key, iv []byte, c aeadVector) {
	t.Helper()
	if c.IV != "" {
		iv = unhex(t, c.IV)
	}
	ad, pt, ct, tag := unhex(t, c.AD), unhex(t, c.Plaintext), unhex(t, c.Ciphertext), unhex(t, c.Tag)
	name := fmt.Sprintf("%d-byte message, %d bytes of AD", len(pt), len(ad))
	sealed := k.Seal(nil, iv, pt, ad)
	if want := append(slices.Clone(ct), tag...); !bytes.Equal(sealed, want) {
		t.Errorf("%s: Seal gives\n%x\nwant\n%x", name, sealed, want)
	}
	opened, err := k.Open(nil, iv, sealed, ad)
	if err != nil || !bytes.Equal(opened, pt) {
		t.Errorf("%s: Open gives %x, %v", name, opened, err)
	}
	for _, blocks := range []int{1, 2, 3} {
		gotCT, gotTag := encryptInPieces(k, iv, ad, pt, blocks*BlockSize)
		if !bytes.Equal(gotCT, ct) || !bytes.Equal(gotTag, tag) {
			t.Errorf("%s: the Encryptor, %d blocks at a time, disagrees", name, blocks)
		}
		gotPT, err := decryptInPieces(k, iv, ad, ct, tag, blocks*BlockSize)
		if err != nil || !bytes.Equal(gotPT, pt) {
			t.Errorf("%s: the Decryptor, %d blocks at a time, gives %v", name, blocks, err)
		}
	}
}

// encryptInPieces encrypts with an Encryptor, passing the whole blocks in pieces of at most piece bytes.
func encryptInPieces(k *Key, iv, ad, pt []byte, piece int) (ct, tag []byte) {
	e := k.NewEncryptor(iv, ad)
	ct = make([]byte, len(pt))
	whole := len(pt) / BlockSize * BlockSize
	for off := 0; off < whole; off += piece {
		end := min(off+piece, whole)
		e.EncryptBlocks(ct[off:end], pt[off:end])
	}
	t := e.Finish(ct[whole:], pt[whole:])
	return ct, t[:]
}

// decryptInPieces decrypts with a Decryptor, passing the whole blocks in pieces of at most piece bytes.
func decryptInPieces(k *Key, iv, ad, ct, tag []byte, piece int) ([]byte, error) {
	d := k.NewDecryptor(iv, ad)
	pt := make([]byte, len(ct))
	whole := len(ct) / BlockSize * BlockSize
	for off := 0; off < whole; off += piece {
		end := min(off+piece, whole)
		d.DecryptBlocks(pt[off:end], ct[off:end])
	}
	if err := d.Finish(pt[whole:], ct[whole:], tag); err != nil {
		return nil, err
	}
	return pt, nil
}

// extraVectors is the layout of extra-v1.json, which testdata/make_extra_vectors.py wrote with the reference
// implementation: messages the published vectors don't cover, each with its own IV.
type extraVectors struct {
	Description  string `json:"description"`
	Source       string `json:"source"`
	SourceSHA256 string `json:"source_sha256"`
	Key          string `json:"key"`
	Data         string `json:"data"`
	Sets         []struct {
		Parameters struct {
			T       uint32 `json:"T"`
			S       uint32 `json:"S"`
			K       uint32 `json:"k"`
			R       uint32 `json:"R"`
			Version uint32 `json:"version"`
		} `json:"parameters"`
		AEAD []aeadVector `json:"aead"`
	} `json:"sets"`
}

func TestExtraVectors(t *testing.T) {
	var v extraVectors
	readVectors(t, "extra-v1.json", &v)
	if v.Description == "" || v.Source == "" || len(v.SourceSHA256) != 64 || v.Key == "" || v.Data == "" {
		t.Error("a descriptive field is empty")
	}
	var sets []Params
	for _, set := range v.Sets {
		ps := set.Parameters
		p := Params{Generations: ps.T, GroupSize: ps.S, Shuffles: ps.K, Rounds: ps.R, Version: ps.Version}
		sets = append(sets, p)
		k := setupKey(t, p)
		for _, c := range set.AEAD {
			if c.IV == "" {
				t.Fatal("each extra case names its IV")
			}
			checkAEADVector(t, k, nil, c)
		}
	}
	if !slices.Equal(sets, []Params{Demo(), Recommended()}) {
		t.Errorf("the file covers %v, not the demo and recommended sets", sets)
	}
}

// keyCheckVectors is the layout of key-check-v1.json.
type keyCheckVectors struct {
	Description      string `json:"description"`
	Status           string `json:"status"`
	Spec             string `json:"spec"`
	AlgorithmVersion uint32 `json:"algorithm_version"`
	Conventions      string `json:"conventions"`
	Cases            []struct {
		Name   string `json:"name"`
		Key    string `json:"key"`
		D      int    `json:"D"`
		Checks []struct {
			T      int  `json:"T"`
			Passes bool `json:"passes"`
		} `json:"checks"`
	} `json:"cases"`
}

// distinctGenerations returns D(K), the number of distinct generations before the first repeat (§9.1).
func distinctGenerations(k grid) int {
	seen := map[grid]bool{}
	for !seen[k] {
		seen[k] = true
		k = life(&k)
	}
	return len(seen)
}

func TestKeyCheckVectors(t *testing.T) {
	var v keyCheckVectors
	readVectors(t, "key-check-v1.json", &v)
	if v.Description == "" || v.Status == "" || v.Spec == "" || v.Conventions == "" || v.AlgorithmVersion != 1 {
		t.Error("a descriptive field is empty, or the algorithm version isn't 1")
	}
	for _, c := range v.Cases {
		key := parseWords(t, c.Key)
		if d := distinctGenerations(key); d != c.D {
			t.Errorf("%s: D = %d, want %d", c.Name, d, c.D)
		}
		for _, check := range c.Checks {
			if got := keyCheck(keyTable(&key, check.T)); got != check.Passes {
				t.Errorf("%s at T = %d: the check gives %v, want %v", c.Name, check.T, got, check.Passes)
			}
			if check.T != int(Demo().Generations) {
				continue
			}
			// Key setup at T = 6,000 must refuse exactly the keys that fail the check.
			b := make([]byte, KeySize)
			key.putBytes(b)
			_, err := NewKey(Demo(), b)
			if check.Passes != (err == nil) {
				t.Errorf("%s: NewKey gives %v", c.Name, err)
			}
		}
	}
}

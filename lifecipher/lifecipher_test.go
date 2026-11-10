package lifecipher

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"math/big"
	"math/bits"
	"math/rand/v2"
	"slices"
	"strings"
	"testing"
)

func newRand(seed uint64) *rand.Rand { return rand.New(rand.NewPCG(seed, 0x9E3779B97F4A7C15)) }

func randomGrid(rng *rand.Rand) grid {
	var g grid
	for r := range g {
		g[r] = rng.Uint32()
	}
	return g
}

// sparseGrid returns a random grid about 1/8 live, closer to real generations (about 9% live) than a dense one.
func sparseGrid(rng *rand.Rand) grid {
	var g grid
	for r := range g {
		g[r] = rng.Uint32() & rng.Uint32() & rng.Uint32()
	}
	return g
}

func randomBytes(rng *rand.Rand, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(rng.Uint32())
	}
	return b
}

// cell returns cell (r, c) of g, with the indices taken mod 32 (§2.1).
func cell(g *grid, r, c int) uint32 {
	return g[r&31] >> (31 - c&31) & 1
}

// gridWith returns a grid whose live cells are the given (row, column) pairs.
func gridWith(cells ...[2]int) grid {
	var g grid
	for _, rc := range cells {
		g[rc[0]&31] |= 1 << (31 - rc[1]&31)
	}
	return g
}

// lifeByRule is §5.1 evaluated cell by cell, exactly as the spec words it.
func lifeByRule(g *grid) grid {
	var next grid
	for r := range 32 {
		for c := range 32 {
			var n uint32
			for a := -1; a <= 1; a++ {
				for b := -1; b <= 1; b++ {
					if a != 0 || b != 0 {
						n += cell(g, r+a, c+b)
					}
				}
			}
			if n == 3 || n == 2 && cell(g, r, c) == 1 {
				next[r] |= 1 << (31 - c)
			}
		}
	}
	return next
}

func mustPanic(t *testing.T, name string, f func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Errorf("%s didn't panic", name)
		}
	}()
	f()
}

func TestByteLayout(t *testing.T) {
	rng := newRand(1)
	b := randomBytes(rng, gridBytes)
	g := gridFromBytes(b)
	for r := range 32 {
		for c := range 32 {
			// §2.2: cell (r, c) is bit 7 − (c mod 8) of byte 4r + ⌊c / 8⌋.
			if want := uint32(b[4*r+c/8]>>(7-c%8)) & 1; cell(&g, r, c) != want {
				t.Fatalf("cell (%d, %d) is %d, want %d", r, c, cell(&g, r, c), want)
			}
		}
	}
	out := make([]byte, gridBytes)
	g.putBytes(out)
	if !bytes.Equal(out, b) {
		t.Fatal("putBytes doesn't give back the bytes gridFromBytes read")
	}
	for i := range gridBytes {
		if g.byteAt(i) != b[i] {
			t.Fatalf("byteAt(%d) = %#x, want %#x", i, g.byteAt(i), b[i])
		}
		h := g
		h.xorByte(i, 0x5A)
		h.putBytes(out)
		want := slices.Clone(b)
		want[i] ^= 0x5A
		if !bytes.Equal(out, want) {
			t.Fatalf("xorByte(%d) doesn't XOR exactly byte %d", i, i)
		}
		h = g
		h.setByte(i, 0xA5)
		h.putBytes(out)
		want[i] = 0xA5
		if !bytes.Equal(out, want) {
			t.Fatalf("setByte(%d) doesn't set exactly byte %d", i, i)
		}
	}
}

func TestPack(t *testing.T) {
	rng := newRand(2)
	for range 100 {
		g := randomGrid(rng)
		p := pack(&g)
		for i, w := range p {
			if w != uint64(g[2*i])<<32|uint64(g[2*i+1]) {
				t.Fatalf("word %d of the packed grid holds the wrong rows", i)
			}
		}
		if p.unpack() != g {
			t.Fatal("unpack doesn't undo pack")
		}
	}
}

func TestLifeMatchesTheRule(t *testing.T) {
	rng := newRand(3)
	for i := range 300 {
		g := randomGrid(rng)
		if i%2 == 1 {
			g = sparseGrid(rng)
		}
		if got, want := life(&g), lifeByRule(&g); got != want {
			t.Fatalf("grid %s:\n got %s\nwant %s", words(g), words(got), words(want))
		}
	}
}

func TestLifePatterns(t *testing.T) {
	block := gridWith([2]int{5, 5}, [2]int{5, 6}, [2]int{6, 5}, [2]int{6, 6})
	if life(&block) != block {
		t.Error("a block isn't still")
	}
	blinker := gridWith([2]int{10, 10}, [2]int{10, 11}, [2]int{10, 12})
	vertical := gridWith([2]int{9, 11}, [2]int{10, 11}, [2]int{11, 11})
	if next := life(&blinker); next != vertical || life(&next) != blinker {
		t.Error("a blinker doesn't oscillate with period 2")
	}
	// A glider moves one row down and one column right every 4 steps, across the torus's edges too.
	for _, at := range [][2]int{{0, 0}, {30, 31}, {31, 30}} {
		glider := func(dr, dc int) grid {
			r, c := at[0]+dr, at[1]+dc
			return gridWith([2]int{r, c + 1}, [2]int{r + 1, c + 2}, [2]int{r + 2, c}, [2]int{r + 2, c + 1}, [2]int{r + 2, c + 2})
		}
		g := glider(0, 0)
		for range 4 {
			g = life(&g)
		}
		if g != glider(1, 1) {
			t.Errorf("the glider at %v didn't move by (1, 1) in 4 steps", at)
		}
	}
	empty := grid{}
	if life(&empty) != empty {
		t.Error("an empty grid comes to life")
	}
}

func TestShiftDefinition(t *testing.T) {
	rng := newRand(4)
	x := randomGrid(rng)
	p := pack(&x)
	for dx := range uint32(32) {
		for dy := range uint32(32) {
			moved := shift(&p, dx, dy)
			y := moved.unpack()
			for r := range 32 {
				for c := range 32 {
					// §5.2: Y(r, c) = X(r − dy, c − dx).
					if cell(&y, r, c) != cell(&x, r-int(dy), c-int(dx)) {
						t.Fatalf("shift by (%d, %d): cell (%d, %d) is wrong", dx, dy, r, c)
					}
				}
			}
		}
	}
}

func TestFoldProperties(t *testing.T) {
	rng := newRand(5)
	for range 200 {
		x, y := randomGrid(rng), randomGrid(rng)
		xy := x
		xy.xor(&y)
		if fold(&xy) != fold(&x)^fold(&y) {
			t.Fatal("F isn't linear")
		}
		// §5.3: F(shift(X, dx, dy)) = rotl(F(X), dy − dx).
		dx, dy := rng.Uint32N(32), rng.Uint32N(32)
		p := pack(&x)
		moved := shift(&p, dx, dy)
		s := moved.unpack()
		if fold(&s) != bits.RotateLeft32(fold(&x), int(dy)-int(dx)) {
			t.Fatalf("shifting by (%d, %d) doesn't rotate the fold by dy − dx", dx, dy)
		}
	}
}

func TestSelectorsSeeEveryCell(t *testing.T) {
	// §5.4.2, rule v5: a change to any one of B's 1,024 cells moves the secret selectors, short of a collision in
	// their 14 bits, about 2^-14 per change. So does a change to two cells on one wrapped diagonal, (r, c) and
	// (r + d, c + d), whose bits cancel in the fold.
	rng := newRand(6)
	b, r := randomGrid(rng), rng.Uint64N(1<<20)
	base := selectorBits(&b, r)
	moved, total := 0, 0
	for row := range 32 {
		for col := range 32 {
			one := b
			one[row] ^= 1 << (31 - col)
			d := 1 + rng.IntN(31)
			two := one
			two[(row+d)&31] ^= 1 << (31 - (col+d)&31)
			if fold(&two) != fold(&b) {
				t.Fatal("two cells on a wrapped diagonal should cancel in the fold")
			}
			for _, other := range []grid{one, two} {
				total++
				if selectorBits(&other, r) != base {
					moved++
				}
			}
		}
	}
	// The expected number of collisions in 2,048 changes is 0.125, so more than 2 would mean a broken chain.
	if total != 2048 || moved < total-2 {
		t.Errorf("only %d of %d single-cell or diagonal changes moved the selectors", moved, total)
	}
}

func TestGroup(t *testing.T) {
	for _, c := range []struct {
		r      uint64
		o      uint32
		groups int
		want   int
	}{
		{0, 0, 375, 0}, {1, 0, 375, 1}, {374, 0, 375, 374}, {375, 0, 375, 0}, {10, 370, 375, 5},
		{math.MaxUint64 - 374, 374, 375, int((math.MaxUint64 % 375) % 375)},
	} {
		if got := group(c.r, c.o, c.groups); got != c.want {
			t.Errorf("group(r = %d, o = %d) = %d, want %d", c.r, c.o, got, c.want)
		}
	}
}

func TestEqMask(t *testing.T) {
	for _, c := range []struct{ a, b, want uint32 }{
		{0, 0, math.MaxUint32}, {1, 0, 0}, {0, 1, 0}, {15, 15, math.MaxUint32}, {1 << 31, 0, 0},
		{math.MaxUint32, math.MaxUint32, math.MaxUint32}, {math.MaxUint32, 0, 0},
	} {
		if got := eqMask(c.a, c.b); got != c.want {
			t.Errorf("eqMask(%#x, %#x) = %#x, want %#x", c.a, c.b, got, c.want)
		}
	}
}

func TestReadEntry(t *testing.T) {
	rng := newRand(7)
	var group [16]packedGrid
	for i := range group {
		g := randomGrid(rng)
		group[i] = pack(&g)
	}
	for j := range uint32(16) {
		if readEntry(&group, j) != group[j] {
			t.Errorf("readEntry(%d) isn't entry %d", j, j)
		}
	}
}

func TestMixRoundRunsBackwards(t *testing.T) {
	// §5.6: B = A′, the selectors can be recomputed from it, and then A = B′ ⊕ Life(A′) ⊕ RK. So no two states
	// merge (T5 in the life-cipher repository's HARNESS.md).
	rng := newRand(8)
	table := make([]packedGrid, 6000)
	for i := range table {
		g := randomGrid(rng)
		table[i] = pack(&g)
	}
	groups := len(table) / 16
	for range 50 {
		st := state{a: randomGrid(rng), b: randomGrid(rng), r: rng.Uint64N(1 << 40), o: rng.Uint32N(uint32(groups))}
		after := st
		after.round(table)
		if after.a != st.b || after.r != st.r+1 || after.o != st.o {
			t.Fatal("a round must move B into A and count the round")
		}
		b := after.a
		s := selectorBits(&b, st.r)
		rk := shift(&table[16*group(st.r, st.o, groups)+int(s&15)], s>>4&31, s>>9)
		a := life(&after.a)
		a.xor(&after.b)
		ru := rk.unpack()
		a.xor(&ru)
		if a != st.a {
			t.Fatal("running a round backwards doesn't give back A")
		}
	}
}

// piBits returns the first n bits of π's fractional part, from Machin's formula π = 16 arctan(1/5) − 4 arctan(1/239)
// in fixed point, with 64 guard bits.
func piBits(n uint) *big.Int {
	one := new(big.Int).Lsh(big.NewInt(1), n+64)
	arctanInv := func(x int64) *big.Int { // arctan(1/x) = 1/x − 1/(3x³) + 1/(5x⁵) − …
		sum, term := new(big.Int), new(big.Int).Div(one, big.NewInt(x))
		x2 := big.NewInt(x * x)
		for k := int64(0); term.Sign() != 0; k++ {
			t := new(big.Int).Div(term, big.NewInt(2*k+1))
			if k%2 == 0 {
				sum.Add(sum, t)
			} else {
				sum.Sub(sum, t)
			}
			term.Div(term, x2)
		}
		return sum
	}
	pi := new(big.Int).Sub(new(big.Int).Mul(big.NewInt(16), arctanInv(5)), new(big.Int).Mul(big.NewInt(4), arctanInv(239)))
	pi.Sub(pi, new(big.Int).Mul(big.NewInt(3), one)) // the fractional part
	return pi.Rsh(pi, 64)
}

func TestSetupConstantIsPi(t *testing.T) {
	// Appendix A: SETUP₀ is π's fractional part from its first bit, cell (r, c) being bit 32r + c + 1.
	frac := piBits(1024)
	var want grid
	for r := range want {
		want[r] = uint32(new(big.Int).Rsh(frac, uint(1024-32*(r+1))).Uint64())
	}
	if setup0 != want {
		t.Fatalf("SETUP₀ isn't π:\n got %s\nwant %s", words(setup0), words(want))
	}
	live := 0
	for _, w := range setup0 {
		live += bits.OnesCount32(w)
	}
	if live != 501 {
		t.Errorf("SETUP₀ has %d live cells, not 501", live)
	}
	// Appendix A also gives the demo set's first five row words.
	demo := setupConstant(Demo())
	if got := words(demo)[:44]; got != "243F7DF8 85A308D7 13198A3E 03707354 A4093823" {
		t.Errorf("the demo set's setup constant starts %s", got)
	}
}

func TestSetupTableRepeats(t *testing.T) {
	// §11.5: H[i] depends only on i mod T/k.
	rng := newRand(9)
	g := make([]grid, 240)
	for i := range g {
		g[i] = sparseGrid(rng)
	}
	k := 6
	h := setupTable(g, k)
	for i := range h {
		if h[i] != h[(i+len(g)/k)%len(g)] {
			t.Fatalf("H[%d] differs from H[%d]", i, i+len(g)/k)
		}
	}
}

func TestSortOrder(t *testing.T) {
	for _, c := range []struct {
		a, b sortKey
		want uint64
	}{
		{sortKey{1, 0}, sortKey{2, 1}, 0},
		{sortKey{2, 0}, sortKey{1, 1}, 1},
		{sortKey{5, 3}, sortKey{5, 2}, 1}, // a tie goes to the smaller generation number
		{sortKey{5, 2}, sortKey{5, 3}, 0},
		{sortKey{5, 2}, sortKey{5, 2}, 0},
		{sortKey{math.MaxUint64, 0}, sortKey{0, 1}, 1},
		{sortKey{0, math.MaxUint64}, sortKey{math.MaxUint64, 0}, 0},
	} {
		if got := after(&c.a, &c.b); got != c.want {
			t.Errorf("after(%v, %v) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestBitonicSort(t *testing.T) {
	rng := newRand(10)
	for _, n := range []int{0, 1, 2, 3, 5, 7, 16, 17, 100, 1000, 6000} {
		for _, spread := range []uint64{4, math.MaxUint64} { // few distinct tags force ties
			keys, gens := make([]sortKey, n), make([]packedGrid, n)
			for i, idx := range rng.Perm(n) {
				keys[i] = sortKey{tag: rng.Uint64() % spread, idx: uint64(idx)}
				gens[i][0] = uint64(idx) // each record's payload names it
			}
			want := slices.Clone(keys)
			slices.SortFunc(want, func(a, b sortKey) int {
				if a.tag != b.tag {
					return compare(a.tag, b.tag)
				}
				return compare(a.idx, b.idx)
			})
			bitonicSort(keys, gens, 0, n, true)
			if !slices.Equal(keys, want) {
				t.Fatalf("n = %d: the network's order differs from a plain sort's", n)
			}
			for i := range keys {
				if gens[i][0] != keys[i].idx {
					t.Fatalf("n = %d: record %d's generation didn't travel with its key", n, i)
				}
			}
		}
	}

	// A part of the records, in descending order: the rest stay as they are.
	keys, gens := make([]sortKey, 40), make([]packedGrid, 40)
	for i := range keys {
		keys[i] = sortKey{tag: uint64(i % 7), idx: uint64(i)}
	}
	before := slices.Clone(keys)
	bitonicSort(keys, gens, 10, 25, false)
	for i := 11; i < 35; i++ {
		if after(&keys[i-1], &keys[i]) == 0 && keys[i-1] != keys[i] {
			t.Fatalf("records %d and %d aren't in descending order", i-1, i)
		}
	}
	if !slices.Equal(keys[:10], before[:10]) || !slices.Equal(keys[35:], before[35:]) {
		t.Fatal("the sort touched records outside its range")
	}
}

func compare(a, b uint64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

func TestShuffleInto(t *testing.T) {
	// §6.5 and §6.6, with ties, which the published vectors don't exercise: shuffle s orders the generations by
	// (tag s·T + i, i), and W[s·T/k + q] XORs the k generations at sorted positions k·q … k·q + k − 1.
	rng := newRand(11)
	const T, k = 48, 4
	G := make([]grid, T)
	for i := range G {
		G[i] = randomGrid(rng)
	}
	tags := make([]uint64, k*T)
	for i := range tags {
		tags[i] = rng.Uint64N(6)
	}
	w := make([]packedGrid, T)
	keys, gens := make([]sortKey, T), make([]packedGrid, T)
	for s := range k {
		shuffleInto(w, G, tags, s, k, keys, gens)
		order := make([]int, T)
		for i := range order {
			order[i] = i
		}
		slices.SortStableFunc(order, func(a, b int) int { return compare(tags[s*T+a], tags[s*T+b]) })
		for q := range T / k {
			var want grid
			for m := range k {
				want.xor(&G[order[k*q+m]])
			}
			if w[s*(T/k)+q].unpack() != want {
				t.Fatalf("shuffle %d, entry %d isn't the XOR of its sorted generations", s, q)
			}
		}
	}
}

func TestParamsValidate(t *testing.T) {
	for _, p := range []Params{
		Recommended(), Demo(),
		{Generations: 65520, GroupSize: 16, Shuffles: 16, Rounds: 1024, Version: 1}, // T and R at their limits
		{Generations: 32768, GroupSize: 16, Shuffles: 32, Rounds: 16, Version: 1},   // k·T = 2^20, R at its least
		{Generations: 16, GroupSize: 16, Shuffles: 16, Rounds: 16, Version: 1},
	} {
		if err := p.Validate(); err != nil {
			t.Errorf("%v: %v", p, err)
		}
	}
	for _, c := range []struct {
		change func(*Params)
		why    string
	}{
		{func(p *Params) { p.GroupSize = 15 }, "S must be 16"},
		{func(p *Params) { p.GroupSize = 32 }, "S must be 16"},
		{func(p *Params) { p.Generations = 0 }, "T must be"},
		{func(p *Params) { p.Generations = 6008 + 1 }, "T must be"},
		{func(p *Params) { p.Generations = 65536 }, "T must be"},
		{func(p *Params) { p.Shuffles = 0 }, "k must divide T"},
		{func(p *Params) { p.Shuffles = 7 }, "k must divide T"},
		{func(p *Params) { p.Generations, p.Shuffles = 65520, 21 }, "k·T must be at most 1,048,576"},
		{func(p *Params) { p.Generations, p.Shuffles = 32768, 64 }, "k·T must be at most 1,048,576"},
		{func(p *Params) { p.Generations, p.Shuffles = 65520, 65520 }, "k·T must be at most"},
		{func(p *Params) { p.Rounds = 15 }, "R must be at least 16, and at most 1,024"},
		{func(p *Params) { p.Rounds = 1025 }, "R must be at least 16, and at most 1,024"},
		{func(p *Params) { p.Rounds = math.MaxUint32 }, "R must be"},
		{func(p *Params) { p.Version = 0 }, "the version must be 1"},
		{func(p *Params) { p.Version = 2 }, "the version must be 1"},
	} {
		p := Recommended()
		c.change(&p)
		err := p.Validate()
		if !errors.Is(err, ErrInvalidParams) || !strings.Contains(err.Error(), c.why) {
			t.Errorf("%v: got %v, want %q", p, err, c.why)
		}
	}
	if got := Recommended().String(); got != "T = 6000, S = 16, k = 30, R = 24, version 1" {
		t.Errorf("String() = %q", got)
	}
	// The parameter sets are values: changing a copy changes nothing else.
	p := Recommended()
	p.Rounds = 1
	if Recommended().Rounds != 24 || Demo().Shuffles != 4 {
		t.Error("a parameter set changed")
	}
}

func TestNewKeyRefuses(t *testing.T) {
	key := demoKeyBytes()
	if _, err := NewKey(Params{}, key); !errors.Is(err, ErrInvalidParams) {
		t.Errorf("zero parameters: %v", err)
	}
	for _, n := range []int{0, 127, 129} {
		if _, err := NewKey(Demo(), make([]byte, n)); !errors.Is(err, ErrKeySize) {
			t.Errorf("a %d-byte key: %v", n, err)
		}
	}
	_, err := NewKey(Demo(), make([]byte, KeySize)) // the empty grid, D = 1
	if !errors.Is(err, ErrKeyCheck) || !strings.Contains(err.Error(), "6000 generations") {
		t.Errorf("the empty grid: %v", err)
	}
}

func TestKeyMethods(t *testing.T) {
	k := setupKey(t, Demo())
	if k.NonceSize() != 128 || k.Overhead() != 16 || k.Params() != Demo() {
		t.Errorf("NonceSize %d, Overhead %d, Params %v", k.NonceSize(), k.Overhead(), k.Params())
	}
}

func TestRoundTrip(t *testing.T) {
	k := setupKey(t, Demo())
	rng := newRand(12)
	for _, n := range []int{0, 1, 127, 128, 129, 255, 256, 257, 300, 1000} {
		for _, adLen := range []int{0, 1, 127, 128, 129, 256, 300} {
			iv, ad, pt := randomBytes(rng, IVSize), randomBytes(rng, adLen), randomBytes(rng, n)
			ct := k.Seal(nil, iv, pt, ad)
			if len(ct) != n+TagSize {
				t.Fatalf("Seal gave %d bytes for %d", len(ct), n)
			}
			got, err := k.Open(nil, iv, ct, ad)
			if err != nil || !bytes.Equal(got, pt) {
				t.Fatalf("n = %d, AD %d: Open gives %v", n, adLen, err)
			}
			// Appending to a prefix, and in place.
			prefixed := k.Seal([]byte("prefix"), iv, pt, ad)
			if !bytes.Equal(prefixed, append([]byte("prefix"), ct...)) {
				t.Fatal("Seal doesn't append to dst")
			}
			buf := make([]byte, n, n+TagSize)
			copy(buf, pt)
			inPlace := k.Seal(buf[:0], iv, buf, ad)
			if !bytes.Equal(inPlace, ct) || &inPlace[0] != &buf[:1][0] {
				t.Fatal("Seal in place differs, or didn't reuse the buffer")
			}
			opened, err := k.Open(inPlace[:0], iv, inPlace, ad)
			if err != nil || !bytes.Equal(opened, pt) {
				t.Fatalf("Open in place: %v", err)
			}
		}
	}
}

func TestOpenRejectsAnyChange(t *testing.T) {
	// §8: a change to the IV, the AD, the ciphertext or the tag makes decryption fail, and releases nothing.
	k := setupKey(t, Demo())
	rng := newRand(13)
	iv, ad, pt := randomBytes(rng, IVSize), []byte("to: bob, msg 7"), randomBytes(rng, 200)
	ct := k.Seal(nil, iv, pt, ad)
	flip := func(b []byte, i int) []byte {
		c := slices.Clone(b)
		c[i] ^= 1
		return c
	}
	for name, c := range map[string][3][]byte{
		"IV, first byte":      {flip(iv, 0), ad, ct},
		"IV, last byte":       {flip(iv, 127), ad, ct},
		"AD":                  {iv, flip(ad, 0), ct},
		"AD, a byte cut":      {iv, ad[:len(ad)-1], ct},
		"AD, a zero added":    {iv, append(slices.Clone(ad), 0), ct},
		"no AD":               {iv, nil, ct},
		"ciphertext, block 1": {iv, ad, flip(ct, 5)},
		"ciphertext, the end": {iv, ad, flip(ct, 150)},
		"tag, first byte":     {iv, ad, flip(ct, 200)},
		"tag, last byte":      {iv, ad, flip(ct, 215)},
		"a byte cut":          {iv, ad, slices.Delete(slices.Clone(ct), 199, 200)},
		"too short":           {iv, ad, ct[:TagSize-1]},
	} {
		dst := make([]byte, 0, 512)
		got, err := k.Open(dst, c[0], c[2], c[1])
		if !errors.Is(err, ErrOpen) || got != nil {
			t.Errorf("%s: Open gives %x, %v", name, got, err)
		}
		if !bytes.Equal(dst[:cap(dst)], make([]byte, cap(dst))) {
			t.Errorf("%s: the failed Open left plaintext in dst", name)
		}
	}
	d := k.NewDecryptor(iv, ad)
	if err := d.Finish(nil, nil, make([]byte, TagSize-1)); !errors.Is(err, ErrOpen) {
		t.Errorf("a 15-byte tag: %v", err)
	}
}

func TestEndMarker(t *testing.T) {
	// §7.4: a trailing zero byte changes the tag, so it can't be cut or added unnoticed. The same holds for the AD.
	k := setupKey(t, Demo())
	iv := make([]byte, IVSize)
	a := k.Seal(nil, iv, []byte("attack at dawn"), nil)
	b := k.Seal(nil, iv, []byte("attack at dawn\x00"), nil)
	if bytes.Equal(a[len(a)-TagSize:], b[len(b)-TagSize:]) {
		t.Error("a trailing zero byte of plaintext doesn't change the tag")
	}
	c := k.Seal(nil, iv, nil, []byte("x"))
	d := k.Seal(nil, iv, nil, []byte("x\x00"))
	if bytes.Equal(c, d) {
		t.Error("a trailing zero byte of AD doesn't change the tag")
	}
}

func TestSeparator(t *testing.T) {
	// §7.3: without the separator, AD = X with the message 80 00 … 00 would absorb the same blocks as AD = X followed
	// by that block with an empty message.
	k := setupKey(t, Demo())
	iv := make([]byte, IVSize)
	x, y := make([]byte, 128), append([]byte{0x80}, make([]byte, 127)...)
	for i := range x {
		x[i] = byte(i)
	}
	a := k.Seal(nil, iv, y, x)
	b := k.Seal(nil, iv, nil, append(slices.Clone(x), y...))
	if bytes.Equal(a[len(a)-TagSize:], b) {
		t.Error("the crafted pair gets the same tag")
	}
}

func TestIncrementalMatchesSeal(t *testing.T) {
	k := setupKey(t, Demo())
	rng := newRand(14)
	for range 20 {
		n := rng.IntN(2000)
		iv, ad, pt := randomBytes(rng, IVSize), randomBytes(rng, rng.IntN(300)), randomBytes(rng, n)
		sealed := k.Seal(nil, iv, pt, ad)
		piece := BlockSize * (1 + rng.IntN(4))
		ct, tag := encryptInPieces(k, iv, ad, pt, piece)
		if !bytes.Equal(append(ct, tag...), sealed) {
			t.Fatalf("the Encryptor, %d bytes at a time, differs from Seal", piece)
		}
		got, err := decryptInPieces(k, iv, ad, sealed[:n], sealed[n:], piece)
		if err != nil || !bytes.Equal(got, pt) {
			t.Fatalf("the Decryptor, %d bytes at a time: %v", piece, err)
		}
	}
}

func TestMisuse(t *testing.T) {
	k := setupKey(t, Demo())
	iv, block := make([]byte, IVSize), make([]byte, BlockSize)
	finishedE := k.NewEncryptor(iv, nil)
	finishedE.Finish(nil, nil)
	finishedD := k.NewDecryptor(iv, nil)
	_ = finishedD.Finish(nil, nil, nil)
	erasedE, erasedD := k.NewEncryptor(iv, nil), k.NewDecryptor(iv, nil)
	erasedE.Erase()
	erasedD.Erase()
	erased, err := NewKey(Demo(), demoKeyBytes())
	if err != nil {
		t.Fatal(err)
	}
	erased.Erase()
	// Buffers that share memory without starting at the same place.
	buf, sealed := make([]byte, 400), k.Seal(nil, iv, make([]byte, 300), nil)
	copy(buf[50:], sealed)
	two := make([]byte, 2*BlockSize+1)
	for name, f := range map[string]func(){
		"Seal with a short IV":                  func() { k.Seal(nil, iv[:127], nil, nil) },
		"Open with a long IV":                   func() { _, _ = k.Open(nil, append(iv, 0), make([]byte, TagSize), nil) },
		"NewEncryptor with no IV":               func() { k.NewEncryptor(nil, nil) },
		"NewDecryptor with no IV":               func() { k.NewDecryptor(nil, nil) },
		"EncryptBlocks, part of a block":        func() { k.NewEncryptor(iv, nil).EncryptBlocks(block, block[:100]) },
		"EncryptBlocks, a short dst":            func() { k.NewEncryptor(iv, nil).EncryptBlocks(block[:100], block) },
		"EncryptBlocks after Finish":            func() { finishedE.EncryptBlocks(block, block) },
		"EncryptBlocks after Erase":             func() { erasedE.EncryptBlocks(block, block) },
		"Encryptor.Finish, a whole block":       func() { k.NewEncryptor(iv, nil).Finish(block, block) },
		"Encryptor.Finish, a short dst":         func() { k.NewEncryptor(iv, nil).Finish(nil, block[:1]) },
		"Encryptor.Finish twice":                func() { finishedE.Finish(nil, nil) },
		"Encryptor.Finish after Erase":          func() { erasedE.Finish(nil, nil) },
		"DecryptBlocks, part of a block":        func() { k.NewDecryptor(iv, nil).DecryptBlocks(block, block[:100]) },
		"DecryptBlocks, a short dst":            func() { k.NewDecryptor(iv, nil).DecryptBlocks(block[:100], block) },
		"DecryptBlocks after Finish":            func() { finishedD.DecryptBlocks(block, block) },
		"DecryptBlocks after Erase":             func() { erasedD.DecryptBlocks(block, block) },
		"Decryptor.Finish, a whole block":       func() { _ = k.NewDecryptor(iv, nil).Finish(block, block, nil) },
		"Decryptor.Finish, a short dst":         func() { _ = k.NewDecryptor(iv, nil).Finish(nil, block[:1], nil) },
		"Decryptor.Finish twice":                func() { _ = finishedD.Finish(nil, nil, nil) },
		"Decryptor.Finish after Erase":          func() { _ = erasedD.Finish(nil, nil, nil) },
		"Seal with an IV the size of a tag":     func() { k.Seal(nil, iv[:TagSize], nil, nil) },
		"Open with a short IV and a short text": func() { _, _ = k.Open(nil, nil, nil, nil) },
		"NewEncryptor with an erased key":       func() { erased.NewEncryptor(iv, nil) },
		"NewDecryptor with an erased key":       func() { erased.NewDecryptor(iv, nil) },
		"Seal with an erased key":               func() { erased.Seal(nil, iv, nil, nil) },
		"Open with an erased key":               func() { _, _ = erased.Open(nil, iv, sealed, nil) },
		"Seal into a shifted copy":              func() { k.Seal(buf[1:1], iv, buf[:300], nil) },
		"Open into a shifted copy":              func() { _, _ = k.Open(buf[:10], iv, buf[50:50+len(sealed)], nil) },
		"EncryptBlocks into a shifted copy":     func() { k.NewEncryptor(iv, nil).EncryptBlocks(two[1:], two[:2*BlockSize]) },
		"DecryptBlocks into a shifted copy":     func() { k.NewDecryptor(iv, nil).DecryptBlocks(two[1:], two[:2*BlockSize]) },
		"Encryptor.Finish into a shifted copy":  func() { k.NewEncryptor(iv, nil).Finish(two[1:11], two[:10]) },
		"Decryptor.Finish into a shifted copy":  func() { _ = k.NewDecryptor(iv, nil).Finish(two[1:11], two[:10], nil) },
	} {
		mustPanic(t, name, f)
	}
	if erasedE.st != (state{}) || erasedD.st != (state{}) || erased.w != nil || erased.k != (grid{}) || erased.m != (grid{}) {
		t.Error("Erase left state behind")
	}
}

func TestInexactOverlap(t *testing.T) {
	b := make([]byte, 100)
	for _, c := range []struct {
		x, y []byte
		want bool
	}{
		{b[:10], b[10:20], false}, // next to each other
		{b[:10], b[50:60], false},
		{b[:10], b[:10], false}, // the same start: in place
		{b[:10], b[:50], false}, // the same start, different lengths
		{b[:0], b[:10], false},  // empty
		{b[:10], b[9:20], true}, // one byte shared
		{b[5:15], b[:10], true}, // the other way round
		{b[10:20], b[12:14], true},
	} {
		if got := inexactOverlap(c.x, c.y); got != c.want {
			t.Errorf("inexactOverlap(b[%d:], b[%d:]) = %v", cap(b)-cap(c.x), cap(b)-cap(c.y), got)
		}
	}
}

func TestErrorMessages(t *testing.T) {
	for _, err := range []error{ErrKeySize, ErrKeyCheck, ErrInvalidParams, ErrOpen} {
		if !strings.HasPrefix(err.Error(), "lifecipher: ") {
			t.Errorf("%q doesn't name the package", err)
		}
	}
	if got := fmt.Sprint(Demo()); got != "T = 6000, S = 16, k = 4, R = 16, version 1" {
		t.Errorf("Demo() prints as %q", got)
	}
}

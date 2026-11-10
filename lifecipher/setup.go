package lifecipher

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"math/bits"
	"runtime"
	"sync"
)

// KeySize is the size of a key: one grid (§3.1).
const KeySize = gridBytes

var (
	// ErrKeySize is returned by NewKey for a key that isn't KeySize bytes.
	ErrKeySize = errors.New("lifecipher: a key must be 128 bytes")

	// ErrKeyCheck is returned, wrapped, by NewKey for a key that fails the key check (§6.1): its first T
	// generations aren't all distinct. A key that passed vetting (§9) always passes. Random bytes almost never do.
	ErrKeyCheck = errors.New("lifecipher: the key fails the key check")
)

// setup0 is SETUP₀, the first 1,024 bits of π's fractional part, as row words (§6.2, Appendix A).
var setup0 = grid{
	0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344, 0xA4093822, 0x299F31D0, 0x082EFA98, 0xEC4E6C89,
	0x452821E6, 0x38D01377, 0xBE5466CF, 0x34E90C6C, 0xC0AC29B7, 0xC97C50DD, 0x3F84D5B5, 0xB5470917,
	0x9216D5D9, 0x8979FB1B, 0xD1310BA6, 0x98DFB5AC, 0x2FFD72DB, 0xD01ADFB7, 0xB8E1AFED, 0x6A267E96,
	0xBA7C9045, 0xF12C7F99, 0x24A19947, 0xB3916CF7, 0x0801F2E2, 0x858EFC16, 0x636920D8, 0x71574E69,
}

// setupConstant returns SETUP: SETUP₀ with T, k, S, R and the version XORed into its first five row words (§6.2).
func setupConstant(p Params) grid {
	g := setup0
	g[0] ^= p.Generations
	g[1] ^= p.Shuffles
	g[2] ^= p.GroupSize
	g[3] ^= p.Rounds
	g[4] ^= p.Version
	return g
}

// keyTable returns the key table G[t] = Life^t(K), for t = 0 … T − 1 (§6.1).
func keyTable(k *grid, T int) []grid {
	g := make([]grid, T)
	g[0] = *k
	for t := 1; t < T; t++ {
		g[t] = life(&g[t-1])
	}
	return g
}

// keyCheck reports whether the last generation of the key table differs from every earlier one, which holds exactly
// when all of them differ: once Life repeats a grid it cycles, and the last generation repeats too (§6.1). It
// compares every grid in full, with no early exit, so its time doesn't depend on the key (§14).
func keyCheck(g []grid) bool {
	last := &g[len(g)-1]
	var repeat uint32
	for t := range g[:len(g)-1] {
		var diff uint32
		for r, w := range last {
			diff |= g[t][r] ^ w
		}
		repeat |= eqMask(diff, 0)
	}
	return repeat == 0
}

// setupTable returns the setup table H[i] = G[i] ⊕ G[i + T/k] ⊕ … ⊕ G[i + (k − 1)T/k], indices mod T (§6.1). Its
// positions are fixed, so building it is constant-time.
func setupTable(g []grid, k int) []packedGrid {
	T := len(g)
	h := make([]packedGrid, T)
	for i := range h {
		var e grid
		for m := range k {
			e.xor(&g[(i+m*(T/k))%T])
		}
		h[i] = pack(&e)
	}
	return h
}

// A sortKey is one generation's place in a shuffle's sort (§6.5): its tag, then its generation number.
type sortKey struct {
	tag, idx uint64
}

// after returns 1 if a sorts after b, by tag and then by generation number, and 0 otherwise. bits.Sub64 runs in
// constant time, so the comparison doesn't branch on the tags.
func after(a, b *sortKey) uint64 {
	_, tagAbove := bits.Sub64(b.tag, a.tag, 0) // 1 if a.tag > b.tag
	_, tagBelow := bits.Sub64(a.tag, b.tag, 0) // 1 if a.tag < b.tag
	_, idxAbove := bits.Sub64(b.idx, a.idx, 0) // 1 if a.idx > b.idx
	return tagAbove | (1^(tagAbove|tagBelow))&idxAbove
}

// compareSwap puts records i and j, the sort keys and the generations they carry, in ascending order if up is set and
// descending order if not. It swaps them with masks, without branching on the keys.
func compareSwap(keys []sortKey, gens []packedGrid, i, j int, up bool) {
	a, b := &keys[i], &keys[j]
	var swap uint64
	if up { // up depends only on the positions, which are public
		swap = after(a, b)
	} else {
		swap = after(b, a)
	}
	m := -swap
	d := (a.tag ^ b.tag) & m
	a.tag ^= d
	b.tag ^= d
	d = (a.idx ^ b.idx) & m
	a.idx ^= d
	b.idx ^= d
	ga, gb := &gens[i], &gens[j]
	for r := range ga {
		d := (ga[r] ^ gb[r]) & m
		ga[r] ^= d
		gb[r] ^= d
	}
}

// bitonicSort sorts the n records from lo, ascending if up is set and descending if not, with a bitonic sorting
// network that works for any n. It carries each generation along with its key. The network depends only on n, and
// its compare-and-swaps don't branch on the keys, so nothing it does depends on the tags (§14).
func bitonicSort(keys []sortKey, gens []packedGrid, lo, n int, up bool) {
	if n < 2 {
		return
	}
	m := n / 2
	bitonicSort(keys, gens, lo, m, !up)
	bitonicSort(keys, gens, lo+m, n-m, up)
	bitonicMerge(keys, gens, lo, n, up)
}

// bitonicMerge sorts the n records from lo, a bitonic sequence, by comparing each record with the one a power of two
// further on: the largest power of two below n.
func bitonicMerge(keys []sortKey, gens []packedGrid, lo, n int, up bool) {
	if n < 2 {
		return
	}
	m := 1 << (bits.Len(uint(n-1)) - 1)
	for i := lo; i < lo+n-m; i++ {
		compareSwap(keys, gens, i, i+m, up)
	}
	bitonicMerge(keys, gens, lo, m, up)
	bitonicMerge(keys, gens, lo+m, n-m, up)
}

// shuffleInto builds shuffle s's T/k entries of W (§6.5, §6.6). It sorts the generations by their tags,
// tags[s·T + i] for generation i, and XORs each run of k consecutive generations in the sorted order into one entry.
// keys and gens are its working space, T records each. The generations travel through the sorting network with their
// tags, so W is built without reading G at a secret position (§14).
func shuffleInto(w []packedGrid, G []grid, tags []uint64, s, k int, keys []sortKey, gens []packedGrid) {
	T := len(G)
	for i := range T {
		keys[i] = sortKey{tag: tags[s*T+i], idx: uint64(i)}
		gens[i] = pack(&G[i])
	}
	bitonicSort(keys, gens, 0, T, true)
	for q := range T / k {
		e := &w[s*(T/k)+q]
		for m := range k {
			e.xor(&gens[k*q+m])
		}
	}
}

// A Key is a key expanded for one parameter set (§6.7): the key K, the round-key table W and the mask M. It
// implements crypto/cipher.AEAD. A Key doesn't change after NewKey returns, so it's safe for concurrent use, until
// Erase.
type Key struct {
	p    Params
	k, m grid
	w    []packedGrid
}

// NewKey expands key, KeySize bytes in the byte layout of §2.2, for the parameter set p (§6). It returns an error
// wrapping ErrKeyCheck if the key fails the key check (§6.1), and ErrKeySize or an error wrapping ErrInvalidParams
// for a malformed key or parameters. A key must have passed vetting (§9) before it's used; the key check catches
// only random bytes and other keys that fall into a short cycle.
//
// Key setup is expensive: T Life steps, a setup run of 2R + R·k·T/16 rounds, and k sorts of T generations. The sorts
// run in parallel, on up to GOMAXPROCS goroutines, while the setup run goes on.
func NewKey(p Params, key []byte) (ks *Key, err error) {
	if err = p.Validate(); err != nil {
		return nil, err
	}
	if len(key) != KeySize {
		return nil, ErrKeySize
	}
	subtle.WithDataIndependentTiming(func() { ks, err = newKey(p, key) })
	return ks, err
}

func newKey(p Params, key []byte) (*Key, error) {
	T, k, R := int(p.Generations), int(p.Shuffles), uint64(p.Rounds)
	K := gridFromBytes(key)
	G := keyTable(&K, T)
	defer clear(G)
	if !keyCheck(G) {
		return nil, fmt.Errorf("%w: its first %d generations aren't all distinct (SPEC.md §6.1)", ErrKeyCheck, T)
	}
	H := setupTable(G, k)
	defer clear(H)

	// §6.5 and §6.6: shuffle s sorts the generations by tags s·T … s·T + T − 1, which the setup run's blocks give in
	// order, so workers sort each shuffle as soon as its tags are ready, while the run goes on.
	ks := &Key{p: p, k: K, w: make([]packedGrid, T)}
	tags := make([]uint64, k*T)
	defer clear(tags)
	ready := make(chan int, k)
	var wg sync.WaitGroup
	for range min(k, runtime.GOMAXPROCS(0)) {
		wg.Go(func() {
			keys, gens := make([]sortKey, T), make([]packedGrid, T)
			for s := range ready {
				shuffleInto(ks.w, G, tags, s, k, keys, gens)
			}
			clear(keys)
			clear(gens)
		})
	}

	// §6.3 and §6.4: the setup run, in mode 1 from the setup constant. Its first block is the mask M. Each later
	// block gives 16 tags, read as big-endian 64-bit integers, words 2u and 2u + 1 of the block, k·T in all.
	st := state{a: setupConstant(p), b: K}
	st.rounds(H, 2*R)
	ks.m = st.b
	for s := range k {
		for block := range T / 16 {
			st.rounds(H, R)
			for u := range 16 {
				tags[s*T+16*block+u] = uint64(st.b[2*u])<<32 | uint64(st.b[2*u+1])
			}
		}
		ready <- s
	}
	close(ready)
	st = state{}
	wg.Wait()
	return ks, nil
}

// Params returns the parameter set k was expanded for.
func (k *Key) Params() Params { return k.p }

// Erase overwrites the key's expanded state, K, M and W, with zeros. Go may have copied parts of it elsewhere, so
// this is a best effort. The Key can't be used afterwards: its methods that use the key panic.
func (k *Key) Erase() {
	clear(k.w)
	k.w = nil
	k.k, k.m = grid{}, grid{}
}

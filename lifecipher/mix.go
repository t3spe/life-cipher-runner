package lifecipher

import (
	"crypto/subtle"
	"math/bits"
)

// golden is ⌊2^32 / φ⌋, φ the golden ratio (§12.1).
const golden = 0x9E3779B9

// selectorBits returns the 14 secret bits s that selector rule v5 draws from grid B in round r (§5.4.2): the entry j
// is s mod 16, the column shift dx is ⌊s / 16⌋ mod 32, and the row shift dy is ⌊s / 512⌋. A multiplication carries
// every bit of h upward, and the rotation brings the high bits back down for the next row, so a change anywhere in B
// moves the top bits of h.
func selectorBits(b *grid, r uint64) uint32 {
	h := uint32(r) * golden // r × 0x9E3779B9 mod 2^32
	for _, w := range b {
		h = bits.RotateLeft32(h^w, 13) * golden
	}
	return h >> 18
}

// group returns the public group g = (o + r) mod (T / S) of round r (§5.4.2).
func group(r uint64, o uint32, groups int) int {
	return int((uint64(o) + r) % uint64(groups))
}

// eqMask returns all ones if a == b, and 0 otherwise, without branching.
func eqMask(a, b uint32) uint32 {
	return uint32(-subtle.ConstantTimeEq(int32(a), int32(b)))
}

// readEntry returns entry j, 0 … 15, of a group of 16 table entries (§5.5). It reads all 16 and keeps entry j with
// masks, so the memory it touches doesn't depend on j (§14).
func readEntry(group *[16]packedGrid, j uint32) packedGrid {
	var m [16]uint64
	for i := range uint32(16) {
		m[i] = uint64(eqMask(i, j)) * 0x0000000100000001 // the mask in both halves of the word
	}
	var e packedGrid
	for r := range e {
		e[r] = group[0][r]&m[0] | group[1][r]&m[1] | group[2][r]&m[2] | group[3][r]&m[3] |
			group[4][r]&m[4] | group[5][r]&m[5] | group[6][r]&m[6] | group[7][r]&m[7] |
			group[8][r]&m[8] | group[9][r]&m[9] | group[10][r]&m[10] | group[11][r]&m[11] |
			group[12][r]&m[12] | group[13][r]&m[13] | group[14][r]&m[14] | group[15][r]&m[15]
	}
	return e
}

// state is the working state of a run of Mix rounds (§5.6): grids A and B, the round counter r and the IV offset o.
type state struct {
	a, b grid
	r    uint64
	o    uint32
}

// round runs one round of Mix with the table tab, which is H in mode 1 and W in mode 2 (§5.6):
// (A, B) ← (B, Life(B) ⊕ A ⊕ RK), where RK is entry S·g + j of tab shifted by (dx, dy). The selectors come from B
// alone, so a round can be undone, and it's a permutation of the state for any table.
func (st *state) round(tab []packedGrid) {
	g := group(st.r, st.o, len(tab)/16)
	s := selectorBits(&st.b, st.r)
	entry := readEntry((*[16]packedGrid)(tab[16*g:16*g+16]), s&15)
	rk := shift(&entry, s>>4&31, s>>9)
	next := life(&st.b)
	for i, w := range rk {
		next[2*i] ^= st.a[2*i] ^ uint32(w>>32)
		next[2*i+1] ^= st.a[2*i+1] ^ uint32(w)
	}
	st.a, st.b = st.b, next
	st.r++
}

// rounds runs n rounds of Mix with the table tab.
func (st *state) rounds(tab []packedGrid, n uint64) {
	for range n {
		st.round(tab)
	}
}

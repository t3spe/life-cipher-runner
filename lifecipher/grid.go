package lifecipher

import (
	"encoding/binary"
	"math/bits"
)

// gridBytes is the size of a grid in bytes: a key, an IV and a block are each one grid.
const gridBytes = 128

// A grid is 32 × 32 cells on a torus (§2.1). Row r is the word g[r], with column c in bit 31 − c, so a row's four
// bytes in the byte layout of §2.2, read big-endian, are its row word.
type grid [32]uint32

// A packedGrid is a grid stored two rows to a 64-bit word: word i holds row 2i in its high half and row 2i + 1 in
// its low half. The tables H and W are kept this way, so the constant-time read of a group (§5.5) and the shift of
// the round key touch half as many words.
type packedGrid [16]uint64

// pack returns g as a packedGrid.
func pack(g *grid) packedGrid {
	var p packedGrid
	for i := range p {
		p[i] = uint64(g[2*i])<<32 | uint64(g[2*i+1])
	}
	return p
}

// unpack returns p as a grid.
func (p *packedGrid) unpack() grid {
	var g grid
	for i, w := range p {
		g[2*i], g[2*i+1] = uint32(w>>32), uint32(w)
	}
	return g
}

// xor XORs src into p, cell by cell.
func (p *packedGrid) xor(src *packedGrid) {
	for i := range p {
		p[i] ^= src[i]
	}
}

// gridFromBytes reads a grid from the first 128 bytes of b (§2.2).
func gridFromBytes(b []byte) grid {
	var g grid
	for r := range g {
		g[r] = binary.BigEndian.Uint32(b[4*r:])
	}
	return g
}

// putBytes writes g into the first 128 bytes of b (§2.2).
func (g *grid) putBytes(b []byte) {
	for r, w := range g {
		binary.BigEndian.PutUint32(b[4*r:], w)
	}
}

// byteAt returns byte i of g. Byte i is in row word i/4, most significant byte first.
func (g *grid) byteAt(i int) byte {
	return byte(g[i>>2] >> (24 - 8*(i&3)))
}

// xorByte XORs v into byte i of g.
func (g *grid) xorByte(i int, v byte) {
	g[i>>2] ^= uint32(v) << (24 - 8*(i&3))
}

// setByte sets byte i of g to v.
func (g *grid) setByte(i int, v byte) {
	shift := 24 - 8*(i&3)
	g[i>>2] = g[i>>2]&^(0xFF<<shift) | uint32(v)<<shift
}

// xor XORs src into g, cell by cell.
func (g *grid) xor(src *grid) {
	for r := range g {
		g[r] ^= src[r]
	}
}

// life returns one Game of Life step of g on the torus, rule B3/S23 (§5.1): a cell is live next if it has exactly
// 3 live neighbors, or if it's live and has exactly 2. It adds up whole rows at once, so it does the same work for
// any grid (§14).
func life(g *grid) grid {
	// For each row, lo3 + 2·hi3 counts every cell with its left and right neighbors, and lo2 + 2·hi2 counts the two
	// neighbors alone. The loop keeps these sums for the rows above and at r, and adds those of the row below.
	upLo3, upHi3, _, _ := rowSums(g[31])
	lo3, hi3, lo2, hi2 := rowSums(g[0])
	var next grid
	for r := range next {
		downLo3, downHi3, downLo2, downHi2 := rowSums(g[(r+1)&31])
		// The 8 neighbors number ones + 2·(a + 2b + c + 2e), which is 2 or 3 exactly when a + 2b + c + 2e = 1:
		// when a ⊕ c = 1 and b = e = 0.
		ones := upLo3 ^ lo2 ^ downLo3
		carry := upLo3&lo2 | upLo3&downLo3 | lo2&downLo3
		a, b := upHi3^hi2, upHi3&hi2
		c, e := downHi3^carry, downHi3&carry
		next[r] = (a ^ c) &^ (b | e) & (ones | g[r])
		upLo3, upHi3 = lo3, hi3
		lo3, hi3, lo2, hi2 = downLo3, downHi3, downLo2, downHi2
	}
	return next
}

// rowSums returns a row's horizontal sums for life: lo3 + 2·hi3 counts each cell with its two neighbors in the row,
// and lo2 + 2·hi2 counts the two neighbors alone.
func rowSums(x uint32) (lo3, hi3, lo2, hi2 uint32) {
	east := bits.RotateLeft32(x, 1)  // each cell's neighbor in column c + 1
	west := bits.RotateLeft32(x, -1) // and in column c − 1
	return east ^ x ^ west, east&x | east&west | x&west, east ^ west, east & west
}

// shift returns the table entry e moved dx columns right and dy rows down, wrapping (§5.2): Y(r, c) = X(r − dy,
// c − dx), for dx and dy in 0 … 31. Both may be secret (§14), so rows move in five steps of 1, 2, 4, 8 and 16, each
// kept or dropped with a mask, and each row rotates by dx through variable shifts and masks, whose timing doesn't
// depend on dx.
func shift(e *packedGrid, dx, dy uint32) packedGrid {
	// One row: row 2i takes row 2i − 1, the low half of the word before, and row 2i + 1 takes row 2i, the high half
	// of its own word.
	var x packedGrid
	keep := -uint64(dy & 1) // all ones if this step moves the rows
	for i := range x {
		x[i] = (e[(i-1)&15]<<32|e[i]>>32)&keep | e[i]&^keep
	}
	// Then 2, 4, 8 and 16 rows: 1, 2, 4 and 8 whole words.
	y := moveWords(&x, 1, dy>>1&1)
	x = moveWords(&y, 2, dy>>2&1)
	y = moveWords(&x, 4, dy>>3&1)
	x = moveWords(&y, 8, dy>>4&1)
	// Columns: each row rotates right by dx, toward its low bits. low marks the bits of each half that stay in
	// it; the rest wrap around to the top of the same half.
	dx &= 31
	low := uint64(0xFFFFFFFF >> dx)
	low |= low << 32
	for i, w := range x {
		x[i] = w>>dx&low | w<<(32-dx)&^low
	}
	return x
}

// moveWords returns p with its words moved s places down, wrapping, if move is 1, and p as it is if move is 0,
// without branching on move.
func moveWords(p *packedGrid, s int, move uint32) packedGrid {
	keep := -uint64(move)
	var q packedGrid
	for i := range q {
		q[i] = p[(i-s)&15]&keep | p[i]&^keep
	}
	return q
}

// fold returns F(g) = rotl(g[0], 0) ⊕ rotl(g[1], 1) ⊕ … ⊕ rotl(g[31], 31) (§5.3).
func fold(g *grid) uint32 {
	var f uint32
	for r, w := range g {
		f ^= bits.RotateLeft32(w, r)
	}
	return f
}

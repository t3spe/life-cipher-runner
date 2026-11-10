package lifecipher

import (
	"errors"
	"fmt"
)

// Params is a parameter set (§3). Init and the finish run 2R rounds each.
type Params struct {
	Generations uint32 // T: generations in the key table G, and entries in the round-key table W
	GroupSize   uint32 // S: entries per group in the round-key lookup; selector rule v5 needs 16
	Shuffles    uint32 // k: generations XORed into each W entry, and the number of shuffles
	Rounds      uint32 // R: Mix rounds after each block; at least 16
	Version     uint32 // the algorithm version: 1, the only one this package implements
}

// Recommended returns the recommended parameter set of §3.3: T = 6,000, S = 16, k = 30, R = 24, version 1, with at
// most 2^48 blocks per key (§4.4).
func Recommended() Params {
	return Params{Generations: 6000, GroupSize: 16, Shuffles: 30, Rounds: 24, Version: 1}
}

// Demo returns the demo set of §3.3: T = 6,000, S = 16, k = 4, R = 16, version 1. It's for teaching and test vectors,
// not a recommendation: at k = 4, cell persistence gives a distinguisher at R = 16 from a few GB (§11.3).
func Demo() Params {
	return Params{Generations: 6000, GroupSize: 16, Shuffles: 4, Rounds: 16, Version: 1}
}

// This implementation's limits, which keep key setup's memory and time bounded.
const (
	MaxGenerations = 65535   // T at most, as in the C implementation
	MaxRounds      = 1024    // R at most
	MaxTags        = 1 << 20 // k·T at most: the tags the setup run draws, one per generation and shuffle
)

// ErrInvalidParams is returned, wrapped with the reason, for parameters that break the constraints of §3.2 or this
// implementation's limits.
var ErrInvalidParams = errors.New("lifecipher: invalid parameters")

// Validate checks p against the constraints of §3.2 and this implementation's limits.
func (p Params) Validate() error {
	var why string
	switch {
	case p.GroupSize != 16:
		why = "S must be 16: selector rule v5 draws a 4-bit entry index"
	case p.Generations == 0 || p.Generations%p.GroupSize != 0 || p.Generations > MaxGenerations:
		why = "T must be a positive multiple of S, at most 65,535"
	case p.Shuffles == 0 || p.Generations%p.Shuffles != 0:
		why = "k must divide T"
	case uint64(p.Generations)*uint64(p.Shuffles) > MaxTags:
		why = "k·T must be at most 1,048,576"
	case p.Rounds < 16 || p.Rounds > MaxRounds:
		why = "R must be at least 16, and at most 1,024"
	case p.Version != 1:
		why = "the version must be 1, the only algorithm version this package implements"
	default:
		return nil
	}
	return fmt.Errorf("%w: %s", ErrInvalidParams, why)
}

// String describes p in the spec's symbols.
func (p Params) String() string {
	return fmt.Sprintf("T = %d, S = %d, k = %d, R = %d, version %d",
		p.Generations, p.GroupSize, p.Shuffles, p.Rounds, p.Version)
}

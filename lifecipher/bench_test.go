package lifecipher

import (
	"fmt"
	"testing"
)

var benchSets = []struct {
	name string
	p    Params
}{
	{"demo", Demo()},
	{"recommended", Recommended()},
}

func BenchmarkNewKey(b *testing.B) {
	key := demoKeyBytes()
	for _, set := range benchSets {
		b.Run(set.name, func(b *testing.B) {
			for b.Loop() {
				if _, err := NewKey(set.p, key); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkSeal(b *testing.B) {
	for _, set := range benchSets {
		k := setupKey(b, set.p)
		for _, size := range []int{1 << 10, 64 << 10} {
			b.Run(fmt.Sprintf("%s/%dKiB", set.name, size>>10), func(b *testing.B) {
				iv, buf := make([]byte, IVSize), make([]byte, size, size+TagSize)
				b.SetBytes(int64(size))
				for b.Loop() {
					k.Seal(buf[:0], iv, buf, nil)
				}
			})
		}
	}
}

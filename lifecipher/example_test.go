package lifecipher_test

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"

	"github.com/t3spe/life-cipher-runner/lifecipher"
)

// demoKey is the demo key of SPEC.md Appendix B, as 32 row words. It's published, so it's burned: it must never
// protect anything. A real key is a vetted grid that was never published (SPEC.md §9).
const demoKey = "6B3028A8 DB46016A 318DA713 85D82A92 6489431E 9A2B00E1 1CB1E684 4106B26D " +
	"90FC90AC 77361985 884930EB 551A3B52 81186009 E8144094 82842900 D88996D1 " +
	"9514CC13 3A81EC34 47580B9D F304B451 84A2B274 24122838 08F6D934 3A69CBB8 " +
	"6A04296A 5F54D36A 42549769 1420992C 30F90206 7215518A 1CE02869 BA961C3B"

func demoKeyBytes() []byte {
	var hexDigits []byte
	for _, c := range []byte(demoKey) {
		if c != ' ' {
			hexDigits = append(hexDigits, c)
		}
	}
	key := make([]byte, lifecipher.KeySize)
	if _, err := hex.Decode(key, hexDigits); err != nil {
		log.Fatal(err)
	}
	return key
}

func Example() {
	k, err := lifecipher.NewKey(lifecipher.Recommended(), demoKeyBytes())
	if err != nil {
		log.Fatal(err) // the key failed the key check, so it can't be a vetted key
	}

	// Every message needs a fresh IV: an IV must never repeat under one key.
	iv := make([]byte, lifecipher.IVSize)
	if _, err = rand.Read(iv); err != nil {
		log.Fatal(err)
	}
	ad := []byte("message 1 of 3") // authenticated, not encrypted
	sealed := k.Seal(nil, iv, []byte("attack at dawn"), ad)

	// The receiver gets the IV and the sealed message, and the same associated data by some channel.
	opened, err := k.Open(nil, iv, sealed, ad)
	if err != nil {
		log.Fatal(err) // the message, its IV or its associated data changed
	}
	fmt.Printf("%s\n", opened)
	// Output: attack at dawn
}

func ExampleNewKey_keyCheck() {
	// Random bytes almost never make a valid key: a random grid usually falls into a short cycle, so the key check
	// refuses it. This key is the empty grid, which stays empty.
	_, err := lifecipher.NewKey(lifecipher.Recommended(), make([]byte, lifecipher.KeySize))
	fmt.Println(errors.Is(err, lifecipher.ErrKeyCheck))
	fmt.Println(err)
	// Output:
	// true
	// lifecipher: the key fails the key check: its first 6000 generations aren't all distinct (SPEC.md §6.1)
}

func ExampleKey_NewEncryptor() {
	k, err := lifecipher.NewKey(lifecipher.Recommended(), demoKeyBytes())
	if err != nil {
		log.Fatal(err)
	}
	iv := make([]byte, lifecipher.IVSize)
	if _, err = rand.Read(iv); err != nil {
		log.Fatal(err)
	}

	// A long message goes through in whole blocks, in as many calls as suits, and then the rest.
	msg := bytes.Repeat([]byte("Life "), 200)
	whole := len(msg) / lifecipher.BlockSize * lifecipher.BlockSize
	ct := make([]byte, len(msg))
	e := k.NewEncryptor(iv, nil)
	e.EncryptBlocks(ct[:whole], msg[:whole])
	tag := e.Finish(ct[whole:], msg[whole:])

	// Decryption mirrors it. Its plaintext isn't authentic until Finish has checked the tag.
	pt := make([]byte, len(ct))
	d := k.NewDecryptor(iv, nil)
	d.DecryptBlocks(pt[:whole], ct[:whole])
	if err := d.Finish(pt[whole:], ct[whole:], tag[:]); err != nil {
		log.Fatal(err) // discard all of pt
	}
	fmt.Println(bytes.Equal(pt, msg))
	// Output: true
}

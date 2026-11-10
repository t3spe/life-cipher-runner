// Package lifecipher implements the Life Cipher, an experimental authenticated cipher with associated data (AEAD)
// built on Conway's Game of Life on a 32 × 32 torus. It follows SPEC.md draft 0.4, algorithm version 1, from
// https://github.com/t3spe/life-cipher; the section numbers in this package's comments refer to that document.
//
// The Life Cipher is an experiment. Nobody outside its project has analyzed it, nothing about it is proven, and it
// must not protect real data.
//
// NewKey expands a key for a parameter set (§6). It runs the key check of §6.1 first, and refuses a key whose first
// T generations aren't all distinct. A key must also have passed vetting (§9), which runs offline and isn't part of
// this package. The resulting Key implements crypto/cipher.AEAD, with the 128-byte IV as the nonce and the 16-byte
// tag appended to the ciphertext. An IV must never repeat under one key. Encryptor and Decryptor process a long
// message block by block.
//
// The code follows the spec's implementation requirements (§14): no secret decides a branch or a memory address.
// Life steps are bit-parallel. The round key is read by touching all 16 entries of its public group. Shifts move rows
// in masked steps, and rotate each row through variable shifts and masks. The shuffles run through a sorting network
// that carries the generations along. The key check and the tag comparison always run in full. Every method that uses
// a key runs with the processor's data-independent timing mode on (crypto/subtle.WithDataIndependentTiming), which
// guarantees constant-time multiplication on ARM cores with DIT. Other cores need the guarantee from elsewhere: on
// Intel cores, the DOITM mode, which the operating system has to enable. Go makes no promise about the machine code
// it generates, so these are properties of the source code. Key.Erase, Encryptor.Erase and Decryptor.Erase overwrite
// state that is no longer needed, as far as Go allows.
//
// Under one key, encryption and decryption together may absorb at most 2^48 blocks (§4.4). This package doesn't
// count them.
package lifecipher

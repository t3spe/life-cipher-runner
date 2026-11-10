# Test data

| File | What it is |
|---|---|
| `demo-v1.json`, `recommended-v1.json`, `key-check-v1.json` | The Life Cipher's published test vectors for algorithm version 1, copied unchanged from `vectors/` in https://github.com/t3spe/life-cipher (SPEC.md §15). A test checks them against the SHA-256 digests SPEC.md §15 publishes, and another reads every field. They're under CC BY 4.0, that repository's `LICENSE-docs`. |
| `extra-v1.json` | More known answers, for cases those vectors don't cover: associated data of 128 bytes or more, including exact multiples of a block, messages of several blocks, and IVs with other offsets o = F(IV) mod 375 (SPEC.md §5.4.3) than the vectors' 297: 0, from two IVs, and 231. The reference implementation wrote it. The file records the SHA-256 of the `reference/lifecipher.py` it used, `ec59c96d…`, which is the one at commit 8a451f1 of https://github.com/t3spe/life-cipher. |
| `make_extra_vectors.py` | Writes `extra-v1.json` with the reference implementation: `python3 make_extra_vectors.py PATH/TO/life-cipher/reference extra-v1.json`. It replaces the file only once the new one is complete. It needs Python 3.10 or later, and the recommended set's key setup takes a few minutes. |

All of them use the burned demo key of SPEC.md Appendix B, which must never protect anything.

The three published vector files stay under their license, CC BY 4.0 (https://creativecommons.org/licenses/by/4.0/),
with attribution to https://github.com/t3spe/life-cipher. Everything else here is under the repository's license, the
GNU Affero General Public License, version 3 (`LICENSE` at the repository's root).

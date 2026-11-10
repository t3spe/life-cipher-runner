"""Writes extra-v1.json: known answers from the Life Cipher's reference implementation for cases the published
vectors (SPEC.md §15) don't cover: associated data of 128 bytes or more, messages of several blocks, and IVs with
other offsets o = F(IV) mod 375 (SPEC.md §5.4.3) than the vectors' IV, whose offset is 297.

    python3 make_extra_vectors.py REFERENCE_DIR OUTPUT

REFERENCE_DIR is the reference/ folder of https://github.com/t3spe/life-cipher, and OUTPUT is the file to write,
extra-v1.json. The file is replaced only once it's complete. The reference needs Python 3.10 or later and nothing
else. Its key setup for the recommended set takes a few minutes.
"""
import hashlib
import json
import os
import pathlib
import sys
import tempfile

REFERENCE = pathlib.Path(sys.argv[1]).resolve()
sys.path.insert(0, str(REFERENCE))
import lifecipher as lc  # noqa: E402
import make_vectors  # noqa: E402

KEY = bytes.fromhex(make_vectors.DEMO_KEY_HEX)      # the burned demo key (SPEC.md Appendix B)
IVS = {
    "the vectors' IV": make_vectors.IV,                         # byte i is (13 + 7i) mod 256: o = 297
    "the counting IV": bytes(range(128)),                       # 00 01 … 7F, whose fold is 0: o = 0 (SPEC.md §11.5)
    "all ones": bytes([0xFF] * 128),                            # 32 equal row words cancel in the fold: o = 0
    "byte i is (5i + 11) mod 256": bytes((5 * i + 11) % 256 for i in range(128)),  # o = 231
}
CASES = [  # (IV, bytes of associated data, bytes of plaintext)
    ("the vectors' IV", 127, 0),
    ("the vectors' IV", 128, 0),
    ("the vectors' IV", 129, 1),
    ("the vectors' IV", 255, 128),
    ("the vectors' IV", 256, 129),
    ("the vectors' IV", 257, 383),
    ("the vectors' IV", 300, 384),
    ("the vectors' IV", 0, 385),
    ("the vectors' IV", 0, 1000),
    ("the counting IV", 23, 256),
    ("all ones", 128, 128),
    ("byte i is (5i + 11) mod 256", 0, 200),
    ("byte i is (5i + 11) mod 256", 129, 64),
]


def pattern(n: int, a: int, b: int) -> bytes:
    return bytes((a * i + b) % 256 for i in range(n))


def build(params: lc.Params) -> dict:
    ks = lc.key_setup(KEY, params)
    aead = []
    for iv_name, ad_len, pt_len in CASES:
        iv, ad, pt = IVS[iv_name], pattern(ad_len, 7, 3), pattern(pt_len, 1, 0)
        ct, tag = lc.encrypt(ks, iv, ad, pt)
        assert lc.decrypt(ks, iv, ad, ct, tag) == pt
        aead.append({"iv": iv.hex(), "ad": ad.hex(), "plaintext": pt.hex(), "ciphertext": ct.hex(), "tag": tag.hex()})
    return {"parameters": {"T": params.T, "S": params.S, "k": params.k, "R": params.R, "version": params.version},
            "aead": aead}


def offset(iv: bytes, params: lc.Params) -> int:
    return lc.iv_offset(lc.grid_from_bytes(iv), params)


def main():
    assert [offset(IVS[name], lc.RECOMMENDED) for name in IVS] == [297, 0, 0, 231]
    source = (REFERENCE / "lifecipher.py").read_bytes()
    output = pathlib.Path(sys.argv[2]).resolve()
    out = tempfile.NamedTemporaryFile("w", dir=output.parent, delete=False, suffix=".tmp")
    json.dump({
        "description": "Extra known answers for the Life Cipher: AEAD cases that SPEC.md §15's vectors don't cover",
        "source": "reference/lifecipher.py of https://github.com/t3spe/life-cipher, by make_extra_vectors.py",
        "source_sha256": hashlib.sha256(source).hexdigest(),
        "key": "the burned demo key of SPEC.md Appendix B",
        "data": "byte i of the associated data is (7i + 3) mod 256, and byte i of the plaintext is i mod 256",
        "sets": [build(lc.DEMO), build(lc.RECOMMENDED)],
    }, out, indent=2)
    out.write("\n")
    out.close()
    os.chmod(out.name, 0o644)
    os.replace(out.name, output)


if __name__ == "__main__":
    main()

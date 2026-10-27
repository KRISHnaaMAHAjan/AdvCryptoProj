from cryptochunk.erasure import encode, decode


def test_recover_every_four_shard_combination():
    original = bytes(range(256)) * 3 + b"cryptography"
    shards = encode(original)
    for indices in __import__('itertools').combinations(range(6), 4):
        recovered = decode({i: shards[i] for i in indices})[:len(original)]
        assert recovered == original


def test_empty_input_roundtrip():
    assert decode({i: encode(b"")[i] for i in (0, 2, 4, 5)})[:0] == b""

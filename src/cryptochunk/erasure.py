"""Small systematic Reed-Solomon-style (4, 6) erasure code over GF(2^8).

The generator matrix is [I_4; P], where P is a 2x4 Vandermonde matrix
with evaluation points 1 and 2. Any four of the six shards reconstruct data.
"""
from __future__ import annotations

from itertools import combinations

_PRIMITIVE_POLYNOMIAL = 0x11D
_DATA_SHARDS = 4
_TOTAL_SHARDS = 6


def _build_tables() -> tuple[list[int], list[int]]:
    exp = [0] * 512
    log = [0] * 256
    value = 1
    for i in range(255):
        exp[i] = value
        log[value] = i
        value <<= 1
        if value & 0x100:
            value ^= _PRIMITIVE_POLYNOMIAL
    for i in range(255, 512):
        exp[i] = exp[i - 255]
    return exp, log


_EXP, _LOG = _build_tables()


def _mul(a: int, b: int) -> int:
    if not a or not b:
        return 0
    return _EXP[_LOG[a] + _LOG[b]]


def _inv(a: int) -> int:
    if a == 0:
        raise ZeroDivisionError("zero has no multiplicative inverse in GF(256)")
    return _EXP[255 - _LOG[a]]


def _matrix_inverse(matrix: list[list[int]]) -> list[list[int]]:
    n = len(matrix)
    work = [row[:] + [1 if i == j else 0 for j in range(n)] for i, row in enumerate(matrix)]
    for col in range(n):
        pivot = next((r for r in range(col, n) if work[r][col]), None)
        if pivot is None:
            raise ValueError("selected shards do not form an invertible matrix")
        work[col], work[pivot] = work[pivot], work[col]
        scale = _inv(work[col][col])
        work[col] = [_mul(v, scale) for v in work[col]]
        for row in range(n):
            if row == col or work[row][col] == 0:
                continue
            factor = work[row][col]
            work[row] = [x ^ _mul(factor, y) for x, y in zip(work[row], work[col])]
    return [row[n:] for row in work]


def generator_row(index: int) -> list[int]:
    if not 0 <= index < _TOTAL_SHARDS:
        raise ValueError("shard index must be in [0, 5]")
    if index < _DATA_SHARDS:
        return [int(i == index) for i in range(_DATA_SHARDS)]
    x = 1 if index == 4 else 2
    return [1, x, _mul(x, x), _mul(_mul(x, x), x)]


def encode(data: bytes) -> list[bytes]:
    """Encode bytes into six equal-length shards (4 data + 2 parity)."""
    shard_size = max(1, (len(data) + _DATA_SHARDS - 1) // _DATA_SHARDS)
    padded = data.ljust(shard_size * _DATA_SHARDS, b"\0")
    shards = [bytearray(padded[i * shard_size:(i + 1) * shard_size]) for i in range(_DATA_SHARDS)]
    for row_index in (4, 5):
        coefficients = generator_row(row_index)
        output = bytearray(shard_size)
        for coefficient, shard in zip(coefficients, shards):
            if coefficient == 0:
                continue
            if coefficient == 1:
                for pos, value in enumerate(shard):
                    output[pos] ^= value
            else:
                for pos, value in enumerate(shard):
                    output[pos] ^= _mul(coefficient, value)
        shards.append(output)
    return [bytes(shard) for shard in shards]


def decode(available: dict[int, bytes]) -> bytes:
    """Recover the four data shards from any four valid shard indices."""
    if len(available) < _DATA_SHARDS:
        raise ValueError(f"need at least {_DATA_SHARDS} valid shards; found {len(available)}")
    chosen = sorted(available)[:_DATA_SHARDS]
    if any(index < 0 or index >= _TOTAL_SHARDS for index in chosen):
        raise ValueError("shard indices must be in [0, 5]")
    shard_sizes = {len(available[index]) for index in chosen}
    if len(shard_sizes) != 1:
        raise ValueError("all shards must have equal length")
    matrix = [generator_row(index) for index in chosen]
    inverse = _matrix_inverse(matrix)
    shard_size = len(available[chosen[0]])
    recovered = [bytearray(shard_size) for _ in range(_DATA_SHARDS)]
    for data_index, row in enumerate(inverse):
        for coefficient, shard_index in zip(row, chosen):
            shard = available[shard_index]
            if coefficient == 0:
                continue
            if coefficient == 1:
                for pos, value in enumerate(shard):
                    recovered[data_index][pos] ^= value
            else:
                for pos, value in enumerate(shard):
                    recovered[data_index][pos] ^= _mul(coefficient, value)
    return b"".join(bytes(shard) for shard in recovered)

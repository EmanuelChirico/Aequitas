import hashlib

H_LEN = 32
L_HASH = hashlib.sha256(b"").digest()

class InvalidOAEP(Exception):
    pass

def _mgf1(seed: bytes, length: int) -> bytes:
    t = b""
    for i in range(-(-length // H_LEN)):
        t += hashlib.sha256(seed + i.to_bytes(4, "big")).digest()
    return t[:length]

def decode_oaep(m_prime: int, k: int) -> bytes:
    try:
        EM = m_prime.to_bytes(k, "big")
    except OverflowError:
        raise InvalidOAEP

    if EM[0] != 0x00:
        raise InvalidOAEP

    masked_seed, masked_db = EM[1:1+H_LEN], EM[1+H_LEN:]
    seed = bytes(a ^ b for a, b in zip(masked_seed, _mgf1(masked_db, H_LEN)))
    db   = bytes(a ^ b for a, b in zip(masked_db,   _mgf1(seed, k - H_LEN - 1)))

    if db[:H_LEN] != L_HASH:
        raise InvalidOAEP

    rest = db[H_LEN:]
    sep  = rest.find(0x01)
    if sep == -1 or any(b != 0 for b in rest[:sep]):
        raise InvalidOAEP

    return rest[sep + 1:]

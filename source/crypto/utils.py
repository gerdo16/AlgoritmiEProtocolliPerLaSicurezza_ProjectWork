from cryptography.hazmat.primitives import hashes
import struct

""" hash data """
def sha256(data: bytes) -> bytes:
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return digest.finalize()

""" serializza N campi binari con prefisso di lunghezza """
def pack_fields(*fields: bytes) -> bytes:
    packed = b''
    for field in fields:
        packed += struct.pack('>I', len(field)) + field
    return packed


""" deserializza N campi binari con prefisso di lunghezza """
def unpack_fields(data: bytes, n: int) -> list[bytes]:
    fields, offset = [], 0
    for _ in range(n):
        if offset + 4 > len(data):
            raise ValueError("Buffer troppo corto durante unpack")
        
        length = struct.unpack(">I", data[offset : offset + 4])[0]
        offset += 4
        fields.append(data[offset : offset + length])
        offset += length
    return fields

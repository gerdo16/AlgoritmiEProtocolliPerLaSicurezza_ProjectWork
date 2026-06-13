from cryptography.hazmat.primitives import hashes
import struct

""" hash data """
def sha256(data: bytes) -> bytes:
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return digest.finalize()

def pack_fields(*fields: bytes) -> bytes:
    """
    fields è una lista di campi binari che vogliamo concatenare in un unica variabile packed
    Il formato è: [len(f1) || f1 || len(f2) || f2 || ...]
    dove len(f) è un intero a 4 byte che indica la lunghezza del campo f
    """
    packed = b''
    for field in fields:
        packed += struct.pack('>I', len(field)) + field
    return packed


def unpack_fields(data: bytes, n: int) -> list[bytes]:
    """
    data è la variabile binaria che contiene i campi concatenati, n è il numero di campi da estrarre
    Ritorna una lista di campi estratti da data
    Riesce a estrarre i campi correttamente solo se data è formattata secondo il formato di pack_fields perchè legge la lunghezza di ogni campo prima di estrarlo
    """
    fields, offset = [], 0
    for _ in range(n):
        if offset + 4 > len(data):
            raise ValueError("Buffer troppo corto durante unpack")
        
        # leggo la lunghezza del campo successivo (4 byte) 
        length = struct.unpack(">I", data[offset : offset + 4])[0]
        offset += 4

        # leggo il campo successivo usando la lunghezza appena letta
        fields.append(data[offset : offset + length])
        offset += length
    return fields


if __name__ == "__main__":
    # Test pack_fields e unpack_fields
    f1 = b"Hello"
    f2 = b"World"
    f3 = b"Test"

    packed = pack_fields(f1, f2, f3)
    print(f"Packed: {packed}")

    unpacked = unpack_fields(packed, 3) # corretto
    print(f"Unpacked: {unpacked}")

    unpacked = unpack_fields(packed, 2) # salta il terzo campo, ma non da errore perchè legge la lunghezza del secondo campo e si sposta correttamente, restituendo solo i primi 2 campi
    print(f"Unpacked: {unpacked}")

    unpacked = unpack_fields(packed, 4) # da errore perchè cerca di leggere un quarto campo che non esiste, l'errore è chiaro e indica che il buffer è troppo corto
    print(f"Unpacked: {unpacked}")
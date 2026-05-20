import random
import string
import os


def random_string(length=6):
    letters = string.ascii_lowercase + string.digits
    return ''.join(random.choice(letters) for _ in range(length))


def random_variable_name(length=None):
    if length is None:
        length = random.randint(8, 20)
    return ''.join(random.choice(string.ascii_letters) for _ in range(length))


def generate_key(length=16):
    return os.urandom(length)


def bytes_to_ps1_array(data: bytes) -> str:
    return ','.join(f'0x{b:02X}' for b in data)


def bytes_to_cs_array(data: bytes) -> str:
    return '{ ' + ', '.join(f'0x{b:02x}' for b in data) + ' }'


def bytes_to_vba_array(data: bytes) -> str:
    parts = []
    for i, b in enumerate(data):
        parts.append(str(b))
        if i > 0 and i % 16 == 0:
            parts.append('_\n        ')
    return ', '.join(p for p in parts if p.strip('_\n '))


def vba_array_lines(data: bytes, indent: int = 8) -> list[str]:
    """Split VBA byte array across multiple lines, 16 bytes per line."""
    sp = ' ' * indent
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        lines.append(sp + ', '.join(str(b) for b in chunk))
    return lines


def split_into_chunks(data: bytes, num_chunks: int | None = None) -> list[tuple[str, bytes]]:
    """Split bytes into N chunks with random variable names."""
    length = len(data)
    if num_chunks is None:
        if length < 50:
            num_chunks = 2
        elif length < 200:
            num_chunks = 3
        elif length < 500:
            num_chunks = 4
        else:
            num_chunks = 5

    chunk_size = length // num_chunks
    chunks = []
    for i in range(num_chunks):
        var = random_variable_name(random.randint(15, 25))
        if i == num_chunks - 1:
            chunk = data[i * chunk_size:]
        else:
            chunk = data[i * chunk_size:(i + 1) * chunk_size]
        chunks.append((var, chunk))
    return chunks

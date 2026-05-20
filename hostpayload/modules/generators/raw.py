"""
Raw binary output generator.

Simply writes the encrypted bytes to a .bin file.
Useful for loading into custom loaders or further tooling.
"""


def generate(encrypted_bytes: bytes) -> bytes:
    """Return raw encrypted bytes (caller writes to .bin file)."""
    return encrypted_bytes

import base64


def _b64Encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')

def _b64Decode(data):
    data += "="*((4 - len(data) % 4) % 4)
    return base64.urlsafe_b64decode(data)

def _encodeInt(value, key_size):
    """Convert an integer to bytes."""
    return value.to_bytes((key_size + 7) // 8, byteorder='big')
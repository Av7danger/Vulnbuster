def encode_url(payload: str) -> str:
    try:
        return ''.join(['%' + hex(ord(c))[2:] for c in payload])
    except Exception:
        return payload

def mutate_case(payload: str) -> str:
    try:
        return payload.swapcase()
    except Exception:
        return payload

def encode_unicode(payload: str) -> str:
    try:
        return ''.join(['\\u{:04x}'.format(ord(c)) for c in payload])
    except Exception:
        return payload

def timing_fuzz(payload: str) -> str:
    try:
        return payload + " /*sleep*/"
    except Exception:
        return payload
# TODO: Add more advanced mutators and evasion logic 
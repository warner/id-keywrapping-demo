import math
from hashlib import sha256
from hmac import HMAC
import struct

def PBKDF2(password, salt, count, dkLen, hfunc=sha256):
    hlen = hfunc().digest_size
    width = int(math.ceil(float(dkLen)/hlen))
    assert width < 2**32
    out = []
    def PRF(data):
        return HMAC(password, data, hfunc).digest()
    def xor(a,b):
        assert len(a) == len(b)
        return "".join([chr(ord(a[i])^ord(b[i])) for i in range(len(a))])
    for i in xrange(width):
        x = PRF(salt+struct.pack(">L", i+1))
        y = x
        for j in xrange(count-1):
            x = PRF(x)
            y = xor(x,y)
        out.append(y)
    return "".join(out)[:dkLen]

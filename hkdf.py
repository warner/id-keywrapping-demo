
from hashlib import sha256
import hmac

def HKDF(SKM, dkLen, XTS=None, CTXinfo="", digest=sha256):
    hlen = digest("").digest()
    if XTS is None:
        XTS = "\x0"*hlen
    # extract
    PRK = hmac.new(salt, SKM, digest).digest()
    # expand
    ...
    

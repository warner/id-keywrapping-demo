
import os, time
from util import aes256cbc_enc, aes256cbc_dec

for l in range(100):
    key = os.urandom(16)
    iv = os.urandom(16)
    pt = "A"*l
    ct = aes256cbc_enc(key, iv, pt)
    pt2 = aes256cbc_dec(key, iv, ct)
    #print l, len(pt), len(ct), len(pt2)
    assert pt == pt2, (l, pt, pt2)

def bench(l):
    key = os.urandom(16)
    iv = os.urandom(16)
    pt = "A"*l
    start = time.time()
    for i in range(100):
        ct = aes256cbc_enc(key, iv, pt)
    elapsed = time.time() - start
    print "len=%d: %.02g" % (l, elapsed/100)
bench(16) # 16-byte messages take 5ms
bench(200) # 200-byte messages take 31ms : 6.5kBps
bench(2000) # 2000-byte messages take 300ms
# C++ (Crypto++) does AES-CTR at 113MBps, 18000x faster


import os, time
from util import aes256cbc_enc, aes256cbc_dec

def test_aes():
    for l in range(100):
        key = os.urandom(16)
        iv = os.urandom(16)
        pt = "A"*l
        ct = aes256cbc_enc(key, iv, pt)
        pt2 = aes256cbc_dec(key, iv, ct)
        #print l, len(pt), len(ct), len(pt2)
        assert pt == pt2, (l, pt, pt2)

def do_bench():
    def bench(l):
        key = os.urandom(16)
        iv = os.urandom(16)
        pt = "A"*l
        start = time.time()
        for i in range(100):
            aes256cbc_enc(key, iv, pt)
        elapsed = time.time() - start
        print "len=%d: %.02g" % (l, elapsed/100)
    bench(16) # 16-byte messages take 5ms
    bench(200) # 200-byte messages take 31ms : 6.5kBps
    bench(2000) # 2000-byte messages take 300ms
    # C++ (Crypto++) does AES-CTR at 113MBps, 18000x faster


from server import Handler
from client import do_init, do_read, do_change
from base64 import b64encode
import json
def test_all():
    h = Handler()
    def fake_network(url, req_obj):
        req_data = json.dumps(req_obj).encode("utf-8")
        return h.receive_request(req_data)
    email = "someone@example.com"
    password_b64 = b64encode("1234")
    initial_UK_b64 = do_init(email, password_b64, None, fake_network)
    later_UK_b64 = do_read(email, password_b64, None, fake_network)
    assert initial_UK_b64 == later_UK_b64
    new_password_b64 = b64encode("abcd")
    do_change(email, password_b64, new_password_b64, None, fake_network)
    final_UK_b64 = do_read(email, new_password_b64, None, fake_network)
    assert final_UK_b64 == initial_UK_b64
test_all()


import os, json
from urllib import urlopen
from hashlib import sha256
from base64 import b64encode, b64decode
from hmac import HMAC
from PBKDF import PBKDF2
import srp
from scrypt import scrypt
from hkdf import HKDF

KEYLEN = 256/8
assert KEYLEN == 32 # bytes
IVLEN = 128/8
assert IVLEN == 16 # bytes
MACLEN = 256/8
assert MACLEN == 32
c1 = 10000
c2 = 10000
SCRYPT_PARAMS = (32768,8,1) # N,r,p, uses 100MB/1.0s on my work laptop

class CorruptDataError(Exception):
    pass

class Oops(Exception):
    pass

from ska.mode import enc_cbc, dec_cbc
from ska.aes import aes
from ska.pad import pkcs7_pad, pkcs7_unpad

def aes256cbc_enc(key, iv, data):
    assert len(iv) == 128/8, len(iv)
    assert len(key) == 256/8, len(key)
    ct = enc_cbc(aes(key), iv)(pkcs7_pad(data))
    return ct
def aes256cbc_dec(key, iv, data):
    pt = pkcs7_unpad(dec_cbc(aes(key), iv)(data))
    return pt

def SALT(s, email=None):
    assert ":" not in s
    assert s.encode("ascii") == s
    # the tag always ends with ":", so this is parseable, hence avoids
    # boundary-confusion attacks
    prefix = "identity.mozilla.com/keywrapping/v1/%s:" % s
    if email is None:
        return prefix
    return prefix+email.encode("utf-8")
def SALT_b64(s, email=None):
    return b64encode(SALT(s, email))

def PBKDF2_b64(password_b64, salt_b64, c, dkLen):
    return b64encode(PBKDF2(password=b64decode(password_b64),
                            salt=b64decode(salt_b64),
                            c=c, dkLen=dkLen))

def scrypt_b64(password_b64, salt_b64, dkLen):
    N,r,p = SCRYPT_PARAMS
    return b64encode(scrypt(password=b64decode(password_b64),
                            salt=b64decode(salt_b64), N=N,r=r,p=p,
                            dkLen=dkLen))
def make_keys(C_b64, salt_b64):
    out = HKDF(SKM=b64decode(C_b64), XTS=b64decode(salt_b64),
               CTXinfo="", dkLen=4*KEYLEN)
    keys = [b64encode(out[i:i+KEYLEN]) for i in range(0, len(out), KEYLEN)]
    #PWK_b64, MAC_b64, SRPpw_b64, accountID_b64 = keys
    return keys

def saltless_srp_create(username, password, hash_alg=srp.SHA1,
                        ng_type=srp.NG_2048, n_hex=None, g_hex=None):
    # unfortunately the python SRP module doesn't make it easy to pass our
    # own salt into create_salted_verification_key(), so we have to get
    # messy. Other SRP libraries (e.g. SJCL) make this easier.
    from srp._pysrp import _hash_map, get_ng, long_to_bytes, gen_x
    from srp import NG_CUSTOM
    if ng_type == NG_CUSTOM and (n_hex is None or g_hex is None):
        raise ValueError("Both n_hex and g_hex are required when ng_type = NG_CUSTOM")
    hash_class = _hash_map[ hash_alg ]
    N,g = get_ng( ng_type, n_hex, g_hex )
    #_s = long_to_bytes( get_random( 4 ) )
    _s = None
    _v = long_to_bytes( pow(g,  gen_x(hash_class, _s, username, password), N))
    return _v

def do_SRP_setup(SRPpw_b64, accountID_b64):
    # if we didn't need an empty salt, we'd use
    # srp.create_salted_verification_key() here
    SRPvkey = saltless_srp_create(accountID_b64, b64decode(SRPpw_b64),
                                  hash_alg=srp.SHA256)
    return b64encode(SRPvkey)

def do_SRP(server_url, accountID_b64, SRPpw_b64, do_network):
    session_id_b64 = b64encode(os.urandom(KEYLEN))
    # use the base64-encoded accountID as a "username" for SRP, to tolerate
    # libraries that need printable/ASCII usernames
    u = srp.User(accountID_b64, b64decode(SRPpw_b64), hash_alg=srp.SHA256)
    _ignored_username, msg1_A = u.start_authentication()
    assert _ignored_username == accountID_b64
    rd = do_network(server_url, ["srp-1",
                                 session_id_b64, accountID_b64, b64encode(msg1_A)])
    r = json.loads(rd.decode("utf-8"))
    if r[0] != "ok": raise Oops("srp-1 error")
    s,B = b64decode(r[1]), b64decode(r[2])
    M = u.process_challenge(s, B)
    if M is None:
        raise Oops("SRP rejected (s,B)")
    rd = do_network(server_url, ["srp-2", session_id_b64, b64encode(M)])
    r = json.loads(rd.decode("utf-8"))
    if r[0] != "ok": raise Oops("srp-1 error")
    # server is now happy and will remember the session for one request
    HAMK = b64decode(r[1])
    u.verify_session(HAMK)
    if not u.authenticated():
        raise Oops("SRP rejected")
    return b64encode(u.get_session_key()), session_id_b64
    

def do_network(url, req_obj):
    req_data = json.dumps(req_obj).encode("utf-8")
    f = urlopen(url, req_data) # POST
    response_data = f.read()
    if f.getcode() != 200:
        raise Oops("network error: %s" % response_data[:400])
    return response_data

def make_session_keys(SRPKSession_b64):
    SRPKSession = b64decode(SRPKSession_b64)
    K,M = KEYLEN, MACLEN
    out = HKDF(SKM=SRPKSession, XTS=SALT("session-keys"), CTXinfo="",
               dkLen=K+M+K+M)
    keys = [out[0:K],
            out[K:K+M],
            out[K+M:K+M+K],
            out[K+M+K:K+M+K+M]]
    (ENC1, MAC1, ENC2, MAC2) = [b64encode(k) for k in keys]
    return (ENC1, MAC1, ENC2, MAC2)

def encrypt_and_mac(enc_b64, mac_b64, data_b64):
    IV = os.urandom(IVLEN)
    A = aes256cbc_enc(key=b64decode(enc_b64), iv=IV, data=b64decode(data_b64))
    dec = aes256cbc_dec(key=b64decode(enc_b64), iv=IV, data=A)
    if True: # self-check
        orig = b64decode(data_b64)
        if dec != orig:
            print "data:", len(orig), orig.encode("hex")
            print "dec :", len(dec), dec.encode("hex")
            raise ValueError("early")
    B = HMAC(key=b64decode(mac_b64), msg=IV+A, digestmod=sha256).digest()
    return b64encode(IV+A+B)

def decrypt(enc_b64, mac_b64, encdata_b64):
    encdata = b64decode(encdata_b64)
    assert len(encdata) > (IVLEN+MACLEN)
    IV,A,B1 = (encdata[:IVLEN], encdata[IVLEN:-MACLEN], encdata[-MACLEN:])
    B2 = HMAC(key=b64decode(mac_b64), msg=IV+A, digestmod=sha256).digest()
    if B1 != B2:
        raise CorruptDataError("bad MAC")
    data = aes256cbc_dec(key=b64decode(enc_b64), iv=IV, data=A)
    return b64encode(data)

def client_create_request(req_obj, enc1_b64, mac1_b64, SessionID_b64):
    data_b64 = b64encode(json.dumps(req_obj).encode("utf-8"))
    enc_data_b64 = encrypt_and_mac(enc1_b64, mac1_b64, data_b64)
    enc_msg = ["encrypted-request", SessionID_b64, enc_data_b64]
    return enc_msg

def client_process_response(rx_b64, enc2_b64, mac2_b64):
    response_data_b64 = decrypt(enc2_b64, mac2_b64, rx_b64)
    return json.loads(b64decode(response_data_b64).decode("utf-8"))


    

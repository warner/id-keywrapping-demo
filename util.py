
import os, json
from urllib import urlopen
from hashlib import sha256
from base64 import b64encode, b64decode
from hmac import HMAC
from PBKDF import PBKDF2
import srp
from scrypt import scrypt
from hkdf import HKDF

KEYLEN = 258/8
assert KEYLEN == 32 # bytes
c1 = 10000
c2 = 10000
N,r,p = 32768,8,1  # scrypt 100MB/1.0s, on work laptop

class CorruptDataError(Exception):
    pass

class Oops(Exception):
    pass

def aes256cbc_enc(key, iv, data):
    return data
def aes256cbc_dec(key, iv, data):
    return data

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
    return b64encode(scrypt(password=b64decode(password_b64),
                            salt=b64decode(salt_b64), N=N,r=r,p=p,
                            dkLen=dkLen))
def make_keys(C_b64, salt_b64):
    out = HKDF(SKM=b64decode(C_b64), XTS=b64decode(salt_b64),
               CTXinfo="", dkLen=3*KEYLEN)
    keys = [b64encode(out[i:i+KEYLEN]) for i in range(0, len(out), KEYLEN)]
    #PWK_b64, MAC_b64, SRPpw_b64 = keys
    return keys

def do_SRP_setup(SRPpw_b64, email):
    out = srp.create_salted_verification_key(email.encode("utf-8"),
                                             b64decode(SRPpw_b64),
                                             hash_alg=srp.SHA256)
    SRPsalt, SRPvkey = out
    return b64encode(SRPsalt), b64encode(SRPvkey)

def do_SRP(server_url, email, SRPpw_b64, salt_b64=None):
    if not salt_b64:
        salt_b64 = do_network(server_url, ["get-salt", email])
    session_id_b64 = b64encode(os.random(KEYLEN))
    # XXX: email is unicode, right? so pass email.encode("utf-8") ?
    u = srp.User(email, b64decode(SRPpw_b64), hash_alg=srp.SHA256)
    _ignored_username, msg1_A = u.start_authentication()
    rd = do_network(server_url, ["srp-1", session_id_b64, email,
                                 b64encode(msg1_A)])
    r = json.loads(rd.decode("utf-8"))
    if r[0] != "ok": raise Oops("srp-1 error")
    s,B = b64decode(r[1]), b64decode(r[2])
    M = u.process_challenge(s, B)
    if M is None:
        raise Oops("SRP rejected")
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
    return response_data

def make_session_keys(SRPKSession_b64):
    SRPKSession = b64decode(SRPKSession_b64)
    out = HKDF(SKM=SRPKSession, XTS=SALT("session-keys"), CTXinfo="",
               L=4*KEYLEN)
    keys = [b64encode(out[i:i+KEYLEN]) for i in range(0, len(out), KEYLEN)]
    (ENC1, MAC1, ENC2, MAC2) = keys
    return (ENC1, MAC1, ENC2, MAC2)

def encrypt_and_mac(enc_b64, mac_b64, data_b64):
    IV = os.urandom(KEYLEN)
    A = aes256cbc_enc(key=b64decode(enc_b64), iv=IV, data=b64decode(data_b64))
    B = HMAC(key=b64decode(mac_b64), msg=IV+A, digestmod=sha256).digest()
    return b64encode(IV+A+B)

def decrypt(enc_b64, mac_b64, encdata_b64):
    encdata = b64decode(encdata_b64)
    assert len(encdata) > 2*KEYLEN
    IV,A,B1 = (encdata[:KEYLEN], encdata[KEYLEN:-KEYLEN], encdata[-KEYLEN:])
    B2 = HMAC(key=b64decode(mac_b64), msg=IV+A, digestmod=sha256).digest()
    if B1 != B2:
        raise CorruptDataError("bad MAC")
    data = aes256cbc_dec(key=b64decode(enc_b64), iv=IV, data=A)
    return b64encode(data)

def client_create_request(req_obj, enc1_b64, mac1_b64, SessionID_b64):
    data_b64 = b64encode(json.dumps(req_obj).encode("utf-8"))
    enc_data_b64 = encrypt_and_mac(enc1_b64, mac1_b64, data_b64)
    enc_msg = ["encrypted-request", SessionID_b64, enc_data_b64]
    return json.dump(enc_msg).encode("utf-8")

def client_process_response(rx_b64, enc2_b64, mac2_b64):
    response_data_b64 = decrypt(enc2_b64, mac2_b64, rx_b64)
    return json.loads(b64decode(response_data_b64).decode("utf-8"))


    

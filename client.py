
import os, sys
from base64 import b64encode, b64decode
from util import (SALT_b64, KEYLEN, PBKDF2_b64, scrypt_b64, c1,c2,
                  make_keys, make_session_keys, do_SRP_setup, do_SRP,
                  encrypt_and_mac, decrypt,
                  do_network, client_create_request, client_process_response,
                  Oops
                  )

def build_PWK(password_b64, email):
    # this is local
    A_b64 = PBKDF2_b64(password_b64=password_b64,
                       salt_b64=SALT_b64("first-PBKDF",email),
                       c=c1, dkLen=KEYLEN)
    # this may be offloaded
    B_b64 = scrypt_b64(password_b64=A_b64,
                       salt_b64=SALT_b64("scrypt"), # no email here, anon++
                       dkLen=KEYLEN)
    # this is local
    merged_b64 = b64encode(b64decode(B_b64)+b64decode(password_b64))
    C_b64 = PBKDF2_b64(password_b64=merged_b64,
                       salt_b64=SALT_b64("second-PBKDF",email),
                       c=c2, dkLen=KEYLEN)
    PWK_b64, MAC_b64, SRPpw_b64 = make_keys(C_b64, SALT_b64("three-keys"))
    return (PWK_b64, MAC_b64, SRPpw_b64)

def MAGIC_SEND_SAFELY(url, secrets):
    # TODO: need something deeper. pinned SSL cert or embedded pubkey
    do_network(url, ["magic-send-safely"]+list(secrets))

def do_init(password_b64, email, db_server):
    UK_b64 = b64encode(os.urandom(2*KEYLEN))
    print "UK created:", UK_b64

    PWK_b64, MAC_b64, SRPpw_b64 = build_PWK(password_b64, email)
    SRPsalt_b64, SRPv_b64 = do_SRP_setup(SRPpw_b64, email)
    MAGIC_SEND_SAFELY(db_server, [email, SRPv_b64, SRPsalt_b64])

    WUK_b64 = encrypt_and_mac(PWK_b64, MAC_b64, UK_b64)
    SRPKsession_b64, sid_b64 = do_SRP(db_server, email, SRPpw_b64)
    enc1_b64,mac1_b64,enc2_b64,mac2_b64 = make_session_keys(SRPKsession_b64)
    req = ["set", WUK_b64]
    msg = client_create_request(req, enc1_b64, mac1_b64, sid_b64)
    rx = do_network(db_server, msg)
    resp = client_process_response(rx, enc2_b64, mac2_b64)
    if resp[0] != "ok":
        raise Oops("server reject")
    return UK_b64

def do_read(password_b64, email, db_server):
    PWK_b64, MAC_b64, SRPpw_b64 = build_PWK(password_b64, email)
    SRPKsession_b64, sid_b64 = do_SRP(db_server, email, SRPpw_b64)
    enc1_b64,mac1_b64,enc2_b64,mac2_b64 = make_session_keys(SRPKsession_b64)
    req = ["get"]
    msg = client_create_request(req, enc1_b64, mac1_b64, sid_b64)
    rx = do_network(db_server, msg)
    resp = client_process_response(rx, enc2_b64, mac2_b64)
    if resp[0] != "ok":
        raise Oops("server reject")
    WUK_b64 = resp[1]
    UK_b64 = decrypt(PWK_b64, MAC_b64, WUK_b64)
    return UK_b64


if __name__ == '__main__':
    email, password, mode = sys.argv[1:4]
    password_b64 = b64encode(password)
    db_server = "http://localhost:8066/go"

    if mode == "changepw":
        new_password = sys.argv[4]
        raise NotImplementedError
    elif mode == "init":
        do_init(password_b64, email, db_server)
        print "UK stored"
        sys.exit(0)
    elif mode == "read":
        UK_b64 = do_read(password_b64, email, db_server)
        print "UK read:", UK_b64
        sys.exit(0)
    else:
        print "unknown mode '%s'" % mode
        sys.exit(1)

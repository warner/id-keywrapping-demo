
import os, sys, json
from base64 import b64encode, b64decode
from util import (SALT_b64, KEYLEN, PBKDF2_b64, scrypt_b64, c1,c2,
                  make_keys, make_session_keys, do_SRP_setup, do_SRP,
                  encrypt_and_mac, decrypt,
                  do_network, client_create_request, client_process_response,
                  Oops, SCRYPT_PARAMS
                  )

def build_PWK(email, password_b64, scrypt_server, do_network):
    # this is local
    A_b64 = PBKDF2_b64(password_b64=password_b64,
                       salt_b64=SALT_b64("first-PBKDF",email),
                       c=c1, dkLen=KEYLEN)
    # can we do scrypt fast enough locally?
    offload_scrypt = False # XXX
    if offload_scrypt:
        N,r,p = SCRYPT_PARAMS
        msg = ["do-scrypt", A_b64, N, r, p]
        rx = do_network(scrypt_server, msg)
        ok, B_b64 = json.loads(rx.decode("utf-8"))
        if ok != "ok":
            raise Oops("scrypt server error")
    else:
        B_b64 = scrypt_b64(password_b64=A_b64,
                           salt_b64=SALT_b64("scrypt"), # no email here, anon++
                           dkLen=KEYLEN)
    # this is local
    merged_b64 = b64encode(b64decode(B_b64)+b64decode(password_b64))
    C_b64 = PBKDF2_b64(password_b64=merged_b64,
                       salt_b64=SALT_b64("second-PBKDF",email),
                       c=c2, dkLen=KEYLEN)
    keys = make_keys(C_b64, SALT_b64("three-keys"))
    return keys # (PWK_b64, MAC_b64, SRPpw_b64, accountID_b64)

def MAGIC_SEND_SAFELY(url, secrets, do_network):
    # TODO: need something deeper. pinned SSL cert or embedded pubkey
    do_network(url, ["magic-send-safely"]+list(secrets))

def do_request(SRPsession, req, do_network, db_server):
    SRPKsession_b64, sid_b64 = SRPsession
    enc1_b64,mac1_b64,enc2_b64,mac2_b64 = make_session_keys(SRPKsession_b64)
    msg = client_create_request(req, enc1_b64, mac1_b64, sid_b64)
    rx = do_network(db_server, msg)
    return client_process_response(rx, enc2_b64, mac2_b64)

def do_init(email, password_b64, db_server, do_network, scrypt_server):
    UK_b64 = b64encode(os.urandom(2*KEYLEN))
    print "UK created:", UK_b64

    keys = build_PWK(email, password_b64, scrypt_server, do_network)
    PWK_b64, MAC_b64, SRPpw_b64, accountID_b64 = keys
    SRPv_b64 = do_SRP_setup(SRPpw_b64, accountID_b64)
    MAGIC_SEND_SAFELY(db_server, [accountID_b64, SRPv_b64], do_network)

    WUK_b64 = encrypt_and_mac(PWK_b64, MAC_b64, UK_b64)
    SRPsession = do_SRP(db_server, accountID_b64, SRPpw_b64, do_network)
    resp = do_request(SRPsession, ["set", WUK_b64], do_network, db_server)
    if resp[0] != "ok":
        raise Oops("server reject")
    return UK_b64

def read(email, password_b64, db_server, do_network, scrypt_server):
    keys = build_PWK(email, password_b64, scrypt_server, do_network)
    PWK_b64, MAC_b64, SRPpw_b64, accountID_b64 = keys
    SRPsession = do_SRP(db_server, accountID_b64, SRPpw_b64, do_network)
    resp = do_request(SRPsession, ["get"], do_network, db_server)
    if resp[0] != "ok":
        raise Oops("server reject")
    WUK_b64 = resp[1]
    UK_b64 = decrypt(PWK_b64, MAC_b64, WUK_b64)
    SRPdata = (SRPpw_b64, accountID_b64)
    return UK_b64, SRPdata

def do_read(email, password_b64, db_server, do_network, scrypt_server):
    UK_b64, SRPdata = read(email, password_b64, db_server, do_network,
                           scrypt_server)
    return UK_b64

def do_change(email, old_password_b64, new_password_b64, db_server, do_network,
              scrypt_server):
    # read the old password, compute the new secrets, send a change request
    UK_b64, oldSRPdata = read(email, old_password_b64, db_server, do_network,
                              scrypt_server)
    old_SRPpw_b64, old_accountID_b64 = oldSRPdata

    keys = build_PWK(email, new_password_b64, scrypt_server, do_network)
    (new_PWK_b64, new_MAC_b64, new_SRPpw_b64, new_accountID_b64) = keys
    new_SRPv_b64 = do_SRP_setup(new_SRPpw_b64, new_accountID_b64)
    new_WUK_b64 = encrypt_and_mac(new_PWK_b64, new_MAC_b64, UK_b64)

    SRPsession = do_SRP(db_server, old_accountID_b64, old_SRPpw_b64, do_network)
    resp = do_request(SRPsession,
                      ["change", new_accountID_b64, new_SRPv_b64, new_WUK_b64],
                      do_network, db_server)
    if resp[0] != "ok":
        raise Oops("server reject")


if __name__ == '__main__':
    email, password, mode = sys.argv[1:4]
    password_b64 = b64encode(password)
    scrypt_server = "http://localhost:8067/do-scrypt"
    db_server = "http://localhost:8066/go"

    if mode == "init":
        do_init(email, password_b64, db_server, do_network, scrypt_server)
        print "UK stored"
    elif mode == "read":
        UK_b64 = do_read(email, password_b64, db_server, do_network,
                         scrypt_server)
        print "UK read:", UK_b64
    elif mode == "changepw":
        new_password = sys.argv[4]
        new_password_b64 = b64encode(new_password)
        do_change(email, password_b64, new_password_b64, db_server, do_network,
                  scrypt_server)
        print "password changed"
    else:
        print "unknown mode '%s'" % mode
        sys.exit(1)

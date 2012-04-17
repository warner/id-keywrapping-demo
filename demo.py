#!/usr/bin/python

import sys, time
from binascii import hexlify

sys.path.append("srp-1.0")
sys.path.append("PBKDF-1.0")
sys.path.append("python-scrypt/build/lib.macosx-10.6-universal-2.6")

from srp import User, Verifier, create_salted_verification_key, \
     SHA256, NG_2048
from PBKDF import PBKDF2
from scrypt import scrypt, pick_params

class Oops(Exception):
    pass

KW1 = "keywrapping-v1@identity.mozilla.com:1"
KW2 = "keywrapping-v1@identity.mozilla.com:2"
KW3 = "keywrapping-v1@identity.mozilla.com:3"
MB = 1000*1000

def netstring(s):
    return "%d:%s." % (len(s), s)
def plus(*strings):
    return "".join([netstring(s) for s in strings])

c1 = 10000
c2 = 10000
N,r,p = pick_params(maxmem=100*MB, maxtime=1.0)
dkLen = 256/8

email = "bob@example.org"
password = "password"

Tstart = time.time()
A = PBKDF2(password=password, salt=plus(KW1, email), c=c1, dkLen=dkLen)
Ta = time.time()
print "time[A]:", Ta-Tstart
B = scrypt(password=A, salt=plus(KW2, email), N=N,r=r,p=p, dkLen=256/8)
Tb = time.time()
print "time[B]:", Tb-Ta
C = PBKDF2(password=plus(password,B), salt=plus(KW3, email), c=c2, dkLen=3*dkLen)
Tc = time.time()
print "time[C]:", Tc-Tb
PWK, MAC, SRPpw = C[:dkLen], C[dkLen:2*dkLen], C[2*dkLen:3*dkLen]
SRPsalt, SRPvkey = create_salted_verification_key(email, SRPpw, hash_alg=SHA256)
Td = time.time()
print "time[D]:", Td-Tc
print "time[total]:", Td-Tstart
print

print "PWK:", hexlify(PWK)
print "MAC:", hexlify(MAC)
print "SRPpw:", hexlify(SRPpw)
print

print "SRPvkey:", hexlify(SRPvkey)
print "SRPsalt:", hexlify(SRPsalt)
sys.exit(0)

salt,vkey = create_salted_verification_key(email, password, hash_alg=SHA256)
print "vkey=%s" % vkey.encode("hex")

u = User(email, password, hash_alg=SHA256)
msg1_username, msg1_A = u.start_authentication() # (username, A)
print "u->v: I=%s, A=%s" % (msg1_username, hexlify(msg1_A))

v = Verifier(email, salt, vkey, msg1_A, hash_alg=SHA256)
s,B = v.get_challenge()
if s is None or B is None:
    raise Oops("Verifier.get_challenge() rejected A: s/B was None")
print "v->u: s=%s, B=%s" % (hexlify(s), hexlify(B))

M = u.process_challenge(s, B)
if M is None:
    raise Oops("User.process_challenge() rejected s or B: M was None")
print "u->v: M=%r" % M

HAMK = v.verify_session(M)
if HAMK is None:
    raise Oops("Verifier.verify_session() rejected M: HAMK was None")
if not v.authenticated():
    raise Oops("Verifier.authenticated() says False")
assert v.authenticated()
print "v.sesskey:", v.get_session_key().encode("hex")

u.verify_session(HAMK)
assert u.authenticated()
print "u.sesskey:",  u.get_session_key().encode("hex")


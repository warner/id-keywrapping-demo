import sys

sys.path.append("srp-1.0")

from srp import User, Verifier, create_salted_verification_key, \
     SHA256, NG_2048

email = "bob@example.org"
password = "password"
salt,vkey = create_salted_verification_key(email, password, hash_alg=SHA256)
print vkey.encode("hex")

u = User(email, password, hash_alg=SHA256)
msg1_username, msg1_A = u.start_authentication() # (username, A)

v = Verifier(email, salt, vkey, msg1_A)
s,B = v.get_challenge()
if s is None or B is None:
    raise Exception

M = u.process_challenge(s, B)
if M is None:
    raise Exception

HAMK = v.verify_session(M)
if HAMK is None:
    raise Exception
assert v.authenticated()
print v.get_session_key().encode("hex")

u.verify_session(HAMK)
assert u.authenticated()
print u.get_session_key().encode("hex")


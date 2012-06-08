
from PBKDF import PBKDF2 as old_PBKDF2
from pbkdf2 import PBKDF2 as new_PBKDF2
import os, random
from hashlib import sha1
from binascii import hexlify
def rand_string():
    return os.urandom(random.randint(0,10))
for trial in range(500):
    password = rand_string()
    salt = rand_string()
    count = random.randint(1, 100)
    dkLen = random.randint(1, 100)
    old_key = old_PBKDF2(password, salt, count, dkLen)
    new_key = new_PBKDF2(password, salt, count, dkLen, hfunc=sha1)
    assert old_key == new_key, (hexlify(old_key), hexlify(new_key))
    if trial % 10 == 0:
        print "trial", trial

# Copyright 2011 Alexey V Michurin <a.michurin@gmail.com>. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification, are
# permitted provided that the following conditions are met:
#
#    1. Redistributions of source code must retain the above copyright notice, this list of
#       conditions and the following disclaimer.
#
#    2. Redistributions in binary form must reproduce the above copyright notice, this list
#       of conditions and the following disclaimer in the documentation and/or other materials
#       provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY Alexey V Michurin ''AS IS'' AND ANY EXPRESS OR IMPLIED
# WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
# FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL Alexey V Michurin OR
# CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
# ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
# NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
# ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# The views and conclusions contained in the software and documentation are those of the
# authors and should not be interpreted as representing official policies, either expressed
# or implied, of Alexey V Michurin.

from random import randrange
try:
    from hashlib import md5 as md5_new
except ImportError:
    # for Python < 2.5
    from md5 import new as md5_new

__all__ = 'gen_salt', 'passphrase_to_salted_key_and_iv'

__doc__ = '''Tools related to key derivation service

See RFC2898 PKCS #5: Password-Based Cryptography Specification Version 2.0'''

md5 = lambda x: md5_new(x).digest()

def gen_salt(saltlen=8):
    return ''.join(map(lambda x: chr(randrange(256)), xrange(saltlen)))

def passphrase_to_salted_key_and_iv(passphrase, salt='', klen=16, ivlen=8):
    dklen = klen + ivlen
    dk = ''
    d = ''
    while len(dk) < dklen:
        d = md5(d + passphrase + salt)
        dk += d
    return (dk[:klen], dk[klen:dklen])

if __name__ == '__main__':
    from testutil import ok, qrepr
    a = '\x09\x8f\x6b\xcd\x46\x21\xd3\x73\xca\xde\x4e\x83\x26\x27\xb4\xf6'
    b = md5('test')
    print qrepr(b), ok(a == b)

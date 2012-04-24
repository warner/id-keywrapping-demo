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


from key import gen_salt
from shortcuts import \
    enc_bf_ecb, dec_bf_ecb, \
    enc_bf_cbc, dec_bf_cbc, \
    enc_aes_ecb, dec_aes_ecb, \
    enc_aes_cbc, dec_aes_cbc


__all__ = ('openssl_enc_bf_ecb', 'openssl_dec_bf_ecb',
           'openssl_enc_bf_cbc', 'openssl_dec_bf_cbc',
           'openssl_enc_aes_128_ecb', 'openssl_dec_aes_128_ecb',
           'openssl_enc_aes_192_ecb', 'openssl_dec_aes_192_ecb',
           'openssl_enc_aes_256_ecb', 'openssl_dec_aes_256_ecb',
           'openssl_enc_aes_128_cbc', 'openssl_dec_aes_128_cbc',
           'openssl_enc_aes_192_cbc', 'openssl_dec_aes_192_cbc',
           'openssl_enc_aes_256_cbc', 'openssl_dec_aes_256_cbc')

__doc__ = '''OpenSSL-compat leyer

Note: this module provides only operation supported by openssl(1).
I.e. PCBC and various length keys for Blowfish are not provided
by this module.

All functions arguments and names are similar to command line
options of openssl(1).

For example
openssl_enc_aes_128_cbc('passphrase', 'text', True)
is the same as
echo -n 'text' | openssl enc -aes-128-cbc -salt -pass pass:passphrase
and
openssl_dec_bf_cbc('passphrase', open('encrypted', 'r').read())
is the same as
cat encrypted | openssl dec -bf-cbc -pass pass:passphrase
'''


def enc_header(salted, salt):
    if salted:
        if salt is None:
            salt = gen_salt(8)
        return 'Salted__' + salt, salt
    return '', ''

def dec_header(cipher):
    if cipher[:8] == 'Salted__':
        return cipher[8:16], cipher[16:]
    return '', cipher


def openssl_enc_bf_ecb(passphrase, text, salted=True, salt=None):
    header, salt = enc_header(salted, salt)
    return header + enc_bf_ecb(text, salt, passphrase, 16)

def openssl_dec_bf_ecb(passphrase, cipher):
    salt, c = dec_header(cipher)
    return dec_bf_ecb(c, salt, passphrase, 16)

def openssl_enc_bf_cbc(passphrase, text, salted=True, salt=None):
    header, salt = enc_header(salted, salt)
    return header + enc_bf_cbc(text, salt, passphrase, 16)

def openssl_dec_bf_cbc(passphrase, cipher):
    salt, c = dec_header(cipher)
    return dec_bf_cbc(c, salt, passphrase, 16)

def openssl_enc_aes_128_ecb(passphrase, text, salted=True, salt=None):
    header, salt = enc_header(salted, salt)
    return header + enc_aes_ecb(text, salt, passphrase, 16)

def openssl_dec_aes_128_ecb(passphrase, cipher):
    salt, c = dec_header(cipher)
    return dec_aes_ecb(c, salt, passphrase, 16)

def openssl_enc_aes_192_ecb(passphrase, text, salted=True, salt=None):
    header, salt = enc_header(salted, salt)
    return header + enc_aes_ecb(text, salt, passphrase, 24)

def openssl_dec_aes_192_ecb(passphrase, cipher):
    salt, c = dec_header(cipher)
    return dec_aes_ecb(c, salt, passphrase, 24)

def openssl_enc_aes_256_ecb(passphrase, text, salted=True, salt=None):
    header, salt = enc_header(salted, salt)
    return header + enc_aes_ecb(text, salt, passphrase, 32)

def openssl_dec_aes_256_ecb(passphrase, cipher):
    salt, c = dec_header(cipher)
    return dec_aes_ecb(c, salt, passphrase, 32)

def openssl_enc_aes_128_cbc(passphrase, text, salted=True, salt=None):
    header, salt = enc_header(salted, salt)
    return header + enc_aes_cbc(text, salt, passphrase, 16)

def openssl_dec_aes_128_cbc(passphrase, cipher):
    salt, c = dec_header(cipher)
    return dec_aes_cbc(c, salt, passphrase, 16)

def openssl_enc_aes_192_cbc(passphrase, text, salted=True, salt=None):
    header, salt = enc_header(salted, salt)
    return header + enc_aes_cbc(text, salt, passphrase, 24)

def openssl_dec_aes_192_cbc(passphrase, cipher):
    salt, c = dec_header(cipher)
    return dec_aes_cbc(c, salt, passphrase, 24)

def openssl_enc_aes_256_cbc(passphrase, text, salted=True, salt=None):
    header, salt = enc_header(salted, salt)
    return header + enc_aes_cbc(text, salt, passphrase, 32)

def openssl_dec_aes_256_cbc(passphrase, cipher):
    salt, c = dec_header(cipher)
    return dec_aes_cbc(c, salt, passphrase, 32)


if __name__ == '__main__':
    from testutil import qrepr, ok, pad
    text = 'Red leather, Yellow leather.'
    passphrase = 'Aluminum, linoleum.'
    for rem, enc_op, dec_op, salted, ref_cipher in (
('openssl -bf-ecb -salt', openssl_enc_bf_ecb, openssl_dec_bf_ecb, True, 'Salted__\x5dbEzK\xe2\x60\x96E\x25\xbc\x5b\x28\xc9\xccY\xf7\xcf\xdaE\x0f\xcf\xba\xbd\xf2\xd2\x91\xb3\x5e\xba\x2f\x1c\xc9\x2f\xe2e\xf6\x8c\xfb\xd8'),
('openssl -bf-ecb -nosalt', openssl_enc_bf_ecb, openssl_dec_bf_ecb, False, '\x06Z\x98oaQ\x3c\x86\xd0\x96\x23v\x8d\xef\xe1\xdb\x0a\x14\x08\x80\x09\x3f\xe0\xf8\xaa\x17\xdb\x2b\x90\xe3Y\x5d'),
('openssl -bf-cbc -salt', openssl_enc_bf_cbc, openssl_dec_bf_cbc, True, 'Salted__\xee\x88\xe9\x01\x05Z\x0e\xa9\xb0\xc7\xb3\x24\x2dM\x92t0\x8d2\x2d\x2ft\x7fh\x14\xb0\x02\xb5\x97\x86\xda\xc5O\x5c1A\xe6\xef\xf6\x18'),
('openssl -bf-cbc -nosalt', openssl_enc_bf_cbc, openssl_dec_bf_cbc, False, 'g\xec\x11\xc2\x28\xd4\xb5W\xd6\x14W\xc1\x0bT\x20TP\xcaa\xb0\x96D\x05\xd2\xe5\xbe\xe6i\xb4\x06\xf6\xa1'),
('openssl -aes-128-ecb -salt', openssl_enc_aes_128_ecb, openssl_dec_aes_128_ecb, True, 'Salted__\x28\xa1\x2e\x80\xa3\x84\xd3\x1f_\xdf7\x97\xbc4\x60P\x03\xb3l\x13\x9f\x25A\xbd\xa2C\x23M\x24S\xac\x2c\x25k\xc7c\xfd\xdaoD'),
('openssl -aes-128-ecb -nosalt', openssl_enc_aes_128_ecb, openssl_dec_aes_128_ecb, False, '\xb2\x5e\x0fO\xc4\xfd\xae\x8f\x99\xa8\x18\x93\x83\xd2\x3a\x9b\x9a3\x98\xcbk\xdc\x195\xc85\x2d\xab\xb6U\x9f\xd5'),
('openssl -aes-192-ecb -salt', openssl_enc_aes_192_ecb, openssl_dec_aes_192_ecb, True, 'Salted__\xba\x0a\xad\x0f\xb1\xac\x9eT\xa3\xe8\x19\xc7P\xfdaY\x3b\xd9\x95\xb0I\x2eZ8\x40y\xa3\x0b\x3e\x0dn\xf6\xa9Y6J\xac\x5d\x9e\x17'),
('openssl -aes-192-ecb -nosalt', openssl_enc_aes_192_ecb, openssl_dec_aes_192_ecb, False, '\xd7\xac\x2a\x21\x84\x94O\xa3\xb7\x90\xcbj\xfb\xa8\xa0\x3d\x11\xb1\x10\x23\xd4\x2c\xebu4\x3e\xe4\xddO\x12b\x27'),
('openssl -aes-256-ecb -salt', openssl_enc_aes_256_ecb, openssl_dec_aes_256_ecb, True, 'Salted__\x27_\xf1\xdf\xd3\x3d5\xe3M6\x1e\x92c\xf9\x98Z4\xd30\xca\xa5q\x15\xb4\xb5\xd27\xef\xd0\x2a\xf7\x3f\xb0\xd2\xd4\x9fW\xea\x3e\x0e'),
('openssl -aes-256-ecb -nosalt', openssl_enc_aes_256_ecb, openssl_dec_aes_256_ecb, False, '\xce\xac6\xc4\xed\xcf\x98\xfa\x91o\x8b\x20\xd0e\xd4x\x8ek5\xc3\xe7\x16\x5c\xa2\xb5Y\xc7\x89\x0f_\x07\xff'),
('openssl -aes-128-cbc -salt', openssl_enc_aes_128_cbc, openssl_dec_aes_128_cbc, True, 'Salted__\x2dd\x22\xdd\x7d\x93\xdc\xa6\xcbj\x9cu\x2d\xa0\xb2\x26\x5d\xf9\x3b\x8d\xb4s7\x92a\xd1\x98\x9e\x04Pmo\x16\x0a\xd2\x14\x92\xb0l\x2e'),
('openssl -aes-128-cbc -nosalt', openssl_enc_aes_128_cbc, openssl_dec_aes_128_cbc, False, '\x04Us\x99\xbc\x0f\xaf\xdb\xeb\xd9\x91\xf1\x3c\x0dr3\xf9\xa8\xe7i\x3fF\xf7M\x236\xa6\xc3XJ\x87\xda'),
('openssl -aes-192-cbc -salt', openssl_enc_aes_192_cbc, openssl_dec_aes_192_cbc, True, 'Salted__\xb0t\x95\xc1\x8e\xe8\xcdr\x03\x1e\x9d\x1afJx\xa0\xdcU\x0ap\xf0\xd0\xe96\x8aoJ\x17\xe5\x8a\x81\xc7\x5e\xb3\xcd\xd8\xe0\xfe\x90S'),
('openssl -aes-192-cbc -nosalt', openssl_enc_aes_192_cbc, openssl_dec_aes_192_cbc, False, '\xc5\xbaF\xecm\xea\x00\xc4\x1bv\x01\xec\x99\x9c\x81\xe2\xd7\x1d\xe8\x3e\x17\xf3\x89\x90\xbf\x5b\x0b\x98Q\x00\x40G'),
('openssl -aes-256-cbc -salt', openssl_enc_aes_256_cbc, openssl_dec_aes_256_cbc, True, 'Salted__5\x5b\x0a\xe8M\xc9\xf8\xc7K\xbe\xfe\x84\x9cK\xc2\x08\xdd\x2c\x9e\xfe\xb5\xcd\x1b\x11\x201\xb95C\x0a\xaa\xd9N\x0b\x01n\xb2\xa5\x18W'),
('openssl -aes-256-cbc -nosalt', openssl_enc_aes_256_cbc, openssl_dec_aes_256_cbc, False, '\xe1\xd7cS\xe5\x60\x1a\x27\xb8\xbce\x2f\xfa\x06\xdc\x17\xef\x26\x91\x83\x3afG\x87\xb4\x9d\x0b5\xf7s\x9c\x02'),
    ):
        if salted:
            salt = ref_cipher[8:16]
        else:
            salt = None
        e = enc_op(passphrase, text, salted, salt)
#        print repr(e)
#        print repr(ref_cipher)
        test_enc = ok(e == ref_cipher)
        t = dec_op(passphrase, e)
#        print repr(t)
#        print repr(text)
        test_dec = ok(t == text)
        # random salt
        t = dec_op(passphrase, enc_op(passphrase, text))
        test_rand = ok(t == text)
        print pad(rem, 50), \
              'enc:', test_enc, \
              'dec:', test_dec, \
              'rand_salt:', test_enc
    __how_to_preapre_test_vectors__=r'''
#!/bin/sh

data='Red leather, Yellow leather.'
pass='Aluminum, linoleum.'

echo "data = '$data'"
echo "password = '$pass'"
for mode in -bf-ecb -bf-cbc \
            -aes-128-ecb -aes-192-ecb -aes-256-ecb \
            -aes-128-cbc -aes-192-cbc -aes-256-cbc
do
  for saltmode in -salt -nosalt
  do
    cryp=`echo -n "$data" | openssl enc "$mode" "$saltmode" -pass "pass:$pass" -
    perl -MMIME::Base64 -pe '$_=decode_base64($_);s-([^\w\d_])-sprintf(q|\x%02X|
    enc=`echo "$mode" | perl -pe 's|-|_|g;s-^-openssl_enc-;'`
    dec=`echo "$mode" | perl -pe 's|-|_|g;s-^-openssl_dec-;'`
    salted='False'
    if test "_$saltmode" = '_-salt'
    then
        salted='True'
    fi
    echo "('openssl $mode $saltmode', $enc, $dec, $salted, '$cryp'),"
  done
done
'''

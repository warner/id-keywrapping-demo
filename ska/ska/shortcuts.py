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


from bf import blowfish
from aes import aes
from mode import dec_ecb, enc_ecb, dec_cbc, enc_cbc, dec_pcbc, enc_pcbc
from pad import pkcs5_pad, pkcs5_unpad, pkcs7_pad, pkcs7_unpad
from key import passphrase_to_salted_key_and_iv


__all__ = ('enc_bf_ecb', 'dec_bf_ecb',
           'enc_bf_cbc', 'dec_bf_cbc',
           'enc_bf_pcbc', 'dec_bf_pcbc',
           'enc_aes_ecb', 'dec_aes_ecb',
           'enc_aes_cbc', 'dec_aes_cbc',
           'enc_aes_pcbc', 'dec_aes_pcbc')

__doc__ = '''Convenience functions'''


def enc_bf_ecb(text, salt, passphrase, keylen=56):
    key, iv = passphrase_to_salted_key_and_iv(passphrase, salt, keylen, 0)
    return enc_ecb(blowfish(key), 8)(pkcs5_pad(text))

def dec_bf_ecb(crypted, salt, passphrase, keylen=56):
    key, iv = passphrase_to_salted_key_and_iv(passphrase, salt, keylen, 0)
    return pkcs5_unpad(dec_ecb(blowfish(key), 8)(crypted))

def enc_bf_cbc(text, salt, passphrase, keylen=56):
    key, iv = passphrase_to_salted_key_and_iv(passphrase, salt, keylen, 8)
    return enc_cbc(blowfish(key), iv)(pkcs5_pad(text))

def dec_bf_cbc(crypted, salt, passphrase, keylen=56):
    key, iv = passphrase_to_salted_key_and_iv(passphrase, salt, keylen, 8)
    return pkcs5_unpad(dec_cbc(blowfish(key), iv)(crypted))

def enc_bf_pcbc(text, salt, passphrase, keylen=56):
    key, iv = passphrase_to_salted_key_and_iv(passphrase, salt, keylen, 8)
    return enc_pcbc(blowfish(key), iv)(pkcs5_pad(text))

def dec_bf_pcbc(crypted, salt, passphrase, keylen=56):
    key, iv = passphrase_to_salted_key_and_iv(passphrase, salt, keylen, 8)
    return pkcs5_unpad(dec_pcbc(blowfish(key), iv)(crypted))


def enc_aes_ecb(text, salt, passphrase, keylen=32):
    key, iv = passphrase_to_salted_key_and_iv(passphrase, salt, keylen, 0)
    return enc_ecb(aes(key), 16)(pkcs7_pad(text))

def dec_aes_ecb(crypted, salt, passphrase, keylen=32):
    key, iv = passphrase_to_salted_key_and_iv(passphrase, salt, keylen, 0)
    return pkcs7_unpad(dec_ecb(aes(key), 16)(crypted))

def enc_aes_cbc(text, salt, passphrase, keylen=32):
    key, iv = passphrase_to_salted_key_and_iv(passphrase, salt, keylen, 16)
    return enc_cbc(aes(key), iv)(pkcs7_pad(text))

def dec_aes_cbc(crypted, salt, passphrase, keylen=32):
    key, iv = passphrase_to_salted_key_and_iv(passphrase, salt, keylen, 16)
    return pkcs7_unpad(dec_cbc(aes(key), iv)(crypted))

def enc_aes_pcbc(text, salt, passphrase, keylen=32):
    key, iv = passphrase_to_salted_key_and_iv(passphrase, salt, keylen, 16)
    return enc_pcbc(aes(key), iv)(pkcs7_pad(text))

def dec_aes_pcbc(crypted, salt, passphrase, keylen=32):
    key, iv = passphrase_to_salted_key_and_iv(passphrase, salt, keylen, 16)
    return pkcs7_unpad(dec_pcbc(aes(key), iv)(crypted))


if __name__ == '__main__':
    from testutil import qrepr, ok, pad
    text = 'Red leather, Yellow leather.'
    passphrase = 'Aluminum, linoleum.'
    for rem, enc_op, dec_op, klen, salt, ref_cryp in (
('openssl -bf-ecb -salt', enc_bf_ecb, dec_bf_ecb, 16, '\x89\xa0\x9c\x14V\x280\xb8', '\xa8\x98\xa3\x27\xe3\xbc\x0e\xd4\x86\x5c\x02z\x7f\x90\x97\x97\xc7\x10\xa8\xd5\x92\xeb_\xd7Y\xc5m\xf5\x5cO\x23\xe3'),
('openssl -bf-ecb -nosalt', enc_bf_ecb, dec_bf_ecb, 16, '', '\x06Z\x98oaQ\x3c\x86\xd0\x96\x23v\x8d\xef\xe1\xdb\x0a\x14\x08\x80\x09\x3f\xe0\xf8\xaa\x17\xdb\x2b\x90\xe3Y\x5d'),
('openssl -bf-cbc -salt', enc_bf_cbc, dec_bf_cbc, 16, 'r\xd5\xf3\x80\x8b\xd8\xaf\x11', '\x14\xf64\x89sd\x03P\x0e\xa2\xd0l\xd3\xe8\x2f\x9c\xe8\x3b\xcchE\xf4\xe0\xa3\x86\xe7\x0a\x8ek\x13\xe46'),
('openssl -bf-cbc -nosalt', enc_bf_cbc, dec_bf_cbc, 16, '', 'g\xec\x11\xc2\x28\xd4\xb5W\xd6\x14W\xc1\x0bT\x20TP\xcaa\xb0\x96D\x05\xd2\xe5\xbe\xe6i\xb4\x06\xf6\xa1'),
('openssl -aes-128-ecb -salt', enc_aes_ecb, dec_aes_ecb, 16, '\x0c\x25\xa7\xc5\x27\xe4\x97y', '\x7d\x0f\xbd\x26\x3a\xcd\xa4mD\xc8eQ\x7c\xbf\x7f\xb2\xa050\xfc\x8a\x85\xe87\x04\xfc\x29\xe9\x2c\xeaW\xc8'),
('openssl -aes-128-ecb -nosalt', enc_aes_ecb, dec_aes_ecb, 16, '', '\xb2\x5e\x0fO\xc4\xfd\xae\x8f\x99\xa8\x18\x93\x83\xd2\x3a\x9b\x9a3\x98\xcbk\xdc\x195\xc85\x2d\xab\xb6U\x9f\xd5'),
('openssl -aes-192-ecb -salt', enc_aes_ecb, dec_aes_ecb, 24, 'T\x7b\x9f\xc7g\x03\x24\xcf', 'n\x18\x87\x2d\xff\x22\xb0\x8b\xe9\xd5\xe6\x01\xa1\x000\xd9\x8e\x8cM\x8bLm\xae\x18\x22\xbd\x0c\xe4\x2a\xe3B\x8c'),
('openssl -aes-192-ecb -nosalt', enc_aes_ecb, dec_aes_ecb, 24, '', '\xd7\xac\x2a\x21\x84\x94O\xa3\xb7\x90\xcbj\xfb\xa8\xa0\x3d\x11\xb1\x10\x23\xd4\x2c\xebu4\x3e\xe4\xddO\x12b\x27'),
('openssl -aes-256-ecb -salt', enc_aes_ecb, dec_aes_ecb, 32, '\x2e\xe8\x10E\x953\xeeU', 'l\xce\xa97\xdbO\xe4\xbc\x3a\x19\x13\x01R6\x2e\xa0D\x974\xd0\xe1\x10\xf6\x3c\xcb\x7c\xcdM\x1d\x7d8\xda'),
('openssl -aes-256-ecb -nosalt', enc_aes_ecb, dec_aes_ecb, 32, '', '\xce\xac6\xc4\xed\xcf\x98\xfa\x91o\x8b\x20\xd0e\xd4x\x8ek5\xc3\xe7\x16\x5c\xa2\xb5Y\xc7\x89\x0f_\x07\xff'),
('openssl -aes-128-cbc -salt', enc_aes_cbc, dec_aes_cbc, 16, '5k\xe5\x80\x9a\xf0\x04\x8a', '\xe8\x018\xae\x3fV\x06\xac\xd1\x1a\x3cf\xd2\xcfwu\x06C\x89\x7f5l\xe0\xaf\x84O\x2c\x3a\x8d\xdc\x7e3'),
('openssl -aes-128-cbc -nosalt', enc_aes_cbc, dec_aes_cbc, 16, '', '\x04Us\x99\xbc\x0f\xaf\xdb\xeb\xd9\x91\xf1\x3c\x0dr3\xf9\xa8\xe7i\x3fF\xf7M\x236\xa6\xc3XJ\x87\xda'),
('openssl -aes-192-cbc -salt', enc_aes_cbc, dec_aes_cbc, 24, '\xf7Z\x1eS\xf2\xb0\xc5\x8d', 'N3\xad\x0cp\x27\xcf\x18E\x07\xc6\xd7\x3c\xfc\x96\x8cc\x03\x3c\x9f\xf8\x2cj\xa6\xdd\xe5\xe8\xb5B\x15\xb5\x7b'),
('openssl -aes-192-cbc -nosalt', enc_aes_cbc, dec_aes_cbc, 24, '', '\xc5\xbaF\xecm\xea\x00\xc4\x1bv\x01\xec\x99\x9c\x81\xe2\xd7\x1d\xe8\x3e\x17\xf3\x89\x90\xbf\x5b\x0b\x98Q\x00\x40G'),
('openssl -aes-256-cbc -salt', enc_aes_cbc, dec_aes_cbc, 32, 'td\xe4\x10gJk\x0b', '\xec\x235v\x90\x90\xe8\x05\x95g\x8a\xb4\xba\xec\x8a\xb6\x00s\x14\x7bI\xaa\x80b\xc8\xf1\x0fL\x0f\x01\xb7\xd6'),
('openssl -aes-256-cbc -nosalt', enc_aes_cbc, dec_aes_cbc, 32, '', '\xe1\xd7cS\xe5\x60\x1a\x27\xb8\xbce\x2f\xfa\x06\xdc\x17\xef\x26\x91\x83\x3afG\x87\xb4\x9d\x0b5\xf7s\x9c\x02'),

('Perl CBC/Blowfish/salt klen=16 (=openssl)', enc_bf_cbc, dec_bf_cbc, 16, 'E\xbdteO\x87z\x5e', '\xa3\x29\xf7\x2by\xf6\xb9iKt\xe7\xf0z\xcc\xccU\x00\xec\x27\xe9\xc1\x20\xf3\x85\x00\xd9\x80\x88\xcf\x2e\x94\xe6'),
('Perl CBC/Blowfish/salt klen=32', enc_bf_cbc, dec_bf_cbc, 32, '\xe2\xe2\x94k\xa4f\x23\xe4', '\xe7\xe1c\xecm\xb1\x7e\x24\x23\xdc\xae\xfb\x83\xf29j\x9a\x1eB\xcb\xec\x91\xac\x1c\x0e\xb0\x1d\x94\x22\xc4\x7f6'),
('Perl CBC/Blowfish/salt klen=48', enc_bf_cbc, dec_bf_cbc, 48, '\xd8\xbf\x03\x8a\x09O\xe5\x40', '\xddX\x27\x11Yc5\x05\x06\xe2\x145\x13cy\x01y\xfb\x0d\xbcN\xaf\x9b\xb3rP\xcdy\xde\x91C7'),
('Perl CBC/Blowfish/salt klen=56', enc_bf_cbc, dec_bf_cbc, 56, '\x96\xda\xe8\x2f\x23\xdd\x01l', '\xa1\xbdY\xc6\x99\xbc\x7dO\xc7e\x95\x96\x12\xe6\x9e\x40\x08\x927\xf4\xfa\xc1\xdc\x60\xbb\xae\xd7\x07\x25\x80Q\x8d'),
('Perl PCBC/Blowfish/salt klen=16', enc_bf_pcbc, dec_bf_pcbc, 16, '\xe1\x99\xdf\x8d\xeb\xcd\xf3r', '\x05X\x16\xfa\x8f\xbf\x3b\x0f\xbc\xfb\x88\xc3L\xa3\x98\x85\xfd\xf0\x9b\x29oH\xf0\x93\x9c\xb7a\xef\x2b\xfeF\x0d'),
('Perl PCBC/Blowfish/salt klen=32', enc_bf_pcbc, dec_bf_pcbc, 32, '\x11\xa3\x9b\x9b\xe1\x7e\xc7\xb5', 'CH\xda0\xeb\x04\xc9\x8el\x99\xd4\x3c\x21\xbdW4q\xd5w\xf2\xaa\x0a\xe3\x3e\x11\xc3\xa8i\xa6\x7c\xdc\xcd'),
('Perl PCBC/Blowfish/salt klen=48', enc_bf_pcbc, dec_bf_pcbc, 48, '\x94\x1b\x87\x0a\xfc\xaa\xdd\x90', 'K\xd2\x0c\x1a\xd4\x21\xbf\x3f\x1f\x11\xcc\x12aM\x7b\x8a\xa13\x0fE\xd94\xf9\xd4\x2e\x3c\x2d2\xe6\x2b\x2d\x7c'),
('Perl PCBC/Blowfish/salt klen=56', enc_bf_pcbc, dec_bf_pcbc, 56, '\x89\x97\xd7\xa6\x12i\x2b7', '\xd1\x04\xd8\xdbW\xb4\xf2tM\x24\x07\x85\x12q\xf7\xf2P\xf8\x91\xb4\x25T\xae\x93gD\x07\x17\x8e\xa3\x17\xf9'),

('Self ECB/Blowfish/salt klen=16 (=openssl)', enc_bf_ecb, dec_bf_ecb, 16, 'X\x8a\xb1\xc6\xdf\x97\x03\xe8', 'l\xf8{)\x84\x1bKm\xde\xef:B~\x95\x0e3I\x9d\x03\x90\x00y\xf4\xdc]\xf45\x9a\xf4~p\xf2'),
('Self ECB/Blowfish/nosalt klen=16 (=openssl)', enc_bf_ecb, dec_bf_ecb, 16, '', '\x06Z\x98oaQ<\x86\xd0\x96#v\x8d\xef\xe1\xdb\n\x14\x08\x80\t?\xe0\xf8\xaa\x17\xdb+\x90\xe3Y]'),
('Self ECB/Blowfish/salt klen=32', enc_bf_ecb, dec_bf_ecb, 32, '\xf0m\x0f?\x04\xbagr', '\xdb\xe0\xbb\xf3\xd7x\xc0\x9f\xcb\x8c \xa6-\x87\xb7i\x10\xc3\xca\xc3\x89\x85H\xc3\x0ek\xc21\x8cg\xf0\x02'),
('Self ECB/Blowfish/nosalt klen=32', enc_bf_ecb, dec_bf_ecb, 32, '', '\xf0\xf0\xf5\xd1tub&P\xd8\x00\xda\xef>\xdb\xbdZG\xaf\x15\xf1{$\x9e\x82\x9dfhd[\x1f\xba'),
('Self ECB/Blowfish/salt klen=48', enc_bf_ecb, dec_bf_ecb, 48, '\xc2"\xcd\xba\x1c\x07\xe5F', '\xb4\xfa?M!\t\xfc.\xaa\xb7\xf3qEL1\x1b\x1fb&\xa5\x8a)\xef\x02\xdb\xeaz\xfe\xf1\xb7\x8b\xc4'),
('Self ECB/Blowfish/nosalt klen=48', enc_bf_ecb, dec_bf_ecb, 48, '', 'E\x0c\xbdc\x8c\xde\xc5V\xe4\x9d\xf3Ew\xabO|\xaf\xa0N4\x0e\x0e\x19?)\xf5\x81~\xbcj\xac\x99'),
('Self ECB/Blowfish/salt klen=56', enc_bf_ecb, dec_bf_ecb, 56, '\xcc\x03{\x8b\xd47!\x91', '\xd8\xc8h7R\xbb\'\xda\x18+(\x81{\x9c\xb9\x93\x8e\x8eX"\xb0\x96\xf4\xd1\xfbt\n\xf6\xaf\xdc\xd3\x0b'),
('Self ECB/Blowfish/nosalt klen=56', enc_bf_ecb, dec_bf_ecb, 56, '', '\xea\x15\xa8\xb9\xa6\x9a}\x8d\xc9\xfb\x99\xcc\xafc"\xdd\t\xdd+\xc0\xdfl\xdb\xd6\xc0y\xf7_\xc1\x0f\xd3\xee'),
('Self CBC/Blowfish/salt klen=16 (=perl)', enc_bf_cbc, dec_bf_cbc, 16, '\xebi\xc3,\xb7\xb3:\xa3', '\x89\x83\x97|2\x1cj\xd9\xeb\xd7\x93\x86\xdb\xad\x7f\xff\x1f\xbf~\xe9\n_\xac\x18u?iU\x0c\x89\x15\x1c'),
('Self CBC/Blowfish/nosalt klen=16', enc_bf_cbc, dec_bf_cbc, 16, '', 'g\xec\x11\xc2(\xd4\xb5W\xd6\x14W\xc1\x0bT TP\xcaa\xb0\x96D\x05\xd2\xe5\xbe\xe6i\xb4\x06\xf6\xa1'),
('Self CBC/Blowfish/salt klen=32 (=perl)', enc_bf_cbc, dec_bf_cbc, 32, '\xee\xb6x\x05i\xa8<\t', "|\x152\xd3\xe3~\x98\x8bH\xd2I\xb7\xe9\r\xd9P*\x12G\xc1\x9f\xf2\x16\xfa3'\x93S\xa7\xcb\xc1\x0b"),
('Self CBC/Blowfish/nosalt klen=32', enc_bf_cbc, dec_bf_cbc, 32, '', 'kkm\x87"\xb9{_\xa4\xc6)x\xd5\xa2O\xb1\xf2\xb9\x8f\x03\xd2\x82M\xbc\xcbO@\x88y\x8a\xc3\x1e'),
('Self CBC/Blowfish/salt klen=48 (=perl)', enc_bf_cbc, dec_bf_cbc, 48, 'K\x0fkl\x1bzV\xc7', '=\x03\xacn\xc4\x7f\xa7C\x1bO\x81\x14\xd7\xbb~\n\x16\xa1\xc7B\x1d\xbarL\x1c\xea\xa4F\x8c/h\xf5'),
('Self CBC/Blowfish/nosalt klen=48', enc_bf_cbc, dec_bf_cbc, 48, '', 'g\xaf{\x0c\x1f\xdf\xeb_&LrJY\xbbL\xce\x98\xdf\x02\xcc\x15\x1d`-B\xc2\xca5\x16<\x0f\xa0'),
('Self CBC/Blowfish/salt klen=56 (=perl)', enc_bf_cbc, dec_bf_cbc, 56, '!+\x10\xd5E\x10\xe2\xcc', '\xa0\x92\xde\xed\xdc[\xca\x1e\xc1\x9e\xd8\xf7I\xafW5\x94\xf5b\xddD2"\x1d\xc0\x18\xabT\xc7`|\xf4'),
('Self CBC/Blowfish/nosalt klen=56', enc_bf_cbc, dec_bf_cbc, 56, '', '#\xe8\'(\xd8\x01\x05\xd1\xa1u\x1f\xef\xad\x10\x1a_\xa4#"\xaf\x9d\xa1G\xe9\x91t\xef\x8e\xf03\xc8\xa3'),
('Self PCBC/Blowfish/salt klen=16 (=perl)', enc_bf_pcbc, dec_bf_pcbc, 16, '_/\x95I%VU\x9b', "\xb6r2R\xfcT\x80\x10\xed\x8b\xff\xa0\xf5\xcf\x11\x8b\x9c\x06\xd1XZ~\xa6\xe95\x93]~p\xa6'\x81"),
('Self PCBC/Blowfish/nosalt klen=16', enc_bf_pcbc, dec_bf_pcbc, 16, '', 'g\xec\x11\xc2(\xd4\xb5W\x80\xc8\xc7\xdc8\xa3.^\xf7?\x87\x9dC\xcf\x85c\x8b\xce\x12\x8a?#E"'),
('Self PCBC/Blowfish/salt klen=32 (=perl)', enc_bf_pcbc, dec_bf_pcbc, 32, '2,Y\x1d\xd0`y<', '\x1e\xca\xe8B\xa6\x82n\x1e\x90\x06L\xc21\xdbA\x05\xa2\x8b\xcbH\x0e\xa4Y\xf0\xc1\x81-\xf4lJ\xb0\x88'),
('Self PCBC/Blowfish/nosalt klen=32', enc_bf_pcbc, dec_bf_pcbc, 32, '', 'kkm\x87"\xb9{_\x06\x99\x15\xa8\x90m@uyo\xa5\xea\xcb"\xb5j\xfd\x9d\xaf\x9d \xfb\xa4\xd1'),
('Self PCBC/Blowfish/salt klen=48 (=perl)', enc_bf_pcbc, dec_bf_pcbc, 48, '9m\xa3\x7f\xb5N\x9b\x03', 'B\x9dm\xfa\xe0cr\xef\xdb\xe4\x06\x03\n\xb9\x0f\xdfn^\xbd\xb7j\x96\xed\x932R\xa5\xebg[ \xa8'),
('Self PCBC/Blowfish/nosalt klen=48', enc_bf_pcbc, dec_bf_pcbc, 48, '', 'g\xaf{\x0c\x1f\xdf\xeb_P=\x11\xdb\xf0\x03#\xfd\xc6I\xea\xa9g\xa5\x0e\xa9\xa3\xb6\r\xdb\x1d\x0em\x9e'),
('Self PCBC/Blowfish/salt klen=56 (=perl)', enc_bf_pcbc, dec_bf_pcbc, 56, '\x88\x90\xcdJ\r\\Z]', '\x03\x8c%\x83\xdd\x0f\x18^\xb0\x89\x96d-\xac\xb6\xf1\x1b\x0b\x87\x04\xac\x02\x06BzV\xab\xfe%\x1ao.'),
('Self PCBC/Blowfish/nosalt klen=56', enc_bf_pcbc, dec_bf_pcbc, 56, '', "#\xe8'(\xd8\x01\x05\xd1\xa5g\xe1\x9eU\x07\x18\xa4\x97\x1d\xe1rg1\xfe\xbb\x96\xc2\xa0J\xe1\x01K\x17"),

('Self ECB/AES/salt klen=16 (=openssl)', enc_aes_ecb, dec_aes_ecb, 16, '\xc9\xef8\xb8B\x97\xa7*', '\xf8\xdav\xbal\xf4\xcdN\xe8\x02\x15u\xf17\x80(y,\xc1\xb5\xa6j\x82\x072;\xdd\x90e\x98|\xb5'),
('Self ECB/AES/nosalt klen=16 (=openssl)', enc_aes_ecb, dec_aes_ecb, 16, '', '\xb2^\x0fO\xc4\xfd\xae\x8f\x99\xa8\x18\x93\x83\xd2:\x9b\x9a3\x98\xcbk\xdc\x195\xc85-\xab\xb6U\x9f\xd5'),
('Self ECB/AES/salt klen=24 (=openssl)', enc_aes_ecb, dec_aes_ecb, 24, 'Te\xe6\xcd\xb9\x92:\xd2', '\xac\x01Kg\xa0u\x92\xc3\xb1\x9f\x06\x9f \xa7\xc2\x8c\x0f\xd5\xe88\x90\x95\x10\xdej6\x96D\x9aFU\xd2'),
('Self ECB/AES/nosalt klen=24 (=openssl)', enc_aes_ecb, dec_aes_ecb, 24, '', "\xd7\xac*!\x84\x94O\xa3\xb7\x90\xcbj\xfb\xa8\xa0=\x11\xb1\x10#\xd4,\xebu4>\xe4\xddO\x12b'"),
('Self ECB/AES/salt klen=32 (=openssl)', enc_aes_ecb, dec_aes_ecb, 32, '\xf8\xed\xf7R\xdc\x89\xff\xab', '\xe1\x07\x85\x05\x04\xd9\xb7L\xa5\xfaq\x19\xe0\xf0\xc5W\x95!\xb9\xdbd\xa8\xc66\x1e\x1c\xb6\xc4\xd6u/\xba'),
('Self ECB/AES/nosalt klen=32 (=openssl)', enc_aes_ecb, dec_aes_ecb, 32, '', '\xce\xac6\xc4\xed\xcf\x98\xfa\x91o\x8b \xd0e\xd4x\x8ek5\xc3\xe7\x16\\\xa2\xb5Y\xc7\x89\x0f_\x07\xff'),
('Self CBC/AES/salt klen=16 (=openssl)', enc_aes_cbc, dec_aes_cbc, 16, '\x8fV\xab3\xe4\xda[6', '\xdb\xdc\x0cD\x88l\x19t\x8a\xa7\x00\xf2\x04\x9d\xdc\x84\xf52\x88\xd3\xf4o,I\xa4\xe4q\xbc\xde\xb1K\x05'),
('Self CBC/AES/nosalt klen=16 (=openssl)', enc_aes_cbc, dec_aes_cbc, 16, '', '\x04Us\x99\xbc\x0f\xaf\xdb\xeb\xd9\x91\xf1<\rr3\xf9\xa8\xe7i?F\xf7M#6\xa6\xc3XJ\x87\xda'),
('Self CBC/AES/salt klen=24 (=openssl)', enc_aes_cbc, dec_aes_cbc, 24, '\xa8\xf3:_e{k\xf8', '\x8e\xcdb-\xb8\xcaf\xe9\xdf\xd0"\xf3\x1f\x98\x01a\xc0\xdd+`\xe2\'\xcb\xf1#\'E\x86\xbeZc\x8d'),
('Self CBC/AES/nosalt klen=24 (=openssl)', enc_aes_cbc, dec_aes_cbc, 24, '', '\xc5\xbaF\xecm\xea\x00\xc4\x1bv\x01\xec\x99\x9c\x81\xe2\xd7\x1d\xe8>\x17\xf3\x89\x90\xbf[\x0b\x98Q\x00@G'),
('Self CBC/AES/salt klen=32 (=openssl)', enc_aes_cbc, dec_aes_cbc, 32, ':\x01W\xf4,\xbb\xd2G', '\xaf_\x9dD\x88\xc5)\xb1\x91\xfc\x91o\x1a\xa8\xd4\xb7B\xad_0\xd1\xe0\x0b,\xfa\x8cr\x11\xc7J\t\xc4'),
('Self CBC/AES/nosalt klen=32 (=openssl)', enc_aes_cbc, dec_aes_cbc, 32, '', "\xe1\xd7cS\xe5`\x1a'\xb8\xbce/\xfa\x06\xdc\x17\xef&\x91\x83:fG\x87\xb4\x9d\x0b5\xf7s\x9c\x02"),
('Self PCBC/AES/salt klen=16', enc_aes_pcbc, dec_aes_pcbc, 16, '\rp]\x1b\x90G\xd5_', '\xf8\x8c\x98\xd1\xe8_\xfbc\xa4\xc4p\x8b\x89&\xcc\x1a\xde&\x9aC\xfc&)W\x8aqDv\x99\xc3\x96\x8a'),
('Self PCBC/AES/nosalt klen=16', enc_aes_pcbc, dec_aes_pcbc, 16, '', '\x04Us\x99\xbc\x0f\xaf\xdb\xeb\xd9\x91\xf1<\rr3\xa1^U6+\xbd \xf8\xd2\x06\xac1f&K2'),
('Self PCBC/AES/salt klen=24', enc_aes_pcbc, dec_aes_pcbc, 24, '\xb6{\xd6\x87\xd2\x19e\xfa', '7\xf9\xe9\xddBI\xf2\xfb\x11\xd9\r\x8a\xb0w\xf1|\xcb\xed\xa15@\xe3\x8f\xde\xf4.\xf8\x94\x9d\xeeo\x9c'),
('Self PCBC/AES/nosalt klen=24', enc_aes_pcbc, dec_aes_pcbc, 24, '', '\xc5\xbaF\xecm\xea\x00\xc4\x1bv\x01\xec\x99\x9c\x81\xe2\x00\xaf\xe6r\xfcW\xd8\xde\xe3"\xb6\xdc\xe9\x93L\x8f'),
('Self PCBC/AES/salt klen=32', enc_aes_pcbc, dec_aes_pcbc, 32, 'i+\x94\xc2l=\xcb\xdc', 'X\x81\xa6\xd1|\xd5\x90\xb3\xeaX\xe9\xb6\xb4\x9d37DTe\x19\xad\xc0\xa0\xaf\xe2\x01\x17\x07\xdd9\xd5$'),
('Self PCBC/AES/nosalt klen=32', enc_aes_pcbc, dec_aes_pcbc, 32, '', "\xe1\xd7cS\xe5`\x1a'\xb8\xbce/\xfa\x06\xdc\x17\xcc\x0f\xcc\xf1\xba\xef\x87#\x85h}\xae\xb3\xbei "),
        ):
        c = enc_op(text, salt, passphrase, klen)
        t = dec_op(c, salt, passphrase, klen)
        print pad(rem, 50), 'enc:', ok(c == ref_cryp), 'dec:', ok(t == text)

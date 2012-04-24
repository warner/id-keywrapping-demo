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


__all__ = 'enc_ecb', 'dec_ecb', 'enc_cbc', 'dec_cbc', 'enc_pcbc', 'dec_pcbc'

__doc__ = '''Block cipher modes of operation

Supported modes: ECB, CBC, PCBC
Supported block size: 64, 128 bits
'''

def xor_text(a, b):
    return ''.join(map(lambda x: chr(ord(x[0])^ord(x[1])), zip(a, b)))


class enc_ecb:

    def __init__(self, block_chifer, block_size=8):
        self.bc = block_chifer
        self.bs = block_size

    def _one_step(self, text): # len(text) == block_size
        return self.bc.enc(text)

    def __call__(self, text): # len(text) % block_size == 0
        crypted = ''
        for s in xrange(0, len(text), self.bs):
            crypted += self._one_step(text[s:s+self.bs])
        return crypted


class dec_ecb(enc_ecb):

    def _one_step(self, crypted):
        return self.bc.dec(crypted)


class enc_cbc(enc_ecb):

    def __init__(self, block_chifer, iv):
        self.c = iv
        self.bc = block_chifer
        self.bs = len(iv)

    def _one_step(self, text):
        self.c = self.bc.enc(xor_text(self.c, text))
        return self.c


class dec_cbc(enc_cbc):

    def _one_step(self, crypted):
        text = xor_text(self.bc.dec(crypted), self.c)
        self.c = crypted
        return text


class enc_pcbc(enc_cbc):

    def _one_step(self, text):
        c = self.bc.enc(xor_text(self.c, text))
        self.c = xor_text(text, c)
        return c


class dec_pcbc(enc_cbc):

    def _one_step(self, crypted):
        p = xor_text(self.bc.dec(crypted), self.c)
        self.c = xor_text(p, crypted)
        return p


if __name__ == '__main__':
    from testutil import ok, pad
    class fake_chifer:
        def enc(self, text):
            return xor_text(text, 'A'*len(text))
        dec = enc
    def test(mode_name, enc_mode, dec_mode, block_size):
        print 'Test mode %s block size %d' % (mode_name, block_size)
        print '     one chank coding'
        iv = ''.join(map(chr, range(48 + block_size, 48, -1)))
        c = fake_chifer()
        text = 'ABCDEFGHabcdefgh'
        e = enc_mode(c, iv)
        cryp = e(text)
        d = dec_mode(c, iv)
        textb = d(cryp)
        print pad('%s %s' % (text, textb), 70), ok(text == textb)
        print '     stream coding'
        text = ''.join(map(lambda x: chr(x), xrange(65, 65+32)))
        e = enc_mode(c, iv)
        cryp = ''
        cryp += e(text[:16])
        cryp += e(text[16:])
        d = dec_mode(c, iv)
        textb = ''
        textb += d(cryp[:16])
        textb += d(cryp[16:])
        print pad('%s %s' % (text, textb), 70), ok(text == textb)
    for bs in 8, 16:
        test('PCBC', enc_pcbc, dec_pcbc, bs)
        test('CBC', enc_cbc, dec_cbc, bs)
        test('ECB', lambda c, iv: enc_ecb(c, len(iv)), lambda c, iv: dec_ecb(c, len(iv)), bs)

# Password-Based Key Derivation from PKCS#5 v2.0 
# Author: Peio Popov <peio@peio.org>
# License: Public Domain

import base64
from math import ceil
from os import urandom
import hashlib
from hashlib import sha1, sha256, sha512
from hmac import new as hmac
from struct import pack, calcsize

'''
@todo Unicode support
@todo Documentation generation
'''


def PRF(key, msg, hashfunct=sha1):
    'Pseudorandom function'
    'B.1. An example pseudorandom function (PRF) for PBKDF2 (Section 5.2) is HMAC-SHA-1.'
    return hmac( key, msg, hashfunct ).digest()

def I2OSP(longint, length=8):
    '''
    I2OSP(longint, length) -> bytes

    I2OSP converts a long integer into a string of bytes (an Octet String). 
    It is defined in the  PKCS #1 v2.1: RSA Cryptography Standard (June 14, 2002)
    '''
    from binascii import a2b_hex, b2a_hex
    hex_string = '%X' % longint
    if len( hex_string ) > 2 * length:
            raise ValueError( 'integer %i too large to encode in %i octets' % ( longint, length ) )
    return a2b_hex(  hex_string.zfill( 2 * length ) )

def strxor(a, b): 
    'XOR of two strings'
    return "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a, b)])

def checkTypes(password, salt, c, dkLen):
    'Check types and convert if possible. Raise error otherwise'
    
    'P password, an octet string'
    if type(password) is str:
        pass 
    elif type(password) is int or long:
        password = I2OSP(password)
    else:
        raise TypeError, 'password should be octet string'
    
    'S salt, an octet string'
    if type(salt) is str:
        pass 
    elif type(salt) is int or long:
        salt = I2OSP(salt)
    else:
        raise TypeError, 'salt should be octet string'
    
    'c iteration count, a positive integer'
    if (type(c) is int or long) and c > 0:
        pass
    else:
        raise TypeError, 'c = %d should be a positive integer'%c
    
    'dkLen iteration count, a positive integer'
    if (type(dkLen) is int or long) and dkLen > 0:
        pass
    else:
        raise TypeError, 'dkLen=%d should be a positive integer'%dkLen
    
    return password, salt

def PBKDF1(password, salt, c=1200, dkLen=20): 
    ''' From PKCS#5 2.0 sect 5.1
    PBKDF1 (P, S, c, dkLen)
    Options: Hash underlying hash function
    Input: P password, an octet string
    S salt, an eight-octet string
    c iteration count, a positive integer
    dkLen intended length in octets of derived key, a positive integer, at most
    16 for MD2 or MD5 and 20 for SHA-1
    Output: DK derived key, a dkLen-octet string    '''
    
    password, salt = checkTypes(password, salt, c, dkLen)
    
    dkMaxLen = hashlib.sha1().digest_size
            
    assert dkLen <= dkMaxLen,  "derived key too long"    
    assert len(salt) == 8, 'Salt should be 8 bytes'
    
    T = sha1(password+salt).digest()
    for _ in xrange(2,c+1):
        T = sha1(T).digest() 
    
    return T[:dkLen] 

def PBKDF2(password, salt, c=1200, dkLen=32):
    '''PBKDF2 (P, S, c, dkLen)
    Options: PRF underlying pseudorandom function (hLen denotes the length in
                octets of the pseudorandom function output)
    Input: P password, an octet string
    S salt, an octet string
    c iteration count, a positive integer
     dkLen intended length in octets of the derived key, a positive integer, at most (2**23 - 1) * hLen
    Output: DK derived key, a dkLen-octet string '''

    'hLen denotes the length in octets of the pseudorandom function output'
    
    password, salt = checkTypes(password, salt, c, dkLen) 
    
    hLen = hashlib.sha1().digest_size
    maxdkLen =  (2**32-1) * hLen
    assert dkLen < maxdkLen,  "derived key too long"

    l = int(ceil(float(dkLen)/hLen))
    r = dkLen - (l-1) * hLen
    
    assert calcsize("!L") == 4, "Iterator should be big-endian 4 byte string"

    dK = '' # Devived key
    for i in xrange(1, l+1):
        # Initial block pack
        U = PRF(password, salt + pack("!L",i))
        tmp_key = U
        for _ in xrange(c-1):
            U = PRF(password, U)
            tmp_key = strxor(tmp_key, U)
            #print 'tmp =',tmp_key
        dK += tmp_key
    
    return dK[:dkLen]

def byte2hex(byteStr):
    'Converts byte str to hex. Adds an interval for readability in the test vector results'
    r = ''.join( [ "%02X " % ord( x ) for x in byteStr ] ).strip()
    return r.lower()

def TestVectorsPBKDF2():
    '''Test vectors according to RFC 3962 Appendix B. 
    http://www.ietf.org/rfc/rfc3962.txt  '''
    
    iterations = (1,2,1200)
    key_size = (16, 32)
    'Sample values for the PBKDF2 HMAC-SHA1 string-to-key function are included below.'
    expected_results = ["cd ed b5 28 1b b2 f8 01 56 5a 11 22 b2 56 35 15", 
                      "cd ed b5 28 1b b2 f8 01 56 5a 11 22 b2 56 35 15 0a d1 f7 a0 4b b9 f3 a3 33 ec c0 e2 e1 f7 08 37",
                      "01 db ee 7f 4a 9e 24 3e 98 8b 62 c7 3c da 93 5d",
                      "01 db ee 7f 4a 9e 24 3e 98 8b 62 c7 3c da 93 5d a0 53 78 b9 32 44 ec 8f 48 a9 9e 61 ad 79 9d 86",
                      "5c 08 eb 61 fd f7 1e 4e 4e c3 cf 6b a1 f5 51 2b",
                      "5c 08 eb 61 fd f7 1e 4e 4e c3 cf 6b a1 f5 51 2b a7 e5 2d db c5 e5 14 2f 70 8a 31 e2 e6 2b 1e 13"]
    expected_results.reverse()
    
    print 'Run tests from RFC 3962 Appendix B:',"\n"
    
    password = "password"
    salt = "ATHENA.MIT.EDUraeburn"
    for i in iterations:
      for key in key_size:
          result = PBKDF2(password, salt, i, key)
          print 'password =',password,'salt =',salt,'c =',i,'dkLen =',key
          print 'expected:',expected_results.pop()
          print 'result  :',byte2hex(result)
                    
    # This test fails in other implementations - salt should be octet string 
    password = "password"
    salt = 0x1234567878563412
    i = 5
    key = 32    
    result = PBKDF2 (password, salt, i, key)
    print 'password =',password,'salt =',salt,'c =',i,'dkLen =',key
    print 'expected:',"d1 da a7 86 15 f2 87 e6 a1 c8 b1 20 d7 06 2a 49 3f 98 d2 03 e6 be 49 a6 ad f4 fa 57 4b 6e 64 ee"
    print 'result  :',byte2hex(result)
        
    password = 'X'*64
    salt = 'pass phrase equals block size'
    i = 1200
    key = 32
    print 'password =',password,'salt =',salt,'c =',i,'dkLen =',key
    result = PBKDF2(password, salt, i, key)
    print 'result  :',byte2hex(result)
    print 'expected:',"13 9c 30 c0 96 6b c3 2b a5 5f db f2 12 53 0a c9 c5 ec 59 f1 a4 52 f5 cc 9a d9 40 fe a0 59 8e d1"
   
    password = 'X'*65
    salt = "pass phrase exceeds block size"
    i = 1200
    key = 32
    print 'password =',password,'salt =',salt
    result = PBKDF2(password, salt, i, key)
    print 'result  :',byte2hex(result)
    print 'expected:', "9c ca d6 d4 68 77 0c d5 1b 10 e6 a6 87 21 be 61 1a 8b 4d 28 26 01 db 3b 36 be 92 46 91 5e c8 2a"
    
    print 'RFC 3962 Appendix B: Finished'

def RandInputPBKDF2():

    from Crypto.Random.random import randint

    for _ in xrange(10):
        pass_len = randint(1,120)
        password = urandom(pass_len)
        
        salt_len = randint(1,120)
        salt = urandom(salt_len)
        
        i = randint(-1,10)
        key = randint(-10,1024)
    #    print 'password =',password,'salt =',salt
        result = PBKDF2(password, salt, i, key)
        print 'result  :',byte2hex(result)

if __name__ == '__main__':
    TestVectorsPBKDF2()
    

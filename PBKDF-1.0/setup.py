#!/usr/bin/env python

from distutils.core import setup

'Packaging instructions from: http://diveintopython3.org/packaging.html'

setup(name='PBKDF',
      py_modules=['PBKDF'],
      version='1.0',
      description='Password based Key Derivation functions from PKCS#5',    
      keywords = ["PBKDF1", "PBKDF2", "key derivation", "password key derivation", "PBKDF", "PKCS5", "PKCS#5", "PKCS"],

      author='Peio Popov',
      author_email='peio@peio.org',
      license = 'Public Domain',
      url = 'http://pypi.python.org/pypi/PBKDF',

      classifiers = ['Development Status :: 5 - Production/Stable',
        'Environment :: Console',
        'Intended Audience :: Education',
        'License :: Public Domain',
        'Natural Language :: English',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Security :: Cryptography'],
        long_description = '''\


PBKDF - Password based Key Derivation functions from PKCS#5
-----------------------------------------------------------

Password based key derivation functions (PBKDF1, PBKDF2) as defined in section 5 of PKCS#5

A key derivation function produces a derived key from a base key and other parameters.
In a password-based key derivation function, the base key is a password and the other
parameters are a salt value and an iteration count.

For verification are included the test vectors from RFC 3962 Appendix B

'''
      )


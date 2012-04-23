Key-Wrapping Demo
=================

This is a quick-and-dirty demo (and specification-as-code) of the
key-wrapping scheme. It has a server process which holds the wrapped keys
entirely in RAM (no persistence across restarts), and a client with two
commands: "init" and "read".

Building
--------

1: (cd srp-1.0 && python setup.py build)
2: (cd python-scrypt-0.1 && python setup.py build)
3: edit Makefile to reflect the actual build/ directory under
   python-scrypt-0.1 . This will include the name of your platform and
   version of python, so the default will probably only work on my Snow
   Leopard box.

You also need to have Twisted installed, as the server uses twisted.web

Running
-------

In one shell: make run-server
In another one: ./client.py EMAIL PASSWORD init
Then, ./client.py EMAIL PASSWORD read

Incompleteness
--------------

This demo still lacks the following important features:

* AES: the actual key-wrapping code is stubbed out. WUK==UK
* safe setup: I still don't know how to best get the initial account data
  (most importantly the SRP verifier, less importantly email and SRP salt) to
  the server safely. This will require either public-key encryption (where
  the client contains a known-good pubkey) or SSL with a pinned certificate
  (where the client contains a known-good cert hash).
* outsourced scrypt: all scrypt processing is done locally

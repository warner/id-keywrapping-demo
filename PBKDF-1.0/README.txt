PBKDF - Password based Key Derivation functions from PKCS#5
-----------------------------------------------------------

Password based key derivation functions (PBKDF1, PBKDF2) as defined in section 5 of PKCS#5

A key derivation function produces a derived key from a base key and other parameters.
In a password-based key derivation function, the base key is a password and the other
parameters are a salt value and an iteration count.

For verification are included the test vectors from RFC 3962 Appendix B

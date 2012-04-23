
import unittest
from scrypt import scrypt, cpuperf, pick_params
from binascii import hexlify

MB = 1000*1000
MiB = 1024*1024

class Basic(unittest.TestCase):
    def test_basic(self):
        # this should take 1MB and 1s
        out = scrypt("password", "salt", N=1024, r=8, p=45, dkLen=16)
        self.failUnlessEqual(len(out), 16)
        self.failUnlessEqual(hexlify(out), "99e138108da14a277b69007c1b5d07ed")
        out = scrypt("password", "salt", N=1024, r=8, p=45, dkLen=32)
        self.failUnlessEqual(len(out), 32)
        self.failUnlessEqual(hexlify(out), "99e138108da14a277b69007c1b5d07edbd41339cd6f31e4dc053479c887a627b")
    def test_cpuperf(self):
        ops_per_second = cpuperf()
        self.failUnless(ops_per_second > 10, ops_per_second)
    def test_params(self):
        opps = 1500000
        # memory limited
        self.failUnlessEqual(pick_params(MiB, 1.0, opps), (1024,8,45))
        self.failUnlessEqual(pick_params(MiB, 2.0, opps), (1024,8,91))
        self.failUnlessEqual(pick_params(MiB, 3.0, opps), (1024,8,137))
        self.failUnlessEqual(pick_params(MiB, 4.0, opps), (1024,8,183))
        self.failUnlessEqual(pick_params(100*MiB, 3.0, opps), (65536,8,2))
        # cpu limited
        self.failUnlessEqual(pick_params(100*MiB, 1.0, opps), (32768,8,1))
        self.failUnlessEqual(pick_params(100*MiB, 2.0, opps), (65536,8,1))

        # and check that it can measure the CPU time itself
        N,r,p = pick_params(MiB, 1.0)
        self.failUnlessEqual(r, 8) # this one is hard-coded
        memory = 128*N*r
        self.failUnless(memory <= MiB, (memory, MiB))


from . import _scrypt
import math


def pick_params(maxmem, maxtime, opps=None):
    """Given memory and time limits, return (N,r,p) parameter tuple.

     'maxmem': memory limit, in bytes, e.g. 10*1000*1000
     'maxtime': operation time, in seconds, e.g. 1.5

    This measures how fast your CPU can perform salsa20/8 core operations. It
    then returns a tuple of parameters which, when passed into scrypt(), will
    use about the given resource limits.
    """
    # this is just a python translation of scryptenc.c's pickparams()
    if opps is None:
        opps = cpuperf()
    opslimit = opps * maxtime
    opslimit = max(opslimit, 32768) # do at least 2^15 core operations
    r = 8 # fixed
    # 128*N*r <= memlimit, 4*N*r*p <= opslimit. If opslimit < memlimit/32,
    # then opslimit imposes the stronger limit on N
    #print "close:", opslimit, maxmem/32
    if opslimit < maxmem/32:
        maxN = opslimit / (4*r)
        # the scrypt codebase uses "logN" but then does N=(unit64_t)(1)<<logN
        # which means it's really log2(N)-1. We match their units but call it
        # "logN1"
        logN1 = int(math.log(maxN,2))-1
        N = 2**(logN1+1)
        p = 1
        #print "cpulimit, maxN %f, logN1 %d" % (maxN, logN1)
    else:
        # the memory limit is tighter
        maxN = maxmem / (128*r)
        logN1 = int(math.log(maxN,2))-1
        N = 2**(logN1+1)
        # then choose p based on the CPU limit
        maxrp = (opslimit/4) / N
        maxrp = int(min(maxrp, 0x3fffffff))
        p = int(maxrp / r)
        #print "memlimit, maxN %f, logN1 %d, maxrp %f" % (maxN, logN1, maxrp)
    #print "N = %d r = %d p = %d" % (N,r,p)
    return (N,r,p)


def scrypt(password, salt, dkLen, N, r, p):
    """Given a password and salt, return a derived key (of length dkLen).

    The scrypt algorithm is parameterized by N/r/p:

     'N' is the CPU/memory cost parameter
     'r' is the block size parameter (8 is the recommended value)
     'p' is the parallelization parameter.

    Memory usage is roughly 128*N*r. CPU time is roughly 4*N*r*p salsa20/8
    operations (call cpuperf() to find out how many salsa20/8 operations can
    be done in a second on this CPU).

    You must provide all of N/r/p, but you can use pick_params() to make this
    easier:

     key = scrypt(password, salt, dkLen, *pick_params(maxmem, maxtime))

    Returns a string of length dkLen.
    """
    return _scrypt.scrypt(password, salt, N, r, p, dkLen)

def cpuperf():
    return _scrypt.cpuperf()

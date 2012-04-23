
import sys, os
from distutils.core import setup, Extension, Command
from distutils.command.build_ext import build_ext
from distutils.util import get_platform
import versioneer
versioneer.versionfile_source = "src/scrypt/_version.py"
versioneer.versionfile_build = "scrypt/_version.py"
versioneer.tag_prefix = ""
versioneer.parentdir_prefix = "python-scrypt-"


LONG_DESCRIPTION="""\
Python bindings to the 'scrypt' memory-hard KDF algorithm

This offers a python interface to a C implementation of the scrypt
key-derivation function (http://www.tarsnap.com/scrypt.html/), using code
from the 'scrypt' encryption utility on that page.

This algorithm takes a password and derives a random key from it, using
significant (but configurable) CPU and memory in the process. By design, an
attacker must spend comparable resources to test each guess, increasing the
costs of a brute-force attack. scrypt is specifically designed to yield no
speedups to hardware-based attacks (like GPUs), unlike ordinary iterated
hashing functions like PBKDF2.
"""

sources = ["src/scrypt-glue/scryptmodule.c"]
sources.extend(["scrypt-1.1.6/lib/util/memlimit.c",
                "scrypt-1.1.6/lib/util/readpass.c",
                "scrypt-1.1.6/lib/util/warn.c",
                "scrypt-1.1.6/lib/scryptenc/scryptenc.c",
                "scrypt-1.1.6/lib/scryptenc/scryptenc_cpuperf.c",
                "scrypt-1.1.6/lib/crypto/crypto_scrypt-ref.c",
                "scrypt-1.1.6/lib/crypto/sha256.c",
                "scrypt-1.1.6/lib/crypto/crypto_aesctr.c",
                ])

m = Extension("scrypt._scrypt",
              include_dirs=["scrypt-1.1.6/lib/util",
                            "scrypt-1.1.6/lib/scryptenc",
                            "scrypt-1.1.6/lib/crypto",
                            "scrypt-1.1.6",
                            ],
              define_macros=[("HAVE_CONFIG_H", None)],
              libraries=["crypto"], # needs OpenSSL for AES_encrypt()
              sources=sources)

commands = versioneer.get_cmdclass().copy()

class build_ext_AutoconfFirst(build_ext):
    def run(self):
        if not os.path.exists("scrypt-1.1.6/config.status"):
            print "Running ./configure for scrypt-1.1.6"
            os.system("cd scrypt-1.1.6 && ./configure")
        return build_ext.run(self)
commands["build_ext"] = build_ext_AutoconfFirst

class Test(Command):
    description = "run tests"
    user_options = []
    def initialize_options(self):
        pass
    def finalize_options(self):
        pass
    def setup_path(self):
        # copied from distutils/command/build.py
        self.plat_name = get_platform()
        plat_specifier = ".%s-%s" % (self.plat_name, sys.version[0:3])
        self.build_lib = os.path.join("build", "lib"+plat_specifier)
        sys.path.insert(0, self.build_lib)
    def run(self):
        self.setup_path()
        import unittest
        test = unittest.defaultTestLoader.loadTestsFromName("scrypt.test_scrypt")
        runner = unittest.TextTestRunner(verbosity=2)
        result = runner.run(test)
        sys.exit(not result.wasSuccessful())
commands["test"] = Test

setup(name="scrypt",
      version=versioneer.get_version(),
      description="Scrypt memory-hard KDF",
      long_description=LONG_DESCRIPTION,
      author="Brian Warner",
      author_email="warner-python-scrypt@lothar.com",
      license="MIT",
      url="https://github.com/warner/python-scrypt",
      ext_modules=[m],
      packages=["scrypt"],
      package_dir={"scrypt": "src/scrypt"},
      cmdclass=commands,
      )

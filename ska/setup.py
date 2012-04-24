from distutils.core import setup

package_name = 'ska'
from ska import __version__ as package_version
michurin = 'Alexey V Michurin'
michurin_email = 'a.michurin@gmail.com'

setup(
  name = package_name,
  version = package_version,
  packages = [package_name],
  description =
   'Symmetric-key algorithms.',
  long_description =
   'Pure Python implementation of Blowfish and AES ' \
   'with EBC, CBC and PCBC modes and variable key length support.',
  author = michurin,
  author_email = michurin_email,
  maintainer = michurin,
  maintainer_email = michurin_email,
  url = 'http://code.google.com/p/ska/',
  download_url = 'http://code.google.com/p/ska/',
  license = 'Simplified BSD License',
  platforms = 'any',
  classifiers = [
    # http://pypi.python.org/pypi?%3Aaction=list_classifiers
    'Development Status :: 4 - Beta',
    #'Development Status :: 5 - Production/Stable',
    'Intended Audience :: Customer Service',
    'Intended Audience :: Developers',
    'Intended Audience :: Education',
    'Intended Audience :: Information Technology',
    'Intended Audience :: System Administrators',
    'Intended Audience :: Telecommunications Industry',
    'License :: OSI Approved :: BSD License',
    'Operating System :: OS Independent',
    'Programming Language :: Python :: 2',
    'Topic :: Security :: Cryptography',
    'Topic :: Software Development :: Libraries']
)

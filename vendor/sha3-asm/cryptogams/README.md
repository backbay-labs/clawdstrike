CRYPTOGAMS distribution repository. As for issues. It's unclear line
between which issues are considered common, common with OpenSSL that is,
and which are specific to this distribition repository. Thing is that
common issues should rather be handled as OpenSSL ones. For this reason
I reserve the right to close problem reports with resolution "to be
taken through OpenSSL channels." Feature requests can be reported as
issues. Pull requests will be [currently] ignored.

Common usage pattern is to invoke script and pass "flavour" and output
file name as command line arguments. "Flavour" refers to ABI family or
specfic OS. E.g. x86_64 scripts recognize 'elf', 'elf32', 'macosx',
'mingw64', 'nasm'. PPC scripts recognize 'linux32', 'linux64',
'linux64le', 'aix32', 'aix64', 'osx32', 'osx64'. And so on... Some
x86_64 scripts even examine CC environment variable in order to
determine if AVX code path should be generated. ["AVX" refers to *all*
AVX versions.]

See https://www.openssl.org/~appro/cryptogams/ for background
information.

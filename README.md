# sha3-d

A pure D library that implements the Keccack[1600] function providing
std.digest compatible APIs for SHA-3 and SHAKE aimed for high-performance.

Introduced in 2015, SHA-3 is the latest member of the SHA family. See NIST FIPS
PUB 202 for more information. SHA-3 is already used worlwide, including SQLite3
for both internal and download integrity operations.

The following are implemented:
- SHA-3-224
- SHA-3-256
- SHA-3-384
- SHA-3-512
- SHAKE-128
- SHAKE-256

When compiled with LDC (`release-nobounds`), this package rivals OpenSSL by
being on-par in terms of performance (~120 MiB/s, 64 KiB buffer, tested on
Ubuntu 20.04 LTS AMD64). _A much faster alternative to keccack-tiny!_

Compatible with DMD, GDC, and LDC.

# License

Published under the Boost License 1.0.
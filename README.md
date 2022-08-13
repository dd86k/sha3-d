# sha3-d

SHA-3 library written entirely in D implementing Keccack-f\[1600,24] and is fully
compatible with the Phobos Digest API (std.digest).

Introduced in 2015, SHA-3 is the latest member of the SHA family. SHA-3 is
already used in production-ready projects worlwide, including SQLite3 for both
internal and download integrity operations. For more information about SHA-3,
consult [NIST FIPS PUB 202](http://dx.doi.org/10.6028/NIST.FIPS.202) (PDF).

This module implements the six official hashing algorithms: SHA-3-224, SHA-3-256,
SHA-3-384, SHA-3-512, SHAKE-128 (XOF), and SHAKE-256 (XOF).

Features:
- A much faster alternative to keccak-tiny.
- Implementation tested with DMD, GDC, and LDC compilers.
- Compatible with HMAC templates (`std.digest.hmac`).
- Creating your own XOFs (e.g., SHAKE-256/1024).

Pull Requests accepted.

**If you would like to disclose a vulnerability, please consult [SECURITY.md](../master/.github/SECURITY.md).**

# Usage

To include it in your project, simply import the `sha3d` package.

## Digest API

If you are unfamiliar with the Digest API, here is a quick summary.

Two APIs are available: Template API and OOP API.

### Template API

The template API uses a structure template and is a good choice if your
application only plans to support one digest algorithm.

```d
SHA3_256 sha3_256;
sha3_256.put("abc");
assert(sha3_256.finish() == cast(ubyte[])
    hexString!"3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");
sha3_256.start();
sha3_256.put("abcdef");
assert(sha3_256.finish() == cast(ubyte[])
    hexString!"a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
```

### OOP API

The OOP API uses a class (object) implementation and is a good choice if
your application plans to support one or more digest algorithms.

```d
Digest sha3_256 = new SHA3_256Digest();
sha3_256.put("abc");
assert(sha3_256.finish() == cast(ubyte[])
    hexString!"3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");
sha3_256.start();
sha3_256.put("abcdef");
assert(sha3_256.finish() == cast(ubyte[])
    hexString!"a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
```

There are numerous ways to avoid GC allocation. For example when only using a
digest for a one-time use in a short scope, there's `std.typecons.scoped`.

# License

Published under the Boost License 1.0.
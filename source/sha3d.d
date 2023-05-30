/// Computes SHA-3 hashes of arbitrary data using a native implementation.
/// Standards: NIST FIPS PUB 202
/// License: $(LINK2 https://www.boost.org/LICENSE_1_0.txt, Boost License 1.0)
/// Authors: $(LINK2 https://github.com/dd86k, dd86k)
module sha3d;

/// Version string of sha3-d that can be used for printing purposes.
public enum SHA3D_VERSION_STRING = "1.2.5";

private import std.digest;
private import core.bitop : rol, bswap;

version (SHA3D_Trace)
    private import std.stdio;

/// Template API SHA-3/SHAKE implementation using the Keccak function.
///
/// It is recommended to use the SHA3_224, SHA3_256, SHA3_384, SHA3_512,
/// SHAKE128, and SHAKE256 template aliases for NIST FIPS 202 approved
/// functions.
///
/// Examples:
/// ---
/// // Defines SHAKE-128/256 with Template API, OOP API, and helper function.
/// alias SHAKE128_256 = KECCAK!(128, 256);
/// alias SHAKE128_256Digest = WrapperDigest!SHAKE128_256;
/// auto shake128_256Of(T...)(T data) { return digest!(SHAKE128_256, T)(data); }
/// ---
///
/// Params:
///   digestSize = Digest size in bits.
///   shake = SHAKE XOF digest size in bits. Defaults to 0 for SHA-3.
///   sponge = Sponge size in bits, must be a power of 25. Defaults to 1600.
///   rounds = Number of rounds for transformation function. Defaults to 24.
///
/// Throws: No exceptions are thrown.
public struct KECCAK(uint digestSize,
    uint shake = 0, uint sponge = 1600, size_t rounds = 24)
{
    version (SHA3D_Trace) {}
    else
    {
        @safe: @nogc: nothrow: pure:
    }
    
    static assert(sponge <= 1600,   "Sponge can't be over 1600 bits.");
    static assert(sponge % 25 == 0, "Sponge must be a power of 25.");
    static assert(rounds <= 24,     "Rounds can't be over 24.");
    
    static if (shake)
    {
        static assert(digestSize == 128 || digestSize == 256,
            "SHAKE digest size must be 128 or 256 bits");
        static assert(shake > 0,
            "SHAKE digest size must be higher than zero.");
        static assert(shake % 8 == 0,
            "SHAKE digest size must be a factor of 25.");
        private enum digestSizeBytes = shake / 8; /// Digest size in bytes
    }
    else // SHA-3
    {
        static assert(digestSize == 224 || digestSize == 256 ||
            digestSize == 384 || digestSize == 512,
            "SHA-3 digest size must be 224, 256, 384, or 512 bits");
        private enum digestSizeBytes = digestSize / 8; /// Digest size in bytes
    }
    
    /// RC constants.
    private immutable static ulong[24] K_RC = [
        0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
        0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
        0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
        0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
        0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
        0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008
    ];
    /// Rho indexes.
    private immutable static int[24] K_RHO = [
         1,  3,  6, 10, 15, 21, 28, 36, 45, 55,  2, 14,
        27, 41, 56,  8, 25, 43, 62, 18, 39, 61, 20, 44
    ];
    /// PI indexes.
    private immutable static size_t[24] K_PI = [
        10,  7, 11, 17, 18, 3,  5, 16,  8, 21, 24, 4,
        15, 23, 19, 13, 12, 2, 20, 14, 22,  9,  6, 1
    ];
    
    /// Digest size in bits.
    enum blockSize = (sponge - digestSize * 2); // Required for HMAC.
    
    //  ...0: Reserved
    //    01: SHA-3
    // ...11: RawSHAKE
    //  1111: SHAKE
    private enum delim = shake ? 0x1f : 0x06; /// Delimiter suffix when finishing
    private enum rate = blockSize / 8; /// Sponge rate in bytes
    private enum stateSize = 200; /// Constant for any derivatives
    private enum state64Size = stateSize / ulong.sizeof;
    private enum statezSize = stateSize / size_t.sizeof;
    
    union
    {
        private size_t[statezSize] statez;  // state (size_t)
        private ulong[state64Size] state64; // state (ulong)
        private ubyte[stateSize] state;  // state (ubyte)
    }
    static assert(state64.sizeof == state.sizeof);
    static assert(statez.sizeof  == state.sizeof);
    
    private ulong[5] bc; // Transformation data
    private ulong t;     // Transformation temporary
    private size_t pt;   // Left-over sponge pointer
    
    /// Initiate or reset the state of the instance.
    void start()
    {
        this = typeof(this).init;
    }
    
    /// Feed the algorithm with data.
    /// Also implements the $(REF isOutputRange, std,range,primitives)
    /// interface for `ubyte` and `const(ubyte)[]`.
    /// Params: input = Input data to digest
    void put(scope const(ubyte)[] input...) @trusted
    {
        size_t i = pt;
        
        // Process wordwise if properly aligned.
        if ((i | cast(size_t)input.ptr) % size_t.alignof == 0)
        {
            static assert(rate % size_t.sizeof == 0);
            foreach (const word; (cast(size_t*)input.ptr)[0..input.length / size_t.sizeof])
            {
                statez[i / size_t.sizeof] ^= word;
                i += size_t.sizeof;
                if (i >= rate)
                {
                    transform;
                    i = 0;
                }
            }
            input = input[input.length - (input.length % size_t.sizeof)..input.length];
        }
        
        // Process remainder bytewise.
        foreach (const b; input)
        {
            state.ptr[i++] ^= b;
            if (i >= rate)
            {
                transform;
                i = 0;
            }
        }
        
        pt = i;
    }
    
    /// Returns the finished hash.
    /// This also clears part of the state, leaving just the final digest.
    /// Returns: Raw digest data.
    ubyte[digestSizeBytes] finish()
    {
        state[pt] ^= delim;
        state[rate - 1] ^= 0x80;
        
        static if (shake)
        {
            ubyte[digestSizeBytes] output = void;
            
            size_t i;
            
            // Transform at {rate} until output is filled.
            do
            {
                transform;
                size_t end = i + rate;
                if (end > digestSizeBytes)
                {
                    output[i..$] = state[0..digestSizeBytes - i];
                    break;
                }
                output[i..end] = state[0..rate];
                i += rate;
            } while (true);
            
            // Clear state of potential sensitive data.
            state64[] = 0;
            bc[] = t = 0;
            
            return output;
        }
        else // SHA-3
        {
            transform;
            
            // Clear potentially sensitive data.
            // State sanitized only if digestSize is less than state
            // of 1600 bits, so 200 Bytes.
            static if (digestSizeBytes < stateSize)
                state[digestSizeBytes..$] = 0;
            bc[] = t = 0;
            
            version (SHA3D_Trace)
            {
                ubyte[digestSizeBytes] r = state[0..digestSizeBytes];
                writeln("HASH=", toHexString!(LetterCase.lower)(r));
                return r;
            }
            else
            {
                return state[0..digestSizeBytes];
            }
        }
    }
    
private:
    
    void transform()
    {
        version (BigEndian) swap;

        for (size_t round; round < rounds; ++round)
        {
            // Theta
            THETA1(0); THETA1(1); THETA1(2); THETA1(3); THETA1(4);
            THETA2(0); THETA2(1); THETA2(2); THETA2(3); THETA2(4);
            t = state64[1];
            // Rho
            RHO(0); RHO(1); RHO(2); RHO(3); RHO(4);
            RHO(5); RHO(6); RHO(7); RHO(8); RHO(9);
            RHO(10); RHO(11); RHO(12); RHO(13); RHO(14);
            RHO(15); RHO(16); RHO(17); RHO(18); RHO(19);
            RHO(20); RHO(21); RHO(22); RHO(23);
            // Chi
            CHI(0); CHI(5); CHI(10); CHI(15); CHI(20);
            // Iota
            state64[0] ^= K_RC[round];
            
            version (SHA3D_Trace)
            {
                writefln("ROUND=%d", round);
                int i;
                foreach (ulong s; state64)
                    if (i & 1)
                        writefln(" v[%2d]=%16x", i++, s);
                    else
                        writef("\tv[%2d]=%16x", i++, s);
                writeln;
            }
        }

        version (BigEndian) swap;
    }
    
    pragma(inline, true)
    void THETA1(size_t i)
    {
        bc[i] = state64[i] ^ state64[i + 5] ^ state64[i + 10] ^
            state64[i + 15] ^ state64[i + 20];
    }
    
    pragma(inline, true)
    void THETA2(size_t i)
    {
        t = bc[(i + 4) % 5] ^ rol(bc[(i + 1) % 5], 1);
        state64[     i] ^= t;
        state64[ 5 + i] ^= t;
        state64[10 + i] ^= t;
        state64[15 + i] ^= t;
        state64[20 + i] ^= t;
    }
    
    pragma(inline, true)
    void RHO(size_t i)
    {
        size_t j = K_PI[i];
        bc[0] = state64[j];
        state64[j] = rol(t, K_RHO[i]);
        t = bc[0];
    }
    
    pragma(inline, true)
    void CHI(size_t j)
    {
        bc[0] = state64[j];
        bc[1] = state64[j + 1];
        bc[2] = state64[j + 2];
        bc[3] = state64[j + 3];
        bc[4] = state64[j + 4];

        state64[j]     ^= (~bc[1]) & bc[2];
        state64[j + 1] ^= (~bc[2]) & bc[3];
        state64[j + 2] ^= (~bc[3]) & bc[4];
        state64[j + 3] ^= (~bc[4]) & bc[0];
        state64[j + 4] ^= (~bc[0]) & bc[1];
    }
    
    version (BigEndian)
    void swap()
    {
        state64[ 0] = bswap(state64[ 0]);
        state64[ 1] = bswap(state64[ 1]);
        state64[ 2] = bswap(state64[ 2]);
        state64[ 3] = bswap(state64[ 3]);
        state64[ 4] = bswap(state64[ 4]);
        state64[ 5] = bswap(state64[ 5]);
        state64[ 6] = bswap(state64[ 6]);
        state64[ 7] = bswap(state64[ 7]);
        state64[ 8] = bswap(state64[ 8]);
        state64[ 9] = bswap(state64[ 9]);
        state64[10] = bswap(state64[10]);
        state64[11] = bswap(state64[11]);
        state64[12] = bswap(state64[12]);
        state64[13] = bswap(state64[13]);
        state64[14] = bswap(state64[14]);
        state64[15] = bswap(state64[15]);
        state64[16] = bswap(state64[16]);
        state64[17] = bswap(state64[17]);
        state64[18] = bswap(state64[18]);
        state64[19] = bswap(state64[19]);
        state64[20] = bswap(state64[20]);
        state64[21] = bswap(state64[21]);
        state64[22] = bswap(state64[22]);
        state64[23] = bswap(state64[23]);
    }
}

/// Template alias for SHA-3-224.
public alias SHA3_224 = KECCAK!(224);
/// Template alias for SHA-3-256.
public alias SHA3_256 = KECCAK!(256);
/// Template alias for SHA-3-384.
public alias SHA3_384 = KECCAK!(384);
/// Template alias for SHA-3-512.
public alias SHA3_512 = KECCAK!(512);
/// Template alias for SHAKE-128.
public alias SHAKE128 = KECCAK!(128, 128);
/// Template alias for SHAKE-256.
public alias SHAKE256 = KECCAK!(256, 256);

/// Convience alias using the SHA-3 implementation.
auto sha3_224Of(T...)(T data) { return digest!(SHA3_224, T)(data); }
/// Ditto
auto sha3_256Of(T...)(T data) { return digest!(SHA3_256, T)(data); }
/// Ditto
auto sha3_384Of(T...)(T data) { return digest!(SHA3_384, T)(data); }
/// Ditto
auto sha3_512Of(T...)(T data) { return digest!(SHA3_512, T)(data); }
/// Ditto
auto shake128Of(T...)(T data) { return digest!(SHAKE128, T)(data); }
/// Ditto
auto shake256Of(T...)(T data) { return digest!(SHAKE256, T)(data); }

// Unittests based on https://www.di-mgt.com.au/sha_testvectors.html

/// Test against empty datasets
@safe unittest
{
    import std.ascii : LetterCase;
    
    assert(toHexString!(LetterCase.lower)(sha3_224Of("")) ==
        "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7");

    assert(toHexString!(LetterCase.lower)(sha3_256Of("")) ==
        "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");

    assert(toHexString!(LetterCase.lower)(sha3_384Of("")) ==
        "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2a"~
        "c3713831264adb47fb6bd1e058d5f004");

    assert(toHexString!(LetterCase.lower)(sha3_512Of("")) ==
        "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6"~
        "15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26");

    assert(toHexString!(LetterCase.lower)(shake128Of("")) ==
        "7f9c2ba4e88f827d616045507605853e");

    assert(toHexString!(LetterCase.lower)(shake256Of("")) ==
        "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f");
}

/// Using convenience wrappers.
@safe unittest
{
    import std.ascii : LetterCase;
    
    assert(toHexString!(LetterCase.lower)(sha3_224Of("abc")) ==
        "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf");

    assert(toHexString!(LetterCase.lower)(sha3_256Of("abc")) ==
        "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");

    assert(toHexString!(LetterCase.lower)(sha3_384Of("abc")) ==
        "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b2"~
        "98d88cea927ac7f539f1edf228376d25");

    assert(toHexString!(LetterCase.lower)(sha3_512Of("abc")) ==
        "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e"~
        "10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0");

    assert(toHexString!(LetterCase.lower)(shake128Of("abc")) ==
        "5881092dd818bf5cf8a3ddb793fbcba7");

    assert(toHexString!(LetterCase.lower)(shake256Of("abc")) ==
        "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739");
}

/// Template API functions.
@safe unittest
{
    SHA3_224 hash;
    hash.start();
    ubyte[1024] data; // 1024 cleared bytes
    hash.put(data);
    ubyte[28] result = hash.finish();
    assert(toHexString!(LetterCase.lower)(result) ==
        "8c6c078646496be04b6f06d0ae323e62bbd0d08201f6a1bbb475ba3e");
}

/// Template API features.
@safe unittest
{
    import std.ascii : LetterCase;
    
    // NOTE: Because the digest is a structure, it must be passed by reference.
    void doSomething(T)(ref T hash)
        if (isDigest!T)
        {
            hash.put(cast(ubyte) 0);
        }
    SHA3_224 sha;
    sha.start();
    doSomething(sha);
    assert(toHexString!(LetterCase.lower)(sha.finish()) ==
        "bdd5167212d2dc69665f5a8875ab87f23d5ce7849132f56371a19096");
}

/// This module conforms to the Digest API.
@safe unittest
{
    assert(isDigest!SHA3_224);
    assert(isDigest!SHA3_256);
    assert(isDigest!SHA3_384);
    assert(isDigest!SHA3_512);
    assert(isDigest!SHAKE128);
    assert(isDigest!SHAKE256);
}

/// The KECCAK structure has a blockSize field.
@safe unittest
{
    assert(hasBlockSize!SHA3_224);
    assert(hasBlockSize!SHA3_256);
    assert(hasBlockSize!SHA3_384);
    assert(hasBlockSize!SHA3_512);
    assert(hasBlockSize!SHAKE128);
    assert(hasBlockSize!SHAKE256);
}

/// Using the digest template API.
@safe unittest
{
    ubyte[28] hash224 = sha3_224Of("abc");
    assert(hash224 == digest!SHA3_224("abc"));

    ubyte[32] hash256 = sha3_256Of("abc");
    assert(hash256 == digest!SHA3_256("abc"));

    ubyte[48] hash384 = sha3_384Of("abc");
    assert(hash384 == digest!SHA3_384("abc"));

    ubyte[64] hash512 = sha3_512Of("abc");
    assert(hash512 == digest!SHA3_512("abc"));

    ubyte[16] shakeHash128 = shake128Of("abc");
    assert(shakeHash128 == digest!SHAKE128("abc"));

    ubyte[32] shakeHash256 = shake256Of("abc");
    assert(shakeHash256 == digest!SHAKE256("abc"));
}

/// Using the template API.
@system unittest
{
    import std.conv : hexString;
    
    SHA3_224 dgst_sha3_224;
    dgst_sha3_224.put(cast(ubyte[]) "abcdef");
    dgst_sha3_224.start();
    dgst_sha3_224.put(cast(ubyte[]) "");
    assert(dgst_sha3_224.finish() == cast(ubyte[]) hexString!
        "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7");
    
    SHA3_256 dgst_sha3_256;
    dgst_sha3_256.put(cast(ubyte[]) "abcdef");
    dgst_sha3_256.start();
    dgst_sha3_256.put(cast(ubyte[]) "");
    assert(dgst_sha3_256.finish() == cast(ubyte[]) hexString!
        "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
    
    SHA3_384 dgst_sha3_384;
    dgst_sha3_384.put(cast(ubyte[]) "abcdef");
    dgst_sha3_384.start();
    dgst_sha3_384.put(cast(ubyte[]) "");
    assert(dgst_sha3_384.finish() == cast(ubyte[]) hexString!(
        "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2a"
        ~"c3713831264adb47fb6bd1e058d5f004"));
    
    SHA3_512 dgst_sha3_512;
    dgst_sha3_512.put(cast(ubyte[]) "abcdef");
    dgst_sha3_512.start();
    dgst_sha3_512.put(cast(ubyte[]) "");
    assert(dgst_sha3_512.finish() == cast(ubyte[]) hexString!(
        "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6"~
        "15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"));
    
    SHAKE128 dgst_shake128;
    dgst_shake128.put(cast(ubyte[]) "abcdef");
    dgst_shake128.start();
    dgst_shake128.put(cast(ubyte[]) "");
    assert(dgst_shake128.finish() == cast(ubyte[]) hexString!
        "7f9c2ba4e88f827d616045507605853e");
    
    SHAKE256 dgst_shake256;
    dgst_shake256.put(cast(ubyte[]) "abcdef");
    dgst_shake256.start();
    dgst_shake256.put(cast(ubyte[]) "");
    assert(dgst_shake256.finish() == cast(ubyte[]) hexString!
        "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f");
}

/// Convenience wrappers.
@system unittest
{
    import std.conv : hexString;
    
    immutable string a = "a";
    
    auto digest224      = sha3_224Of(a);
    assert(digest224 == cast(ubyte[]) hexString!
        "9e86ff69557ca95f405f081269685b38e3a819b309ee942f482b6a8b");
    auto digest256      = sha3_256Of(a);
    assert(digest256 == cast(ubyte[]) hexString!
        "80084bf2fba02475726feb2cab2d8215eab14bc6bdd8bfb2c8151257032ecd8b");
    auto digest384      = sha3_384Of(a);
    assert(digest384 == cast(ubyte[]) hexString!(
        "1815f774f320491b48569efec794d249eeb59aae46d22bf77dafe25c5edc28d7"~
        "ea44f93ee1234aa88f61c91912a4ccd9"));
    auto digest512      = sha3_512Of(a);
    assert(digest512 == cast(ubyte[]) hexString!(
        "697f2d856172cb8309d6b8b97dac4de344b549d4dee61edfb4962d8698b7fa80"~
        "3f4f93ff24393586e28b5b957ac3d1d369420ce53332712f997bd336d09ab02a"));
    auto digestshake128 = shake128Of(a);
    assert(digestshake128 == cast(ubyte[]) hexString!
        "85c8de88d28866bf0868090b3961162b");
    auto digestshake256 = shake256Of(a);
    assert(digestshake256 == cast(ubyte[]) hexString!(
        "867e2cb04f5a04dcbd592501a5e8fe9ceaafca50255626ca736c138042530ba4"));
        
    immutable string abc = "abc";
    
    digest224      = sha3_224Of(abc);
    assert(digest224 == cast(ubyte[]) hexString!
        "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf");
    digest256      = sha3_256Of(abc);
    assert(digest256 == cast(ubyte[]) hexString!
        "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");
    digest384      = sha3_384Of(abc);
    assert(digest384 == cast(ubyte[]) hexString!(
        "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b2"~
        "98d88cea927ac7f539f1edf228376d25"));
    digest512      = sha3_512Of(abc);
    assert(digest512 == cast(ubyte[]) hexString!(
        "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e"~
        "10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"));
    digestshake128 = shake128Of(abc);
    assert(digestshake128 == cast(ubyte[]) hexString!
        "5881092dd818bf5cf8a3ddb793fbcba7");
    digestshake256 = shake256Of(abc);
    assert(digestshake256 == cast(ubyte[]) hexString!(
        "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739"));
    
    immutable string longString =
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    
    digest224      = sha3_224Of(longString);
    assert(digest224 == cast(ubyte[]) hexString!
        "8a24108b154ada21c9fd5574494479ba5c7e7ab76ef264ead0fcce33");
    digest256      = sha3_256Of(longString);
    assert(digest256 == cast(ubyte[]) hexString!
        "41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376");
    digest384      = sha3_384Of(longString);
    assert(digest384 == cast(ubyte[]) hexString!(
        "991c665755eb3a4b6bbdfb75c78a492e8c56a22c5c4d7e429bfdbc32b9d4ad5a"~
        "a04a1f076e62fea19eef51acd0657c22"));
    digest512      = sha3_512Of(longString);
    assert(digest512 == cast(ubyte[]) hexString!(
        "04a371e84ecfb5b8b77cb48610fca8182dd457ce6f326a0fd3d7ec2f1e91636d"~
        "ee691fbe0c985302ba1b0d8dc78c086346b533b49c030d99a27daf1139d6e75e"));
    digestshake128 = shake128Of(longString);
    assert(digestshake128 == cast(ubyte[]) hexString!
        "1a96182b50fb8c7e74e0a707788f55e9");
    digestshake256 = shake256Of(longString);
    assert(digestshake256 == cast(ubyte[]) hexString!(
        "4d8c2dd2435a0128eefbb8c36f6f87133a7911e18d979ee1ae6be5d4fd2e3329"));
    
    ubyte[] onemilliona = new ubyte[1_000_000];
    onemilliona[] = 'a';
    
    digest224      = sha3_224Of(onemilliona);
    assert(digest224 == cast(ubyte[]) hexString!
        "d69335b93325192e516a912e6d19a15cb51c6ed5c15243e7a7fd653c");
    digest256      = sha3_256Of(onemilliona);
    assert(digest256 == cast(ubyte[]) hexString!
        "5c8875ae474a3634ba4fd55ec85bffd661f32aca75c6d699d0cdcb6c115891c1");
    digest384      = sha3_384Of(onemilliona);
    assert(digest384 == cast(ubyte[]) hexString!(
        "eee9e24d78c1855337983451df97c8ad9eedf256c6334f8e948d252d5e0e7684"~
        "7aa0774ddb90a842190d2c558b4b8340"));
    digest512      = sha3_512Of(onemilliona);
    assert(digest512 == cast(ubyte[]) hexString!(
        "3c3a876da14034ab60627c077bb98f7e120a2a5370212dffb3385a18d4f38859"~
        "ed311d0a9d5141ce9cc5c66ee689b266a8aa18ace8282a0e0db596c90b0a7b87"));
    digestshake128 = shake128Of(onemilliona);
    assert(digestshake128 == cast(ubyte[]) hexString!
        "9d222c79c4ff9d092cf6ca86143aa411");
    digestshake256 = shake256Of(onemilliona);
    assert(digestshake256 == cast(ubyte[]) hexString!(
        "3578a7a4ca9137569cdf76ed617d31bb994fca9c1bbf8b184013de8234dfd13a"));
}

// Because WrapperDigest requires functions to be nothrow
version (SHA3D_Trace) {}
else
{
    /// OOP API SHA-3/SHAKE implementation alias.
    public alias SHA3_224Digest = WrapperDigest!SHA3_224;
    /// Ditto
    public alias SHA3_256Digest = WrapperDigest!SHA3_256;
    /// Ditto
    public alias SHA3_384Digest = WrapperDigest!SHA3_384;
    /// Ditto
    public alias SHA3_512Digest = WrapperDigest!SHA3_512;
    /// Ditto
    public alias SHAKE128Digest = WrapperDigest!SHAKE128;
    /// Ditto
    public alias SHAKE256Digest = WrapperDigest!SHAKE256;
    
    /// Using the OOP API.
    @system unittest
    {
        import std.conv : hexString;
        
        SHA3_224Digest sha3_224 = new SHA3_224Digest();
        assert(sha3_224.finish() == cast(ubyte[]) hexString!
            "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7");
        
        SHA3_256Digest sha3_256 = new SHA3_256Digest();
        assert(sha3_256.finish() == cast(ubyte[]) hexString!
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
        
        SHA3_384Digest sha3_384 = new SHA3_384Digest();
        assert(sha3_384.finish() == cast(ubyte[]) hexString!(
            "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2a"~
            "c3713831264adb47fb6bd1e058d5f004"));
        
        SHA3_512Digest sha3_512 = new SHA3_512Digest();
        assert(sha3_512.finish() == cast(ubyte[]) hexString!(
            "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6"~
            "15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"));
        
        SHAKE128Digest shake128 = new SHAKE128Digest();
        assert(shake128.finish() == cast(ubyte[]) hexString!(
            "7f9c2ba4e88f827d616045507605853e"));
        
        SHAKE256Digest shake256 = new SHAKE256Digest();
        assert(shake256.finish() == cast(ubyte[]) hexString!(
            "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"));
    }
}

/// Testing with HMAC
@system unittest
{
    // NOTE: OpenSSL (3.0.1) seems to be incapable of producing a hash
    //       using SHAKE and HMAC. However, this should work since
    //       unittests for SHAKE-related hashes are passing.
    
    import std.ascii : LetterCase;
    import std.string : representation;
    import std.digest.hmac : hmac;
    
    immutable string input =
        "The quick brown fox jumps over the lazy dog";
    auto secret = "secret".representation;
    
    assert(input
        .representation
        .hmac!SHA3_256(secret)
        .toHexString!(LetterCase.lower) ==
	    "93379fab68fae6d0fde0c816ea8a49fbd3c80f136c6af08bc61df5268d01b4d8");
    assert(input
        .representation
        .hmac!SHA3_512(secret)
        .toHexString!(LetterCase.lower) ==
	    "394e52da72b28bab49174a0d22cd48eac415de750027e6485ceb945b9948d8ae"~
        "e656e61e217ac1352a41c66454e2a9ae830fddbdf4f8aa6215c586b88e158ee8");
}

// because of WrapperDigest
version (SHA3D_Trace) {}
else
{
    /// Testing out various SHAKE XOFs.
    @system unittest
    {
        import std.conv : hexString;
        
        // Define SHAKE-128/256
        alias SHAKE128_256 = KECCAK!(128, 256);
        alias SHAKE128_256Digest = WrapperDigest!SHAKE128_256;
        auto shake128_256Of(T...)(T data) { return digest!(SHAKE128_256, T)(data); }
        
        // SHAKE128("", 256) =
        auto shake128_256empty = hexString!(
            "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26");
        
        // Using convenience alias
        assert(shake128_256Of("") == shake128_256empty);
        
        // Using OOP API
        Digest shake128_256 = new SHAKE128_256Digest();
        assert(shake128_256.finish() == shake128_256empty);
        
        // Define SHAKE-256/512
        alias SHAKE256_512 = KECCAK!(256, 512);
        alias SHAKE256_512Digest = WrapperDigest!SHAKE256_512;
        auto shake256_512Of(T...)(T data) { return digest!(SHAKE256_512, T)(data); }
        
        // SHAKE256("", 512) =
        auto shake256_512empty = hexString!(
            "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"~
            "d75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be");
        
        // Convenience alias
        assert(shake256_512Of("") == shake256_512empty);
        
        // OOP API
        Digest shake256_512 = new SHAKE256_512Digest();
        assert(shake256_512.finish() == shake256_512empty);
    }
}

/// Stretching out XOFs functions to extremes.
@system unittest
{
    import std.conv : hexString;
    
    // Define SHAKE-256/2048
    alias SHAKE256_2048 = KECCAK!(256, 2048);
    auto shake256_2048Of(T...)(T data) { return digest!(SHAKE256_2048, T)(data); }
    
    // SHAKE-256/2048('abc')
    assert(shake256_2048Of("abc") == hexString!(
        "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739"~
        "d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4"~
        "1385141204f329979fd3047a13c5657724ada64d2470157b3cdc288620944d78"~
        "dbcddbd912993f0913f164fb2ce95131a2d09a3e6d51cbfc622720d7a75c6334"~
        "e8a2d7ec71a7cc29cf0ea610eeff1a588290a53000faa79932becec0bd3cd0b3"~
        "3a7e5d397fed1ada9442b99903f4dcfd8559ed3950faf40fe6f3b5d710ed3b67"~
        "7513771af6bfe11934817e8762d9896ba579d88d84ba7aa3cdc7055f6796f195"~
        "bd9ae788f2f5bb96100d6bbaff7fbc6eea24d4449a2477d172a5507dcc931412"));
}

version (TestOverflow)
{
    /// Testing against buffer overflow
    // https://mouha.be/sha-3-buffer-overflow/
    @system unittest
    {
        import std.conv : hexString;
        import core.memory : GC;
        
        ubyte[] buf = new ubyte[4294967295];
        
        // Test for overflow
        SHA3_224 sha3_224;
        sha3_224.put(0);
        sha3_224.put(buf);
        
        GC.free(buf.ptr);
        
        assert(sha3_224.finish() == cast(ubyte[]) hexString!(
            "c5bcc3bc73b5ef45e91d2d7c70b64f196fac08eee4e4acf6e6571ebe"));
    
        ubyte[] buf2 = new ubyte[4294967296];
        
        // Test for infinite loop
        sha3_224.start();
        sha3_224.put(0);
        sha3_224.put(buf2);
    
        GC.free(buf2.ptr);
    }
}

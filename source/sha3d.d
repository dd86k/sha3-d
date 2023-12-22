/// Computes SHA-3 hashes of arbitrary data using a native implementation.
/// Standards: NIST FIPS PUB 202
/// License: $(LINK2 https://www.boost.org/LICENSE_1_0.txt, Boost License 1.0)
/// Authors: $(LINK2 https://github.com/dd86k, dd86k)
module sha3d;

/// Version string of sha3-d that can be used for printing purposes.
public enum SHA3D_VERSION_STRING = "1.3.0-dev";

private import std.digest;
private import core.bitop : rol, bswap;

version (SHA3D_Trace)
    private import std.stdio;

//TODO: Extra delimiter parameters (with delimiter2 and delimiter3)
//      For TurboSHAKE, there are additional domain separators used.
/// Template API SHA-3/SHAKE implementation using the Keccak function.
///
/// It is highly recommended to use the SHA3_224, SHA3_256, SHA3_384, SHA3_512,
/// SHAKE128, and SHAKE256 template aliases complying with NIST FIPS 202.
///
/// To use SHAKE256 with a different XOF digest size, define an alias as
/// `KECCAK!(256, 1024)` where 1024 is the output size in bits. For example,
/// a drop-in replacement for Git hashes could be defined as `KECCAK!(256, 160)`.
///
/// Otherwise, the structure template offers a few parameters, mainly
/// digest size (output size in bits), xof size (xof output size in bits, d parameter)
/// which overrides digest size if used, width (b parameter in bits),
/// and number of rounds in the transformation function.
///
/// By default, the SHA-3 delimiter (D parameter of 0x06) is used. If the
/// shake digest size parameter is used, the SHAKE delimiter is used (0x1f).
///
/// Examples:
/// ---
/// // Defines SHAKE128-512 XOF with Template API, OOP API, and helper function.
/// alias SHAKE128_512 = KECCAK!(128, 512);
/// alias SHAKE128_512Digest = WrapperDigest!SHAKE128_512;
/// auto shake128_512Of(T...)(T data) { return digest!(SHAKE128_512, T)(data); }
/// ---
///
/// Params:
///   digestSize = Digest size in bits.
///   shakeSize = SHAKE XOF digest size in bits, replacing digest size. Defaults to 0 for SHA-3.
///   width = Permutation size in bits, must be a multiple of 25 up to 1600. Defaults to 1600.
///   rounds = Number of rounds for transformation function. Defaults to 24.
///
/// Warning: Other width settings than 1600 could not be currently tested.
///
/// This implementation is not compatible with TurboSHAKE, KangarooTwelve,
/// cSHAKE, and others, because of the extra implementation details requirements
/// which are currently absent from this implementation.
///
/// Throws: No exceptions are thrown.
public struct KECCAK(uint digestSize,
    uint shakeSize = 0, uint width = 1600, size_t rounds = 24)
{
    version (SHA3D_Trace) {} else
    {
        @safe: @nogc: nothrow: pure:
    }
    
    static assert(width % 25 == 0, "Width must be a power of 25.");
    static assert(width <= 1600,   "Width can't be over 1600 bits.");
    static assert(width >=  200,   "Widths under 200 bits is currently not supported.");
    static assert(rounds <= 24,    "Can't have more than 24 rounds.");
    static assert(rounds  >  0,    "Must have one or more rounds.");
    
    // NOTE: Type selection
    //
    //       The b (input bits) parameter determines w (width in bits):
    //
    //       | b | 25 | 50 | 100 | 200 | 400 | 800 | 1600 | (state size)
    //       | w |  1 |  2 |   4 |   8 |  16 |  32 |   64 | (word size)
    //       | l |  0 |  1 |   2 |   3 |   4 |   5 |    6 | (lane size)
    //
    //       The official Keccak Team XKCP package only covers down to 200.
    //       So, w=8:ubyte, w=16:ushort, w=32:uint, and w=64:ulong
    
    // NOTE: Rounds
    //
    //       Extra rounds would be restarting from the end of the defined arrays:
    //       "the preceding rounds for KECCAK-p[1600, 30] are indexed by
    //       the integers from -6 to -1."
    //       While possible, not supported by any implementation.
    //
    //       KeccakTools specifies a number of nominal rounds. They only exist
    //       in name so they're not really suggestions. They are: 24 for b=1600,
    //       22 for b=800, 20 for b=400, 18 for b=200, 16 for b=100, 14 for b=50,
    //       and 12 for b=25.
    
    static if (width == 1600)
    {
        /// RC values for Keccak-p[1600]
        private enum K_RC_IMPL = [ // @suppress(dscanner.performance.enum_array_literal)
            0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
            0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
            0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
            0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
            0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
            0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008
        ];
        private enum K_RHO_IMPL = [ // @suppress(dscanner.performance.enum_array_literal)
             1,  3,  6, 10, 15, 21, 28, 36, 45, 55,  2, 14,
            27, 41, 56,  8, 25, 43, 62, 18, 39, 61, 20, 44
        ];
        alias ktype = ulong;
    }
    else static if (width == 800)
    {
        /// RC values for Keccak-p[800]
        private enum K_RC_IMPL = [ // @suppress(dscanner.performance.enum_array_literal)
            0x00000001, 0x00008082, 0x0000808A, 0x80008000,
            0x0000808B, 0x80000001, 0x80008081, 0x00008009,
            0x0000008A, 0x00000088, 0x80008009, 0x8000000A,
            0x8000808B, 0x0000008B, 0x00008089, 0x00008003,
            0x00008002, 0x00000080, 0x0000800A, 0x8000000A,
            0x80008081, 0x00008080, 0x80000001, 0x80008008
        ];
        private enum K_RHO_IMPL = [ // @suppress(dscanner.performance.enum_array_literal)
             1,  3,  6, 10, 15, 21, 28,  4, 13, 23,  2, 14,
            27,  9, 24,  8, 25, 11, 30, 18,  7, 29, 20, 12
        ];
        alias ktype = uint;
    }
    else static if (width == 400)
    {
        /// RC values for Keccak-p[400]
        private enum K_RC = [ // @suppress(dscanner.performance.enum_array_literal)
            0x0001, 0x8082, 0x808a, 0x8000,
            0x808b, 0x0001, 0x8081, 0x8009,
            0x008a, 0x0088, 0x8009, 0x000a,
            0x808b, 0x008b, 0x8089, 0x8003,
            0x8002, 0x0080, 0x800a, 0x000a,
            0x8081, 0x8080, 0x0001, 0x8008
        ];
        private enum K_RHO_IMPL = [ // @suppress(dscanner.performance.enum_array_literal)
            1,  3, 6, 10, 15,  5, 12, 4, 13,  7, 2, 14,
            11, 9, 8,  8,  9, 11, 14, 2,  7, 13, 4, 12
        ];
        alias ktype = ushort;
    }
    else static if (width == 200)
    {
        /// RC values for Keccak-p[200]
        private enum K_RC = [ // @suppress(dscanner.performance.enum_array_literal)
            0x01, 0x82, 0x8a, 0x00,
            0x8b, 0x01, 0x81, 0x09,
            0x8a, 0x88, 0x09, 0x0a,
            0x8b, 0x8b, 0x89, 0x03,
            0x02, 0x80, 0x0a, 0x0a,
            0x81, 0x80, 0x01, 0x08
        ];
        private enum K_RHO_IMPL = [ // @suppress(dscanner.performance.enum_array_literal)
            1, 3, 6, 2, 7, 5, 4, 4, 5, 7, 2, 6,
            3, 1, 0, 0, 1, 3, 6, 2, 7, 5, 4, 4,
        ];
        alias ktype = ubyte;
    }
    else
        static assert(0, "Unsupported width parameter");
    
    /// RC constants.
    private immutable static ktype[rounds] K_RC = K_RC_IMPL[0..rounds];
    
    static if (shakeSize)
    {
        static assert(digestSize == 128 || digestSize == 256,
            "SHAKE digest size must be 128 or 256 bits");
        static assert(shakeSize > 0,
            "SHAKE digest size must be higher than zero.");
        static assert(shakeSize % 8 == 0,
            "SHAKE digest size must be a factor of 25.");
        private enum digestSizeBytes = shakeSize / 8; /// Digest size in bytes
    }
    else // SHA-3
    {
        static assert(digestSize == 224 || digestSize == 256 ||
            digestSize == 384 || digestSize == 512,
            "SHA-3 digest size must be 224, 256, 384, or 512 bits");
        private enum digestSizeBytes = digestSize / 8; /// Digest size in bytes
    }
    
    // KeccakRhoOffsets[i] = ((i+1)*(i+2)/2) % w;
    // NOTE: rol *wants* const int
    /// Rho indexes.
    private immutable static int[24] K_RHO = K_RHO_IMPL;
    /// PI indexes.
    private immutable static size_t[24] K_PI = [
        10,  7, 11, 17, 18, 3,  5, 16,  8, 21, 24, 4,
        15, 23, 19, 13, 12, 2, 20, 14, 22,  9,  6, 1
    ];
    
    /// Block size in bits as required for HMAC.
    ///
    /// It is calculated using: width - digestSize * 2.
    enum blockSize = width - digestSize * 2;
    
    //  ..00: Reserved
    //  ..01: SHA-3
    //  ..11: RawSHAKE
    //  1111: SHAKE
    private enum delim = shakeSize ? 0x1f : 0x06; /// Padding delimiter when finishing
    private enum capacity = width - blockSize; /// Capacity in bits
    private enum rate = (width - capacity) / 8; /// Sponge rate in bytes (width - capacity)
    private enum state8Size = width / 8; /// State size in bytes
    private enum stateSize = state8Size / ktype.sizeof;
    
    // NOTE: size_t[] statez was removed
    //       because of misalignment issues when b <= 1600
    union
    {
        private ktype[stateSize]   state;  // state
        private ubyte[state8Size]  state8; // state (ubyte)
    }
    static assert(state.sizeof == state8.sizeof, "State alias mismatch");
    
    private ktype[5] bc; // Transformation data
    private ktype t;     // Transformation temporary
    private size_t pt;   // Left-over sponge pointer
    
    version (SHA3D_Trace) // For tests anyway
    {
        uint round_counter;
        bool verbose;
    }
    
    /// Initiate or reset the state of the instance.
    void start()
    {
        this = typeof(this).init;
    }
    
    version (SHA3D_Trace)
    void enable_verbose()
    {
        verbose = true;
        writeln("keccak.init capacity=", capacity, " rate=", rate, " statesz=", state8Size);
    }
    
    /// Feed the algorithm with data.
    /// Also implements the $(REF isOutputRange, std,range,primitives)
    /// interface for `ubyte` and `const(ubyte)[]`.
    /// Params: input = Input data to digest
    void put(scope const(ubyte)[] input...) @trusted
    {
        size_t i = pt;
        
        // Process wordwise if properly word-aligned aligned.
        // Disabled if the width is lower than 400 (ktype=short).
        static if (width >= 400)
        {
            if ((i | cast(ktype)input.ptr) % ktype.alignof == 0)
            {
                static assert(rate % ktype.sizeof == 0);
                foreach (const word; (cast(ktype*)input.ptr)[0..input.length / ktype.sizeof])
                {
                    state[i / ktype.sizeof] ^= word;
                    i += size_t.sizeof;
                    if (i >= rate)
                    {
                        transform;
                        i = 0;
                    }
                }
                input = input[input.length - (input.length % ktype.sizeof)..input.length];
            }
        }
        
        // Process remainder bytewise.
        foreach (const b; input)
        {
            state8.ptr[i++] ^= b;
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
        // Mark delimiter at end of message and padding at the end of sponge.
        state8[pt] ^= delim;
        state8[rate - 1] ^= 0x80;
        
        static if (shakeSize)
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
                    output[i..$] = state8[0..digestSizeBytes - i];
                    break;
                }
                output[i..end] = state8[0..rate];
                i += rate;
            } while (true);
            
            // Clear state of potential sensitive data.
            state[] = 0;
            bc[] = t = 0;
            
            version (SHA3D_Trace)
            {
                if (verbose) writeln("HASH=", toHexString!(LetterCase.lower)(output));
            }
            
            return output;
        }
        else // SHA-3
        {
            transform;
            
            // Clear potentially sensitive data.
            // State sanitized only if digestSize is less than state
            // of 1600 bits, so 200 Bytes.
            static if (digestSizeBytes < stateSize)
                state8[digestSizeBytes..$] = 0;
            bc[] = t = 0;
            
            version (SHA3D_Trace)
            {
                ubyte[digestSizeBytes] r = state8[0..digestSizeBytes];
                if (verbose) writeln("HASH=", toHexString!(LetterCase.lower)(r));
                return r;
            }
            else
            {
                return state8[0..digestSizeBytes];
            }
        }
    }
    
private:
    
    void transform()
    {
        version (BigEndian) swap;
        
        version (SHA3D_Trace) if (verbose) writefln("keccak.transform=%d", ++round_counter);

        for (size_t round; round < rounds; ++round)
        {
            // Theta
            THETA1(0); THETA1(1); THETA1(2); THETA1(3); THETA1(4);
            THETA2(0); THETA2(1); THETA2(2); THETA2(3); THETA2(4);
            t = state[1];
            // Rho
            RHO(0); RHO(1); RHO(2); RHO(3); RHO(4);
            RHO(5); RHO(6); RHO(7); RHO(8); RHO(9);
            RHO(10); RHO(11); RHO(12); RHO(13); RHO(14);
            RHO(15); RHO(16); RHO(17); RHO(18); RHO(19);
            RHO(20); RHO(21); RHO(22); RHO(23);
            // Chi
            CHI(0); CHI(5); CHI(10); CHI(15); CHI(20);
            // Iota
            state[0] ^= K_RC[round];
            
            version (SHA3D_Trace)
            {
                if (verbose)
                {
                    writefln("keccak.round=%d", round + 1);
                    int i;
                    foreach (ulong s; state)
                        if (i & 1)
                            writefln(" s[%2d]=%16x", i++, s);
                        else
                            writef("\ts[%2d]=%16x", i++, s);
                    writeln;
                }
            }
        }

        version (BigEndian) swap;
    }
    
    pragma(inline, true)
    void THETA1(size_t i)
    {
        bc[i] = state[i] ^ state[i + 5] ^ state[i + 10] ^
            state[i + 15] ^ state[i + 20];
    }
    
    pragma(inline, true)
    void THETA2(size_t i)
    {
        t = bc[(i + 4) % 5] ^ rol(bc[(i + 1) % 5], 1);
        state[     i] ^= t;
        state[ 5 + i] ^= t;
        state[10 + i] ^= t;
        state[15 + i] ^= t;
        state[20 + i] ^= t;
    }
    
    pragma(inline, true)
    void RHO(size_t i)
    {
        size_t j = K_PI[i];
        bc[0] = state[j];
        state[j] = rol(t, K_RHO[i]);
        t = bc[0];
    }
    
    pragma(inline, true)
    void CHI(size_t j)
    {
        bc[0] = state[j];
        bc[1] = state[j + 1];
        bc[2] = state[j + 2];
        bc[3] = state[j + 3];
        bc[4] = state[j + 4];

        state[j]     ^= (~bc[1]) & bc[2];
        state[j + 1] ^= (~bc[2]) & bc[3];
        state[j + 2] ^= (~bc[3]) & bc[4];
        state[j + 3] ^= (~bc[4]) & bc[0];
        state[j + 4] ^= (~bc[0]) & bc[1];
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

/// Checks block sizes from FIPS PUB 202, used for HMAC.
@safe unittest
{
    static assert(SHA3_224.blockSize / 8 == 144);
    static assert(SHA3_256.blockSize / 8 == 136);
    static assert(SHA3_384.blockSize / 8 == 104);
    static assert(SHA3_512.blockSize / 8 ==  72);
}

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
version (SHA3D_Trace) {} else
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

/// Making digests using XOFs.
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
    
    // Define SHAKE-256/160
    // Test: KeccakSum --shake256 --outputbits 160 --hex empty_file
    alias SHAKE256_160 = KECCAK!(256, 160);
    auto shake256_160Of(T...)(T data) { return digest!(SHAKE256_160, T)(data); }
    
    assert(shake256_160Of("") == hexString!(
        "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea"));
}

/// Testing with HMAC
@system unittest
{
    // NOTE: OpenSSL (3.0.1) seems to be incapable of producing a hash
    //       using SHAKE and HMAC. However, this should work since
    //       unittests for SHA3+HMAC hashes are already passing.
    
    import std.ascii : LetterCase;
    import std.string : representation;
    import std.digest.hmac : hmac;
    
    string input = "The quick brown fox jumps over the lazy dog";
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

version (TestOverflow)
{
    /// Testing against buffer overflow.
    /// Enabled via "dub test -c test-overflow"
    // https://mouha.be/sha-3-buffer-overflow/
    @system unittest
    {
        import std.conv : hexString;
        import core.memory : GC;
        
        ubyte[] buf = new ubyte[uint.max];
        
        // Test for overflow
        SHA3_224 sha3_224;
        sha3_224.put(0);
        sha3_224.put(buf);
        
        GC.free(buf.ptr);
        
        assert(sha3_224.finish() == cast(ubyte[]) hexString!(
            "c5bcc3bc73b5ef45e91d2d7c70b64f196fac08eee4e4acf6e6571ebe"));
        
        ubyte[] buf2 = new ubyte[uint.max];
        
        // Test for infinite loop
        sha3_224.start();
        sha3_224.put(0);
        sha3_224.put(buf2);
        
        GC.free(buf2.ptr);
    }
}

/// K12 tests.
/+@system unittest
{
    import std.conv : hexString;
    
    // Defines primitive Keccak-p[1600,12]
    // Digest size of 256+8 bits, using SHA-3 delimiter
    alias K12 = KECCAK!(256, 256, 1600, 12);
    auto k12Of(T...)(T data) { return digest!(K12, T)(data); }
    // k12("")= 1ac2d450fc3b4205d19da7bfca1b37513c0803577ac7167f06fe2ce1f0ef39e542
    
    K12 k12;
    k12.enable_verbose();
    assert(k12.finish() == hexString!(
    //assert(k12Of("") == hexString!(
        "1ac2d450fc3b4205d19da7bfca1b37513c0803577ac7167f06fe2ce1f0ef39e542"));
}+/

/// Testing smaller widths.
/+@system unittest
{
    import std.conv : hexString;
    import std.stdio : writefln;
    
    // Keccak-p[800,22]
    // https://github.com/XKCP/XKCP/blob/master/tests/TestVectors/KeccakF-800-IntermediateValues.txt
    // The file only goes through 2 sets of arounds, which matches,
    // test vectors, but this requires at least 4 sets of rounds to finish
    // since the rate is 36 Bytes (3 rounds + 1 finishing).
    
    // Defines primitive Keccak-p[800,22]
    // Digest size of 256 bits, using SHA-3 delimiter
    alias KECCAK800 = KECCAK!(256, 0, 800, 22);
    auto k800Of(T...)(T data) { return digest!(KECCAK800, T)(data); }
    
    ubyte[] input = new ubyte[100];
    input[] = 0;
    
    /*
    5D D4 31 E5 FB C6 04 F4 99 BF A0 23 2F 45 F8 F1
    42 D0 FF 51 78 F5 39 E5 A7 80 0B F0 64 36 97 AF
    4C F3 5A BF 24 24 7A 22 15 27 17 88 84 58 68 9F
    54 D0 5C B1 0E FC F4 1B 91 FA 66 61 9A 59 9E 1A
    1F 0A 97 A3 87 96 65 AB 68 8D AB AF 15 10 4B E7
    98 1A 00 34 F3 EF 19 41 76 0E 0A 93 70 80 B2 87
    96 E9 EF 11
    */
    KECCAK800 k800;
    version (SHA3D_Trace) k800.enable_verbose();
    k800.put(input);
    ubyte[32] r = k800.finish();
    assert(r == hexString!(
    //assert(k800Of(input) == hexString!(
        "5dd431e5fbc604f499bfa0232f45f8f142d0ff5178f539e5a7800bf0643697af"));
}+/

/// Using XOF as a PRNG
/+@system unittest
{
    import std.conv : hexString;
    
    // Define SHAKE-256/1024
    alias SHAKE256_1024 = KECCAK!(256, 1024);
    
    SHAKE256_1024 digest;
    digest.put(cast(ubyte[])"abc"); // Seed ish
    
    assert(digest.finish() == hexString!(
        "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739"~
        "d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4"~
        "1385141204f329979fd3047a13c5657724ada64d2470157b3cdc288620944d78"~
        "dbcddbd912993f0913f164fb2ce95131a2d09a3e6d51cbfc622720d7a75c6334"));
    assert(digest.finish() == hexString!(
        "e8a2d7ec71a7cc29cf0ea610eeff1a588290a53000faa79932becec0bd3cd0b3"~
        "3a7e5d397fed1ada9442b99903f4dcfd8559ed3950faf40fe6f3b5d710ed3b67"~
        "7513771af6bfe11934817e8762d9896ba579d88d84ba7aa3cdc7055f6796f195"~
        "bd9ae788f2f5bb96100d6bbaff7fbc6eea24d4449a2477d172a5507dcc931412"));
}+/

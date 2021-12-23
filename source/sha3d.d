/// Computes SHA-3 hashes of arbitary data.
/// Reference: NIST FIPS PUB 202
/// License: $(LINK2 www.boost.org/LICENSE_1_0.txt, Boost License 1.0)
/// Authors: $(LINK2 github.com/dd86k, dd86k)
module sha3d;

public enum SHA3D_VERSION_STRING = "1.2.1";

private import std.digest;
private import core.bitop : rol, bswap;

private immutable ulong[24] K_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
    0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008
];
private immutable int[24] K_ROTC = [
     1,  3,  6, 10, 15, 21, 28, 36, 45, 55,  2, 14,
    27, 41, 56,  8, 25, 43, 62, 18, 39, 61, 20, 44
];
private immutable int[24] K_PI = [
    10,  7, 11, 17, 18, 3,  5, 16,  8, 21, 24, 4,
    15, 23, 19, 13, 12, 2, 20, 14, 22,  9,  6, 1
];

/// Template API SHA-3/SHAKE implementation using the Keccak[1600] function.
///
/// Supports SHA-3-224, SHA-3-256, SHA-3-384, SHA-3-512, SHAKE-128, and SHAKE-256.
/// It is recommended to use the SHA3_224, SHA3_256, SHA3_384, SHA3_512, SHAKE128,
/// and SHAKE256 template aliases.
///
/// To make a XOF (like SHAKE-128/256):
/// ---
/// alias SHAKE128_256 = KECCAK!(128, 256);
/// alias SHAKE128_256Digest = WrapperDigest!SHAKE128_256;
/// auto shake128_256Of(T...)(T data) { return digest!(SHAKE128_256, T)(data); }
/// ---
///
/// Params:
///   digestSize = Digest size in bits.
///   shake = Sets SHAKE XOF digest output. For example, KECCAK!(128, 256) results in SHAKE-128/256. Defaults to 0 for SHA-3.
public struct KECCAK(uint digestSize, uint shake = 0)
{
    static if (shake)
    {
        static assert(digestSize == 128 || digestSize == 256,
            "SHAKE digest size must be 128 or 256 bits");
        static assert(shake > 0 && shake <= 1600,
            "SHAKE digest size must be between 1 to 1600 bits");
        private enum digestSizeBytes = shake / 8; /// Digest size in bytes
    }
    else // SHA-3
    {
        static assert(digestSize == 224 || digestSize == 256 ||
            digestSize == 384 || digestSize == 512,
            "SHA-3 digest size must be 224, 256, 384, or 512 bits");
        private enum digestSizeBytes = digestSize / 8; /// Digest size in bytes
    }
    
    @safe @nogc pure nothrow:
    
    enum blockSize = (1600 - digestSize * 2);	/// Digest size in bits
    
    //  ...0: Reserved
    //    01: SHA-3
    // ...11: RawSHAKE
    //  1111: SHAKE
    private enum delim = shake ? 0x1f : 0x06; /// Delimiter suffix when finishing
    private enum rate = blockSize / 8; /// Sponge rate in bytes
    private enum stateSize = 200;
    private enum stateSt64Size = stateSize / 8;
    private enum stateStzSize = stateSize / size_t.sizeof;
    
    union
    {
        private ubyte[stateSize] st;  // state (8bit)
        private ulong[stateSt64Size] st64; // state (64bit)
        private size_t[stateStzSize] stz; // state (size_t)
    }
    static assert(st64.sizeof == st.sizeof);
    static assert(stz.sizeof == st.sizeof);
    
    private ulong[5] bc; // transformation data
    private ulong t; // transformation temporary
    private size_t pt; // left-over pointer
    
    /// Initiate or reset the state of the structure.
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
        size_t j = pt;
        
        // Process wordwise if properly aligned.
        if ((j | cast(size_t) input.ptr) % size_t.alignof == 0)
        {
            static assert(rate % size_t.sizeof == 0);
            foreach (const word; (cast(size_t*) input.ptr)[0 .. input.length / size_t.sizeof])
            {
                stz.ptr[j / size_t.sizeof] ^= word;
                j += size_t.sizeof;
                if (j >= rate)
                {
                    transform;
                    j = 0;
                }
            }
            input = input.ptr[input.length - (input.length % size_t.sizeof) .. input.length];
        }
        
        // Process remainder bytewise.
        foreach (const b; input)
        {
            st.ptr[j++] ^= b;
            if (j >= rate)
            {
                transform;
                j = 0;
            }
        }
        
        pt = j;
    }
    
    /// Returns the finished hash.
    /// This also clears part of the state, leaving just the final digest.
    /// Returns: Raw digest data.
    ubyte[digestSizeBytes] finish()
    {
        st[pt] ^= delim;
        st[rate - 1] ^= 0x80;
        transform;
        
        // Clear potentially sensitive data
        // State sanitized only if digestSize is less than 1600 bits (200 bytes)
        static if (digestSizeBytes < 200)
            st[digestSizeBytes .. $] = 0;
        bc[0..4] = 0;
        t = 0;
        return st[0 .. digestSizeBytes];
    }
    
private:
    
    void transform()
    {
        version (BigEndian) swap;

        ROUND( 0);
        ROUND( 1);
        ROUND( 2);
        ROUND( 3);
        ROUND( 4);
        ROUND( 5);
        ROUND( 6);
        ROUND( 7);
        ROUND( 8);
        ROUND( 9);
        ROUND(10);
        ROUND(11);
        ROUND(12);
        ROUND(13);
        ROUND(14);
        ROUND(15);
        ROUND(16);
        ROUND(17);
        ROUND(18);
        ROUND(19);
        ROUND(20);
        ROUND(21);
        ROUND(22);
        ROUND(23);

        version (BigEndian) swap;
    }
    
    void THETA1(size_t i)
    {
        bc[i] = st64[i] ^ st64[i + 5] ^ st64[i + 10] ^ st64[i + 15] ^ st64[i + 20];
    }
    
    void THETA2(size_t i)
    {
        t = bc[(i + 4) % 5] ^ rol(bc[(i + 1) % 5], 1);
        st64[     i] ^= t;
        st64[ 5 + i] ^= t;
        st64[10 + i] ^= t;
        st64[15 + i] ^= t;
        st64[20 + i] ^= t;
    }
    
    void RHO(size_t i)
    {
        int j = K_PI[i];
        bc[0] = st64[j];
        st64[j] = rol(t, K_ROTC[i]);
        t = bc[0];
    }
    
    void CHI(size_t j)
    {
        bc[0] = st64[j];
        bc[1] = st64[j + 1];
        bc[2] = st64[j + 2];
        bc[3] = st64[j + 3];
        bc[4] = st64[j + 4];

        st64[j]     ^= (~bc[1]) & bc[2];
        st64[j + 1] ^= (~bc[2]) & bc[3];
        st64[j + 2] ^= (~bc[3]) & bc[4];
        st64[j + 3] ^= (~bc[4]) & bc[0];
        st64[j + 4] ^= (~bc[0]) & bc[1];
    }
    
    void ROUND(size_t r)
    {
        // Theta
        THETA1(0);
        THETA1(1);
        THETA1(2);
        THETA1(3);
        THETA1(4);
        THETA2(0);
        THETA2(1);
        THETA2(2);
        THETA2(3);
        THETA2(4);
        t = st64[1];
        // Rho
        RHO(0);
        RHO(1);
        RHO(2);
        RHO(3);
        RHO(4);
        RHO(5);
        RHO(6);
        RHO(7);
        RHO(8);
        RHO(9);
        RHO(10);
        RHO(11);
        RHO(12);
        RHO(13);
        RHO(14);
        RHO(15);
        RHO(16);
        RHO(17);
        RHO(18);
        RHO(19);
        RHO(20);
        RHO(21);
        RHO(22);
        RHO(23);
        // Chi
        CHI(0);
        CHI(5);
        CHI(10);
        CHI(15);
        CHI(20);
        // Iota
        st64[0] ^= K_RC[r];
    }
    
    version (BigEndian)
    void swap()
    {
        st64[ 0] = bswap(st64[ 0]);
        st64[ 1] = bswap(st64[ 1]);
        st64[ 2] = bswap(st64[ 2]);
        st64[ 3] = bswap(st64[ 3]);
        st64[ 4] = bswap(st64[ 4]);
        st64[ 5] = bswap(st64[ 5]);
        st64[ 6] = bswap(st64[ 6]);
        st64[ 7] = bswap(st64[ 7]);
        st64[ 8] = bswap(st64[ 8]);
        st64[ 9] = bswap(st64[ 9]);
        st64[10] = bswap(st64[10]);
        st64[11] = bswap(st64[11]);
        st64[12] = bswap(st64[12]);
        st64[13] = bswap(st64[13]);
        st64[14] = bswap(st64[14]);
        st64[15] = bswap(st64[15]);
        st64[16] = bswap(st64[16]);
        st64[17] = bswap(st64[17]);
        st64[18] = bswap(st64[18]);
        st64[19] = bswap(st64[19]);
        st64[20] = bswap(st64[20]);
        st64[21] = bswap(st64[21]);
        st64[22] = bswap(st64[22]);
        st64[23] = bswap(st64[23]);
    }
}

// Unittest based on https://www.di-mgt.com.au/sha_testvectors.html

/// Test against empty datasets
@safe unittest
{
    assert(toHexString(sha3_224Of("")) ==
        "6B4E03423667DBB73B6E15454F0EB1ABD4597F9A1B078E3F5B5A6BC7");

    assert(toHexString(sha3_256Of("")) ==
        "A7FFC6F8BF1ED76651C14756A061D662F580FF4DE43B49FA82D80A4B80F8434A");

    assert(toHexString(sha3_384Of("")) ==
        "0C63A75B845E4F7D01107D852E4C2485C51A50AAAA94FC61995E71BBEE983A2AC37138"~
        "31264ADB47FB6BD1E058D5F004");

    assert(toHexString(sha3_512Of("")) ==
        "A69F73CCA23A9AC5C8B567DC185A756E97C982164FE25859E0D1DCC1475C80A615B212"~
        "3AF1F5F94C11E3E9402C3AC558F500199D95B6D3E301758586281DCD26");

    assert(toHexString(shake128Of("")) == "7F9C2BA4E88F827D616045507605853E");

    assert(toHexString(shake256Of("")) ==
        "46B9DD2B0BA88D13233B3FEB743EEB243FCD52EA62B81B82B50C27646ED5762F");
}

/// Of wrappers + toHexString
@safe unittest
{
    assert(toHexString(sha3_224Of("abc")) ==
        "E642824C3F8CF24AD09234EE7D3C766FC9A3A5168D0C94AD73B46FDF");

    assert(toHexString(sha3_256Of("abc")) ==
        "3A985DA74FE225B2045C172D6BD390BD855F086E3E9D525B46BFE24511431532");

    assert(toHexString(sha3_384Of("abc")) ==
        "EC01498288516FC926459F58E2C6AD8DF9B473CB0FC08C2596DA7CF0E49BE4B298D88C"~
        "EA927AC7F539F1EDF228376D25");

    assert(toHexString(sha3_512Of("abc")) ==
        "B751850B1A57168A5693CD924B6B096E08F621827444F70D884F5D0240D2712E10E116"~
        "E9192AF3C91A7EC57647E3934057340B4CF408D5A56592F8274EEC53F0");
}

/// Structure functions
@safe unittest
{
    SHA3_224 hash;
    hash.start();
    ubyte[1024] data;
    hash.put(data);
    ubyte[28] result = hash.finish();
}

/// Template usage
@safe unittest
{
    // Let's use the template features:
    // NOTE: When passing a digest to a function, it must be passed by reference!
    void doSomething(T)(ref T hash)
        if (isDigest!T)
        {
            hash.put(cast(ubyte) 0);
        }
    SHA3_224 sha;
    sha.start();
    doSomething(sha);
    assert(toHexString(sha.finish()) ==
        "BDD5167212D2DC69665F5A8875AB87F23D5CE7849132F56371A19096");
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

@safe unittest
{
    assert(isDigest!SHA3_224);
    assert(isDigest!SHA3_256);
    assert(isDigest!SHA3_384);
    assert(isDigest!SHA3_512);
    assert(isDigest!SHAKE128);
    assert(isDigest!SHAKE256);
}

/// Convience alias for $(REF digest, std,digest) using the SHA-3 implementation.
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

/// digest! wrappers
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

/// Structures
@system unittest
{
    import std.conv : hexString;
    
    SHA3_224 dgst_sha3_224;
    dgst_sha3_224.put(cast(ubyte[]) "abcdef");
    dgst_sha3_224.start();
    dgst_sha3_224.put(cast(ubyte[]) "");
    assert(dgst_sha3_224.finish() ==
        cast(ubyte[]) hexString!"6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7");
    
    SHA3_256 dgst_sha3_256;
    dgst_sha3_256.put(cast(ubyte[]) "abcdef");
    dgst_sha3_256.start();
    dgst_sha3_256.put(cast(ubyte[]) "");
    assert(dgst_sha3_256.finish() ==
        cast(ubyte[]) hexString!"a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
    
    SHA3_384 dgst_sha3_384;
    dgst_sha3_384.put(cast(ubyte[]) "abcdef");
    dgst_sha3_384.start();
    dgst_sha3_384.put(cast(ubyte[]) "");
    assert(dgst_sha3_384.finish() ==
        cast(ubyte[]) hexString!("0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2a"
        ~"c3713831264adb47fb6bd1e058d5f004"));
    
    SHA3_512 dgst_sha3_512;
    dgst_sha3_512.put(cast(ubyte[]) "abcdef");
    dgst_sha3_512.start();
    dgst_sha3_512.put(cast(ubyte[]) "");
    assert(dgst_sha3_512.finish() ==
        cast(ubyte[]) hexString!("a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6"
        ~"15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"));
    
    SHAKE128 dgst_shake128;
    dgst_shake128.put(cast(ubyte[]) "abcdef");
    dgst_shake128.start();
    dgst_shake128.put(cast(ubyte[]) "");
    assert(dgst_shake128.finish() == cast(ubyte[]) hexString!"7f9c2ba4e88f827d616045507605853e");
    
    SHAKE256 dgst_shake256;
    dgst_shake256.put(cast(ubyte[]) "abcdef");
    dgst_shake256.start();
    dgst_shake256.put(cast(ubyte[]) "");
    assert(dgst_shake256.finish() ==
        cast(ubyte[]) hexString!"46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f");
}

/// "Of" wrappers like sha3_224Of
@system unittest
{
    import std.conv : hexString;
    
    immutable string a = "a";
    
    auto digest224      = sha3_224Of(a);
    assert(digest224 == cast(ubyte[]) hexString!"9e86ff69557ca95f405f081269685b38e3a819b309ee942f482b6a8b");
    auto digest256      = sha3_256Of(a);
    assert(digest256 == cast(ubyte[]) hexString!"80084bf2fba02475726feb2cab2d8215eab14bc6bdd8bfb2c8151257032ecd8b");
    auto digest384      = sha3_384Of(a);
    assert(digest384 == cast(ubyte[]) hexString!("1815f774f320491b48569efec794d"
        ~"249eeb59aae46d22bf77dafe25c5edc28d7ea44f93ee1234aa88f61c91912a4ccd9"));
    auto digest512      = sha3_512Of(a);
    assert(digest512 == cast(ubyte[]) hexString!("697f2d856172cb8309d6b8b97dac4de344b549d4dee61edfb4962d8698b7fa8"
        ~"03f4f93ff24393586e28b5b957ac3d1d369420ce53332712f997bd336d09ab02a"));
    auto digestshake128 = shake128Of(a);
    assert(digestshake128 == cast(ubyte[]) hexString!"85c8de88d28866bf0868090b3961162b");
    auto digestshake256 = shake256Of(a);
    assert(digestshake256 == cast(ubyte[]) hexString!("867e2cb04f5a04dcbd592501a5e8fe9ceaafca50255626ca736c138042"
        ~"530ba4"));
        
    immutable string abc = "abc";
    
    digest224      = sha3_224Of(abc);
    assert(digest224 == cast(ubyte[]) hexString!"e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf");
    digest256      = sha3_256Of(abc);
    assert(digest256 == cast(ubyte[]) hexString!"3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");
    digest384      = sha3_384Of(abc);
    assert(digest384 == cast(ubyte[]) hexString!("ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b"
        ~"298d88cea927ac7f539f1edf228376d25"));
    digest512      = sha3_512Of(abc);
    assert(digest512 == cast(ubyte[]) hexString!("b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712"
        ~"e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"));
    digestshake128 = shake128Of(abc);
    assert(digestshake128 == cast(ubyte[]) hexString!"5881092dd818bf5cf8a3ddb793fbcba7");
    digestshake256 = shake256Of(abc);
    assert(digestshake256 == cast(ubyte[]) hexString!("483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e7"
        ~"8b5739"));
    
    immutable string longString = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    
    digest224      = sha3_224Of(longString);
    assert(digest224 == cast(ubyte[]) hexString!"8a24108b154ada21c9fd5574494479ba5c7e7ab76ef264ead0fcce33");
    digest256      = sha3_256Of(longString);
    assert(digest256 == cast(ubyte[]) hexString!"41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376");
    digest384      = sha3_384Of(longString);
    assert(digest384 == cast(ubyte[]) hexString!("991c665755eb3a4b6bbdfb75c78a492e8c56a22c5c4d7e429bfdbc32b9d4ad5"
        ~"aa04a1f076e62fea19eef51acd0657c22"));
    digest512      = sha3_512Of(longString);
    assert(digest512 == cast(ubyte[]) hexString!("04a371e84ecfb5b8b77cb48610fca8182dd457ce6f326a0fd3d7ec2f1e91636"
        ~"dee691fbe0c985302ba1b0d8dc78c086346b533b49c030d99a27daf1139d6e75e"));
    digestshake128 = shake128Of(longString);
    assert(digestshake128 == cast(ubyte[]) hexString!"1a96182b50fb8c7e74e0a707788f55e9");
    digestshake256 = shake256Of(longString);
    assert(digestshake256 == cast(ubyte[]) hexString!("4d8c2dd2435a0128eefbb8c36f6f87133a7911e18d979ee1ae6be5d4fd"
        ~"2e3329"));
    
    ubyte[] onemilliona = new ubyte[1_000_000];
    onemilliona[] = 'a';
    
    digest224      = sha3_224Of(onemilliona);
    assert(digest224 == cast(ubyte[]) hexString!"d69335b93325192e516a912e6d19a15cb51c6ed5c15243e7a7fd653c");
    digest256      = sha3_256Of(onemilliona);
    assert(digest256 == cast(ubyte[]) hexString!"5c8875ae474a3634ba4fd55ec85bffd661f32aca75c6d699d0cdcb6c115891c1");
    digest384      = sha3_384Of(onemilliona);
    assert(digest384 == cast(ubyte[]) hexString!("eee9e24d78c1855337983451df97c8ad9eedf256c6334f8e948d252d5e0e768"
        ~"47aa0774ddb90a842190d2c558b4b8340"));
    digest512      = sha3_512Of(onemilliona);
    assert(digest512 == cast(ubyte[]) hexString!("3c3a876da14034ab60627c077bb98f7e120a2a5370212dffb3385a18d4f3885"
        ~"9ed311d0a9d5141ce9cc5c66ee689b266a8aa18ace8282a0e0db596c90b0a7b87"));
    digestshake128 = shake128Of(onemilliona);
    assert(digestshake128 == cast(ubyte[]) hexString!"9d222c79c4ff9d092cf6ca86143aa411");
    digestshake256 = shake256Of(onemilliona);
    assert(digestshake256 == cast(ubyte[]) hexString!("3578a7a4ca9137569cdf76ed617d31bb994fca9c1bbf8b184013de8234"
        ~"dfd13a"));
}

/// OOP API SHA-3/SHAKE implementation aliases.
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

/// Test OOP wrappers
@system unittest
{
    import std.conv : hexString;
    
    SHA3_224Digest sha3_224 = new SHA3_224Digest();
    assert(sha3_224.finish() == cast(ubyte[])
        hexString!"6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7");
    
    SHA3_256Digest sha3_256 = new SHA3_256Digest();
    assert(sha3_256.finish() == cast(ubyte[])
        hexString!"a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
    
    SHA3_384Digest sha3_384 = new SHA3_384Digest();
    assert(sha3_384.finish() == cast(ubyte[])
        hexString!("0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac371"~
        "3831264adb47fb6bd1e058d5f004"));
    
    SHA3_512Digest sha3_512 = new SHA3_512Digest();
    assert(sha3_512.finish() == cast(ubyte[])
        hexString!("a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615"~
        "b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"));
    
    SHAKE128Digest shake128 = new SHAKE128Digest();
    assert(shake128.finish() == cast(ubyte[])
        hexString!("7f9c2ba4e88f827d616045507605853e"));
    
    SHAKE256Digest shake256 = new SHAKE256Digest();
    assert(shake256.finish() == cast(ubyte[])
        hexString!("46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"));
}

/// Testing with HMAC
@system unittest
{
    import std.ascii : LetterCase;
    import std.string : representation;
    import std.digest.hmac : hmac;

    auto secret = "secret".representation;
    assert("The quick brown fox jumps over the lazy dog"
        .representation
        .hmac!SHA3_256(secret)
        .toHexString!(LetterCase.lower) ==
	"93379fab68fae6d0fde0c816ea8a49fbd3c80f136c6af08bc61df5268d01b4d8");
}

/// Testing out various SHAKE XOFs.
@system unittest
{
    import std.conv : hexString;
    
    // SHAKE128("", 256)
    auto shake128_256empty =
        hexString!("7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26");
    // SHAKE256("", 512)
    auto shake256_512empty =
        hexString!("46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"~
        "d75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be");
    
    // SHAKE-128/256
    alias SHAKE128_256 = KECCAK!(128, 256);
    alias SHAKE128_256Digest = WrapperDigest!SHAKE128_256;
    auto shake128_256Of(T...)(T data) { return digest!(SHAKE128_256, T)(data); }
    
    // Template API
    assert(shake128_256Of("") == shake128_256empty);
    
    // OOP API
    Digest shake128_256 = new SHAKE128_256Digest();
    assert(shake128_256.finish() == shake128_256empty);
    
    // SHAKE-256/512
    alias SHAKE256_512 = KECCAK!(256, 512);
    alias SHAKE256_512Digest = WrapperDigest!SHAKE256_512;
    auto shake256_512Of(T...)(T data) { return digest!(SHAKE256_512, T)(data); }
    
    // Template API
    assert(shake256_512Of("") == shake256_512empty);
    
    // OOP API
    Digest shake256_512 = new SHAKE256_512Digest();
    assert(shake256_512.finish() == shake256_512empty);
}

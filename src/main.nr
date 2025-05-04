// use dep::bignum::{params::BigNumParams, RuntimeBigNum};

// due to the bug with the RSA we don't need a function for a TLD yet; hence can think that DS is always a thing

use dep::aztec::macros::aztec;
#[aztec]
pub contract Main {
    // fn double(x: Field) -> pub Field { x * 2 }
    // fn triple(x: Field) -> pub Field { x * 3 }
    // fn quadruple(x: Field) -> pub Field { double(double(x)) }

    use std::{meta::derive, ops::{Add, Sub}};
    use dep::aztec::macros::storage::storage;
    use dep::aztec::prelude::Map;
    use dep::aztec::protocol_types::traits::{FromField, ToField, Hash};

    // TODO add `pub` and correct algorithm suffixes
    type P256Key = [u8; 64];
    // #[derive(Hash)]
    type Domain<NUM_LABELS: Field> = [str, NUM_LABELS];
    // #[derive(Hash)]
    struct ZoneKeyId<NUM_LABELS: Field> {
        domain: Domain<NUM_LABELS>,
        validity_to_from: (Field, Field),
        // tag: Field
    }
    // #[derive(Hash)]
    struct DkimKeySelectorId<NUM_LABELS: Field> {
        selector: str, 
        domain: Domain<NUM_LABELS>,
        // (Field, Field) // Validity time window
    };
    // #[derive(Hash)]
    struct DkimKeyDefaultId<NUM_LABELS: Field> {
        domain: Domain<NUM_LABELS>,
        validity_to_from: (Field, Field),
    }
    // #[derive(Hash)]
    struct DsId<NUM_LABELS: Field> {
        child: str,
        parent: Domain<NUM_LABELS - 1>,
    }

    type DomainDigest = Field;

    #[storage]
    struct Storage<Context> {
        // TODO I'm thinking about establish a bit complex tree structure and just provide getters for the API
        // starting from `["com"]` TODO _from `[]`_
        // as DNSSEC uses different algorithms a `Map` sig-key value is a `Vec<u8>` to represent all of them
        registry_ds: dep::aztec::prelude::Map<DomainDigest, Ds, Context>,
        registry_keysigkey: Map<Field, Ksigk>,
        registry_zonesigkey: Map<Field, Zsigk>,
        registry_dkimkey_selector: Map<Field, Map<
            Field, // a DKIM-key digest
            (
                DkimKey,
                bool, // is revoked
                Field, // no later
                Field, // not before
            )
        >>
        // registry_dkimkey_default = Map<DomainDigest, Map<
        //     Field, // a DKIM-key digest
        //     DkimKey
        // >>
    }

    pub fn add_zsigk_ecdsa256sha256(
        /// take this from a verified source
        ksigk: P256Key,

        // other args will be checked

        ksigk_rrset_position: u32,
        // delegationsigner: _,
        rrset_dnskey: Vec<u8>,
        rrsig_dnskey: P256Key,
        zsigk: P256Key,
        zsigk_rrset_position: u32,
        // time and tag shouldn't go here -- deal with it downstream in a contract
    ) {
        for i in 0..63 {
            rrset_dnskey[ksigk_rrset_position + i] = ksigk[i];
            rrset_dnskey[zsigk_rrset_position + i] = zsigk[i];
        }

        assert(std::ecdsa_secp256r1::verify_signature(ksigk[0..31], ksigk[31..], rrsig_dnskey, dep::sha256::sha256_var(rrset_dnskey, rrset_dnskey.len())));
    }

    pub fn add_ds_ecdsa(
        /// take this from a verified source
        parent_zsigk: ([u8; 32], [u8; 32]),
        
        ds_rrset: Vec<u8>,
        child_ksigk: ([u8; 32], [u8; 32]),
    ) {}

    pub fn add_dkim_ecdsa() {}
}

#[test]
fn test_paypalcom_pp_ndash_dkim1_txt() {
    assert(std::ecdsa_secp256r1::verify_signature(
        [
            63,
            205,
            154,
            30,
            253,
            187,
            190,
            55,
            132,
            12,
            194,
            84,
            134,
            245,
            60,
            127,
            77,
            150,
            247,
            245,
            158,
            110,
            91,
            47,
            124,
            192,
            139,
            251,
            44,
            12,
            16,
            152,
        ],
        [
            3,
            255,
            220,
            108,
            69,
            43,
            105,
            56,
            152,
            89,
            11,
            209,
            48,
            103,
            137,
            208,
            6,
            195,
            252,
            174,
            80,
            57,
            174,
            28,
            151,
            101,
            240,
            92,
            129,
            207,
            59,
            238,
        ],
        [
            133,
            3,
            79,
            178,
            129,
            65,
            2,
            67,
            119,
            121,
            165,
            221,
            220,
            168,
            254,
            139,
            229,
            14,
            138,
            199,
            185,
            203,
            214,
            105,
            252,
            73,
            216,
            223,
            47,
            213,
            33,
            17,
            40,
            67,
            22,
            254,
            64,
            169,
            83,
            144,
            131,
            79,
            44,
            126,
            28,
            103,
            221,
            246,
            253,
            57,
            66,
            124,
            94,
            234,
            91,
            47,
            79,
            204,
            187,
            66,
            116,
            248,
            80,
            3,
        ],
        [190, 104, 21, 63, 5, 38, 46, 193, 97, 171, 69, 178, 157, 245, 203, 13, 99, 150, 97, 252, 242, 185, 185, 207, 130, 121, 103, 47, 81, 243, 19, 55]
    ));
}

#[test]
fn test_ecdsa_com_dnskey() {
    assert(std::ecdsa_secp256r1::verify_signature(
        [
            183,
            31,
            4,
            101,
            16,
            29,
            219,
            226,
            191,
            12,
            148,
            85,
            209,
            47,
            161,
            108,
            28,
            218,
            68,
            244,
            191,
            27,
            162,
            85,
            52,
            24,
            173,
            31,
            58,
            169,
            176,
            105,
        ],
        [
            115,
            242,
            27,
            132,
            235,
            83,
            44,
            244,
            3,
            94,
            232,
            212,
            131,
            44,
            162,
            109,
            137,
            48,
            106,
            125,
            50,
            86,
            12,
            12,
            176,
            18,
            157,
            69,
            10,
            193,
            8,
            53,
        ],
        [
            40,
            4,
            14,
            209,
            3,
            30,
            39,
            182,
            205,
            32,
            153,
            102,
            68,
            4,
            4,
            132,
            22,
            49,
            92,
            23,
            170,
            229,
            202,
            1,
            220,
            28,
            115,
            184,
            93,
            60,
            190,
            131,
            7,
            139,
            125,
            206,
            153,
            177,
            111,
            218,
            116,
            239,
            233,
            28,
            125,
            232,
            107,
            251,
            220,
            79,
            24,
            150,
            238,
            245,
            133,
            83,
            224,
            105,
            154,
            192,
            149,
            2,
            56,
            235,
        ],
        [144, 246, 38, 118, 139, 81, 41, 183, 88, 81, 151, 57, 40, 52, 222, 50, 229, 112, 139, 75, 134, 246, 227, 200, 175, 30, 32, 88, 4, 32, 197, 56]
    ));
}


#[test]
fn test_rsa() {
    let params: BigNumParams<9, 1024> = BigNumParams::new(
        false,
        [0x9b5f6367e94c0d47502451357be1b5, 0x2cf79e792ab501e6a8a1ca519af2cb, 0x3af9c9fc1c5466fb684cf009d7197c, 0xe2941992548cee0d67dd4547e11dd6, 0xcb8d5735b9321db085f1b8e2d8038f, 0xbe4ab0caea759e2f773a1f9029c73e, 0xbeb2aaa5b3778d6eebfba6bf9ea191, 0x2f21681bf6d6aba555032bf6f9f036, 0xc5d232c7c1537c79f4b7ac28ff1168],
        [0x76587ae99144b02f5c0561abe7b171, 0x572705d030eba70862781acd71f9db, 0xbf7332c0b01314b98e6e4b4e779bb7, 0x1fcde23d91266af32660e5a1c07804, 0xf2f65cfe7bb21f91c71480ddc7e187, 0xd5a265ca080f426885f31564eb35a5, 0x3c9aa2fe848c273cd5f5248fd1eeb1, 0xe3665a614a6a26b98594f893a7eba8, 0xab2d9c34eba3f025bc64776b917622]
    );
    let signature: RuntimeBigNum<9, 1024> = RuntimeBigNum::from_array(
        params,
        [0x8e24b00c41f4f76c69edc9794e596d, 0xf56024369222a279178234d9b256b8, 0x21c8dbe808e3c0e9c5968deb4d8126, 0x25550a447219a6b82f7b48f722034c, 0x1d90802722814b6b8f1d01c6ebbfe3, 0x7bcc51de0c8b896cd4f3403eadcec8, 0x57e9e8bcb4979c3e3aa4b7eca8e475, 0x1363a2f15f0187cb42739e0c78cc4e, 0xaef740a3591cf9c63ae660790309c8]
    );
    assert(
        dep::noir_rsa::rsa::verify_sha256_pkcs1v15(
            [9, 77, 116, 176, 84, 37, 6, 44, 24, 67, 19, 129, 158, 130, 151, 108, 31, 225, 126, 224, 106, 117, 67, 255, 37, 232, 114, 47, 53, 50, 58, 197],
            signature,
            65537
        )
    );
}

// #[test]
// fn test_() {
//     let digest: [u8; 32] = [117, 9, 229, 189, 160, 199, 98, 210, 186, 199, 249, 13, 117, 139, 91, 34, 99, 250, 1, 204, 188, 84, 42, 181, 227, 223, 22, 59, 224, 142, 108, 169];
//     let params: BigNumParams<18, 2048> = BigNumParams::new(
//             false,
//             [0x320e3fd2ac91530fe87c5d0339b8c9, 0xdcfcf6c4978ba5a1ab88d406fb8094, 0xd5800612e4755aadb37370a240ff81, 0x738c3aa64681506730592ae9bc5fda, 0x9f8f701c911e725bee1be0742e1a6, 0x618dc82e8b2f0c3b842a11320a1858, 0x8547c03d7d1611d40c0344533faec0, 0x116aa47d00b47cf2a0020d79fa110b, 0x5b69aa3379c07357141ddb0249c21c, 0x5f5b575ac974112172940e552a7c97, 0xb9eca24d9f9e3e5e4dbccab76fc193, 0xfbfa167ac05f078fb7cc54c60d1548, 0x5f128d3d960d7497dee19ad6289ac3, 0x6bce971aecb172b0467c6df9a28468, 0xd000ba73583754f889bef2292da312, 0x531040c99d3fd0bb263c7473558d2b, 0xa31efbce2d858a18e6d05f0b5a342, 0xc8],
//             [0x4c617696e76c6bd4f122b047fa4adc, 0xaafca25e2d7a639297e9c5cbbc8eb2, 0x6617645454da971978476ad086a375, 0x29a916c613f74464dedcddbddb67d3, 0xb48b3a7c550ee255ee7ad8c9698871, 0xc3e3d3169e61d41cc8388cd0bb3194, 0x72ee3ff094ea1b9296492366fe398a, 0x5ae7cd9c1ed1cfb4b7db2ec08b5736, 0xe880c9b01edd7fa6340fb8d241d6a2, 0x81899f93b28c12576b2dcd9c1a9022, 0x7e77a5751db46645c3288fdc6e22ba, 0x4ee17e658ad069f5a4b66786e0060e, 0x5c6009ab0795ccee11ff3d61209aee, 0x7faa3258374dfbe06c22ab4ecb4080, 0x6cef1c8040327dd9880068218d96e9, 0x72e57b7ab70200f25fab2054f45c28, 0xd61361cf599ca7656c7ecacacbe52e, 0x1479]
//     );
//     let signature: RuntimeBigNum<18, 2048> = RuntimeBigNum::from_array(
//             params,
//             [0x318b6c033614d835d06df0c7369b98, 0xa910f3dc3b06ef82fded2b512a0a79, 0x64bbf6d55bec9375b814f49a1ab7d2, 0x8bbc90ce50513a94225de5ae2002fb, 0x60e5c156686a41718ff42e6d0dd03f, 0x189b04e18d3f06e00d928f0d09a369, 0x5993e8301d6f23c4f4a037516bdb52, 0x096744117a22b0af39aae83631a4ae, 0xb530abb5eb0b87cdfcbd95e3d711bd, 0x186f03693c2103aa3e8eb1bfac0f8b, 0x6f236b019a3f699ea8cc7156e3cbcc, 0xa2dcbc81eeccc739646cdaebcf2006, 0x89e8b63cf8ad3bfe264ad99f4a76fd, 0x32751797dc531f01e08a6bfd687e15, 0xb2706ca49b1f65fa0a20617e21c7ef, 0xdf0e9db7c28c62c8bd3b00564ca49e, 0xdc5549da818ceac23c2436571eff47, 0x84]
//     );
//     // assert(
//         dep::noir_rsa::rsa::verify_sha256_pkcs1v15(
//             digest,
//             signature,
//             65537
//         );
//     // );
// }
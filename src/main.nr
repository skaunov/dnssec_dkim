// due to the bug with the RSA we don't need a function for a TLD yet; hence can think that DS is always a thing
// use dep::bignum::{params::BigNumParams, RuntimeBigNum};

#[dep::aztec::macros::aztec]
pub contract Main {
    use std::meta::derive;
    use std::hash::pedersen_hash;
    use dep::aztec::macros::{
        storage::storage, functions::{initializer, public, } // internal, private, utility, view
    };
    use dep::aztec::protocol_types::traits::{Packable, Deserialize, Serialize}; // , Hash, FromField, ToField, 
    use dep::aztec::prelude::{Map, PublicMutable}; // PublicContext, PublicImmutable, 

    // TODO add `pub` and correct algorithm suffixes
    // type P256Key = [u8; 64];
    
    /// FQDN specified max. len. minus the _domaindkim_ specified part minus minimum selector can take
    global FQDN_LEN_MAX: u32 = 253 - 10 - 2;
    global DNSKEY_64_PACKED_LEN: u32 = 64 + 1 + FQDN_LEN_MAX;
    global DKIM_LABEL: [u8; 10] = "_domainkey".as_bytes();
    global DOT_BYTE: u8 = ".".as_bytes()[0];
    global DKIM_KEY_RSA2048_PACKED_LEN: u32 = 256 + 1 + FQDN_LEN_MAX + 1 + 63;

    type Fqdn = BoundedVec<u8, FQDN_LEN_MAX>; 
    
    /// estimation of max length of a DNSKEY record, can be calculated precisely beyond the prototype #calculatonEstimation
    // The thing is RRSIG covers a whole RRset of the records of a type. The prototype handles only the kind of setup which have a couple of DNSKEY; actually this already covers most of the setups. But there's some ways to combine a big `RRset` 
    // from parts with enough development invested in this. A straight-forward solution is to save tuples of records, iterate over those to get the digest, and wipe them.
    // [A recommended DNSKEY RRset length maximum is 13 but some systems allow much higher (which open those for an attack).](https://datatracker.ietf.org/meeting/121/materials/slides-121-dnsop-sessb-dns-upper-limit-values-00) */
    #[derive(Deserialize, Serialize)]
    pub struct DnskeyRecordSetBytes {bytes: BoundedVec<u8, 333 * 2>}
    
    #[derive(Deserialize, Serialize)]
    pub struct DsRecordSetBytes {bytes: BoundedVec<u8, 289 * 2>} // #calculatonEstimation
    
    #[derive(Deserialize, Serialize)]
    pub struct DkimKeyRsa2048 {
        domain: Fqdn,
        selector: BoundedVec<u8, 63>,
        key: [u8; 256]
    }

    #[derive(Deserialize, Serialize)]
    pub struct DkimRecordRsa2048 {
        bytes: BoundedVec<u8, 263 + FQDN_LEN_MAX>, // #calculatonEstimation
    }
    
    #[derive(Deserialize, Serialize)]
    pub struct Bytes64DnsKey {
        domain: Fqdn, 
        key_x: [u8; 32],
        key_y: [u8; 32]
        // tag: Field
    }
    // TODO quite some space for optimization here
    /*      it's really awful now, but with packed string this would be orders better
            also moving the keys itself to a distributed storage so that only digest and revocation live here 
    while the key only enter as an argument */
    impl Packable<DNSKEY_64_PACKED_LEN> for Bytes64DnsKey {
        fn pack(self) -> [Field; DNSKEY_64_PACKED_LEN] {
            let l = self.domain.len();
            let mut r = [0; DNSKEY_64_PACKED_LEN - 64];
            for i in 0..l {
                r[i] = self.domain.get(i) as Field;
            }
            r[FQDN_LEN_MAX] = l as Field;
            
            r.concat(self.key_x.map(|b| b as Field)).concat(self.key_y.map(|b| b as Field))
        }
        fn unpack(packed: [Field; DNSKEY_64_PACKED_LEN]) -> Self {
            let mut d: [u8; FQDN_LEN_MAX] = [0; FQDN_LEN_MAX];
            let mut (key_x, key_y): ([u8; 32], [u8; 32]) = ([0; 32], [0; 32]);
            for i in 0..FQDN_LEN_MAX {d[i] = packed[i] as u8;}
            for i in 0..32 {
                key_x[i] = packed[i + FQDN_LEN_MAX + 1] as u8;
                key_y[i] = packed[i + FQDN_LEN_MAX + 1 + 32] as u8;
            }
            Bytes64DnsKey{
                domain: BoundedVec::from_parts_unchecked(
                    // &packed[0..FQDN_LEN_MAX].map(|e| e as u8).as_array(), 
                    d, packed[FQDN_LEN_MAX] as u32
                ),//.map(|e| e as u8), 
                // key: &packed[(FQDN_LEN_MAX + 1)..].map(|e| e as u8).as_array()
                key_x, key_y
            }
        }
    }

    impl Packable<DKIM_KEY_RSA2048_PACKED_LEN> for DkimKeyRsa2048 {
        fn pack(self) -> [Field; DKIM_KEY_RSA2048_PACKED_LEN] {
            let l_domain = self.domain.len();
            let l_selector = self.selector.len();
            let mut r_domain = [0; FQDN_LEN_MAX + 1];
            for i in 0..l_domain {
                r_domain[i] = self.domain.get(i) as Field;
            }
            r_domain[FQDN_LEN_MAX] = l_domain as Field;
            let mut r_selector = [0; 63 + 1];
            for i in 0..l_selector {
                r_selector[i] = self.selector.get(i) as Field;
            }
            r_selector[63] = l_selector as Field;
            
            r_domain.concat(r_selector).concat(self.key.map(|b| b as Field))
        }
        fn unpack(packed: [Field; DKIM_KEY_RSA2048_PACKED_LEN]) -> Self {
            let mut d: [u8; FQDN_LEN_MAX] = [0; FQDN_LEN_MAX];
            let mut s: [u8; 63] = [0; 63];
            let mut key: [u8; 256] = [0; 256];
            for i in 0..FQDN_LEN_MAX {d[i] = packed[i] as u8;}
            for i in 0..63 {s[i] = packed[i + FQDN_LEN_MAX + 1] as u8;}
            for i in 0..256 {
                key[i] = packed[i + FQDN_LEN_MAX + 1 + 63 + 1] as u8;
            }
            DkimKeyRsa2048{
                domain: BoundedVec::from_parts_unchecked(d, packed[FQDN_LEN_MAX] as u32),
                selector: BoundedVec::from_parts_unchecked(s, packed[FQDN_LEN_MAX + 1 + 63] as u32),
                key
            }
        }
    }

    #[dep::aztec::macros::storage::storage]
    struct Storage<Context> {
        keysigkey_64bytes: Map<
            Field, // Bytes64DnsKey,
            PublicMutable<
                bool, // is *not* revoked
                Context
            >,
            Context
        >,
        zonesigkey_64bytes: Map<
            Field, // Bytes64DnsKey,
            PublicMutable<
                bool, // is *not* revoked
                Context
            >,
            Context
        >,
        dkimkey_rsa2048: Map<
            Field, // DkimKey,
            PublicMutable<
                // (
                    bool, // is *not* revoked
                    // Field, // no later
                    // Field, // not before
                // )
                Context
            >,
            Context
        >
    }

    /// Starting with the "com." KSK; when RSA verifier will be fixed it should be "." KSK here.
    #[public] #[initializer]
    fn initialize() {
        let the = Bytes64DnsKey{
            domain: BoundedVec::from_array("com.".as_bytes()),
            key_x: [
                183 as u8,
                31 as u8,
                4 as u8,
                101 as u8,
                16 as u8,
                29 as u8,
                219 as u8,
                226 as u8,
                191 as u8,
                12 as u8,
                148 as u8,
                85 as u8,
                209 as u8,
                47 as u8,
                161 as u8,
                108 as u8,
                28 as u8,
                218 as u8,
                68 as u8,
                244 as u8,
                191 as u8,
                27 as u8,
                162 as u8,
                85 as u8,
                52 as u8,
                24 as u8,
                173 as u8,
                31 as u8,
                58 as u8,
                169 as u8,
                176 as u8,
                105 as u8
            ],
            key_y: [ 
                115 as u8,
                242 as u8,
                27 as u8,
                132 as u8,
                235 as u8,
                83 as u8,
                44 as u8,
                244 as u8,
                3 as u8,
                94 as u8,
                232 as u8,
                212 as u8,
                131 as u8,
                44 as u8,
                162 as u8,
                109 as u8,
                137 as u8,
                48 as u8,
                106 as u8,
                125 as u8,
                50 as u8,
                86 as u8,
                12 as u8,
                12 as u8,
                176 as u8,
                18 as u8,
                157 as u8,
                69 as u8,
                10 as u8,
                193 as u8,
                8 as u8,
                53 as u8,
            ]
        }.pack();
        storage.keysigkey_64bytes.at(pedersen_hash(the)).write(
            // (
            //     the, 
                true
            // )
        );
    }
    
    #[public]
    fn add_zsigk_len64_signed_ecdsa256sha256(
        // ksigk_x: [u8; 32],
        // ksigk_y: [u8; 32],
        // domain: Fqdn,
        ksigk: Bytes64DnsKey,
        domain_rrset_position: u32,
        ksigk_rrset_position: u32,
        // delegationsigner: _,
        rrset_dnskey: DnskeyRecordSetBytes, 
        rrsig_dnskey: [u8; 64],
        zsigk_x: [u8; 32],
        zsigk_y: [u8; 32],
        zsigk_rrset_position: u32,
    ) {
        assert(storage.keysigkey_64bytes.at(pedersen_hash(ksigk.pack())).read(), "the key have been revoked or never added"); 

        let mut rrset_dnskey = rrset_dnskey;
        for i in 0..ksigk.domain.len() {
            rrset_dnskey.bytes.set_unchecked(domain_rrset_position + i, ksigk.domain.get(i));
        }
        for i in 0..32 {
            rrset_dnskey.bytes.set_unchecked(ksigk_rrset_position + i, ksigk.key_x[i]);
            rrset_dnskey.bytes.set_unchecked(ksigk_rrset_position + i + 32, ksigk.key_y[i]);
            rrset_dnskey.bytes.set_unchecked(zsigk_rrset_position + i, zsigk_x[i]);
            rrset_dnskey.bytes.set_unchecked(zsigk_rrset_position + i + 32, zsigk_y[i]);
        }

        let h: [u8; 32] = dep::sha256::sha256_var(
                rrset_dnskey.bytes.storage(), rrset_dnskey.bytes.len() as u64
            );
        assert(std::ecdsa_secp256r1::verify_signature(
            // ksigk.key[0..32], ksigk.key[32..64], 
            ksigk.key_x, ksigk.key_y,
            rrsig_dnskey, h
        ));

        storage.zonesigkey_64bytes.at(pedersen_hash(Bytes64DnsKey{
            domain: ksigk.domain, key_x: zsigk_x, key_y: zsigk_y
        }.pack())).write(true);
    }

    #[public]
    fn add_ds_ecdsa(
        parent_zsigk: Bytes64DnsKey,
        rrset_ds: DsRecordSetBytes,
        child_ksigk: Bytes64DnsKey,
        child_domain_position: u32,
        ksigk_rrset_position: u32,
        rrsig_ds: [u8; 64],
    ) {
        assert(storage.zonesigkey_64bytes.at(pedersen_hash(parent_zsigk.pack())).read(), "the key have been revoked or never added"); 

        let l_child = child_ksigk.domain.len();
        let l_parent = parent_zsigk.domain.len();
        // assert(".".as_bytes()[0] == child_ksigk.domain.get(l_child - l_parent), "DS must define a subdomain");
        let mut rrset_ds = rrset_ds;
        for i in 0..(l_child - l_parent) {
            rrset_ds.bytes.set_unchecked(i + child_domain_position, child_ksigk.domain.get(i));
        }
        for i in 0..l_parent {
            // assert(parent_zsigk.domain.get(i) == child_ksigk.domain.get(i + l_child - l_parent), "DS must define a subdomain");
            rrset_ds.bytes.set_unchecked(
                i + child_domain_position + l_child, parent_zsigk.domain.get(i)
            );
        }
        for i in 0..32 {
            rrset_ds.bytes.set_unchecked(ksigk_rrset_position + i, child_ksigk.key_x[i]);
            rrset_ds.bytes.set_unchecked(ksigk_rrset_position + i + 32, child_ksigk.key_y[i]);
        }

        let sig_check = std::ecdsa_secp256r1::verify_signature(
            parent_zsigk.key_x, parent_zsigk.key_y,
            rrsig_ds, dep::sha256::sha256_var(
                rrset_ds.bytes.storage(), rrset_ds.bytes.len() as u64
            )
        );
        assert(sig_check);

        storage.keysigkey_64bytes.at(pedersen_hash(child_ksigk.pack())).write(true);
    }

    #[public]
    fn add_dkim_rsa2048_signed_ecdsa256sha256(
        parts: DkimKeyRsa2048,
        record: DkimRecordRsa2048,
        dkim_key_position: u32,
        rrsig: [u8; 64],
        zsigk_x: [u8; 32],
        zsigk_y: [u8; 32],
    ) {
        assert(storage.zonesigkey_64bytes.at(pedersen_hash(
            Bytes64DnsKey{domain: parts.domain, key_x: zsigk_x, key_y: zsigk_y}
            .pack()
        )).read());
        
        let mut record = record.bytes;
        let l_selector = parts.selector.len();
        // let index_dot_first = l_selector;
        // let index_DKIM_LABEL = index_dot_first + 1;
        // let index_dot_second = index_dot_first + 1 + 10;
        // let index_domain_start = index_dot_second + 1;
        for i in 0..l_selector {
            record.set_unchecked(i, parts.selector.get_unchecked(i)); // TODO there were a lot of `get` to switch 
        }
        record.set_unchecked(l_selector, DOT_BYTE); 
        // for i in ()..index_dot_second {
        for i in 0..10 {
            record.set_unchecked(i + l_selector + 1, DKIM_LABEL[i]); 
        }
        record.set_unchecked(l_selector + 1 + 10, DOT_BYTE); 
        // for i in ..( + index_domain_start) {
        for i in 0..parts.domain.len() {
            record.set_unchecked(i + l_selector + 1 + 10 + 1, parts.domain.get(i)); 
        }
        for i in 0..256 {
            record.set_unchecked(i + dkim_key_position, parts.key[i]); 
        }

        let sig_check = std::ecdsa_secp256r1::verify_signature(
            zsigk_x, zsigk_y,
            rrsig, dep::sha256::sha256_var(
                record.storage(), record.len() as u64
            )
        );
        assert(sig_check);

        storage.dkimkey_rsa2048.at(pedersen_hash(parts.pack())).write(true);
    }

    #[public]
    fn check_rsa2048(the: DkimKeyRsa2048) {
        assert(storage.dkimkey_rsa2048.at(pedersen_hash(the.pack())).read());
    }
    
    // TODO a lib function since adding a DKIM key which needs an additional trust assumption isn't acceptable; but quite verifiable as an addition
    // should only be used if the caller trusts the delegated domain
    // fn add_dkim_rsa2048_delegated_signed_ecdsa256sha256() {}

    // AFAIK DKIM has no revokation mechanism so it can be done by revealing the private key to the contract publicly. Sadly privately won't make this as that would allow the key owner to mark it revoked for this contract only.
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


// #[test]
// fn test_rsa() {
//     let params: BigNumParams<9, 1024> = BigNumParams::new(
//         false,
//         [0x9b5f6367e94c0d47502451357be1b5, 0x2cf79e792ab501e6a8a1ca519af2cb, 0x3af9c9fc1c5466fb684cf009d7197c, 0xe2941992548cee0d67dd4547e11dd6, 0xcb8d5735b9321db085f1b8e2d8038f, 0xbe4ab0caea759e2f773a1f9029c73e, 0xbeb2aaa5b3778d6eebfba6bf9ea191, 0x2f21681bf6d6aba555032bf6f9f036, 0xc5d232c7c1537c79f4b7ac28ff1168],
//         [0x76587ae99144b02f5c0561abe7b171, 0x572705d030eba70862781acd71f9db, 0xbf7332c0b01314b98e6e4b4e779bb7, 0x1fcde23d91266af32660e5a1c07804, 0xf2f65cfe7bb21f91c71480ddc7e187, 0xd5a265ca080f426885f31564eb35a5, 0x3c9aa2fe848c273cd5f5248fd1eeb1, 0xe3665a614a6a26b98594f893a7eba8, 0xab2d9c34eba3f025bc64776b917622]
//     );
//     let signature: RuntimeBigNum<9, 1024> = RuntimeBigNum::from_array(
//         params,
//         [0x8e24b00c41f4f76c69edc9794e596d, 0xf56024369222a279178234d9b256b8, 0x21c8dbe808e3c0e9c5968deb4d8126, 0x25550a447219a6b82f7b48f722034c, 0x1d90802722814b6b8f1d01c6ebbfe3, 0x7bcc51de0c8b896cd4f3403eadcec8, 0x57e9e8bcb4979c3e3aa4b7eca8e475, 0x1363a2f15f0187cb42739e0c78cc4e, 0xaef740a3591cf9c63ae660790309c8]
//     );
//     assert(
//         dep::noir_rsa::rsa::verify_sha256_pkcs1v15(
//             [9, 77, 116, 176, 84, 37, 6, 44, 24, 67, 19, 129, 158, 130, 151, 108, 31, 225, 126, 224, 106, 117, 67, 255, 37, 232, 114, 47, 53, 50, 58, 197],
//             signature,
//             65537
//         )
//     );
// }

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
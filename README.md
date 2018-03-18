# secp256k1
secp256k1 by pure swift

## License
secp256k1 can be used, distributed and modified user the MIT license.

## Requirements
secp256k1 requires Swift 4.

macOS

## Install

WIP

## Dependency

None

## How to use

``` swift
struct secp256k1_pubkey (64bytes)
struct secp256k1_ecdsa_signature (64bytes)
struct secp256k1_context (opaque)

struct SECP256K1_FLAGS: OptionSet {
    /** Flags to pass to secp256k1_context_create. */
    public static let SECP256K1_CONTEXT_VERIFY: SECP256K1_FLAGS
    public static let SECP256K1_CONTEXT_SIGN: SECP256K1_FLAGS
    public static let SECP256K1_CONTEXT_NONE: SECP256K1_FLAGS
    /** Flag to pass to secp256k1_ec_pubkey_serialize and secp256k1_ec_privkey_export. */
    public static let SECP256K1_EC_COMPRESSED: SECP256K1_FLAGS
    public static let SECP256K1_EC_UNCOMPRESSED: SECP256K1_FLAGS
}

func secp256k1_context_create(_ flags: SECP256K1_FLAGS) -> secp256k1_context ?
func secp256k1_context_clone(_ ctx: secp256k1_context) -> secp256k1_context
func secp256k1_context_destroy(_ ctx: inout secp256k1_context)
func secp256k1_ec_pubkey_parse(_ ctx: secp256k1_context, _ pubkey: inout secp256k1_pubkey, _ input: [UInt8], _ inputlen: UInt) -> Bool
func secp256k1_ec_pubkey_serialize(_ ctx: secp256k1_context, _ output: inout [UInt8], _ outputlen: inout UInt, _ pubkey: secp256k1_pubkey, _ flags: SECP256K1_FLAGS) -> Bool
func secp256k1_ecdsa_signature_parse_der(_ ctx: secp256k1_context, _ sig: inout secp256k1_ecdsa_signature, _ input: [UInt8], _ inputlen: UInt) -> Bool
func secp256k1_ecdsa_signature_parse_compact(_ ctx: secp256k1_context, _ sig: inout secp256k1_ecdsa_signature, _ input64: [UInt8]) -> Bool
func secp256k1_ecdsa_signature_serialize_der(_ ctx: secp256k1_context, _ output: inout [UInt8], _ outputlen: inout UInt, _ sig: secp256k1_ecdsa_signature) -> Bool
func secp256k1_ecdsa_signature_serialize_compact(_ ctx: secp256k1_context, _ output64: inout [UInt8], _ sig: secp256k1_ecdsa_signature) -> Bool
func secp256k1_ecdsa_signature_normalize(_ ctx: secp256k1_context, _ sigout: inout secp256k1_ecdsa_signature , _ sigin: secp256k1_ecdsa_signature) -> Bool
func secp256k1_ecdsa_verify(_ ctx: secp256k1_context, _ sig: secp256k1_ecdsa_signature, _ msg32: [UInt8], _ pubkey: secp256k1_pubkey) -> Bool
func secp256k1_ecdsa_sign(_ ctx: secp256k1_context, _ signature: inout secp256k1_ecdsa_signature, _ msg32: [UInt8], _ seckey: [UInt8], _ noncefp: secp256k1_nonce_function?, _ noncedata: [UInt8]?) -> Bool
func secp256k1_ec_seckey_verify(_ ctx: secp256k1_context, _ seckey: [UInt8]) -> Bool
func secp256k1_ec_pubkey_create(_ ctx: secp256k1_context, _ pubkey: inout secp256k1_pubkey, _ seckey: [UInt8]) -> Bool
func secp256k1_ec_privkey_negate(_ ctx: secp256k1_context, _ seckey: inout [UInt8]) -> Bool
func secp256k1_ec_pubkey_negate(_ ctx: secp256k1_context, _ pubkey: inout secp256k1_pubkey) -> Bool
func secp256k1_ec_privkey_tweak_add(_ ctx: secp256k1_context, _ seckey: inout [UInt8], _ tweak: [UInt8]) -> Bool
func secp256k1_ec_pubkey_tweak_add(_ ctx: secp256k1_context, _ pubkey: inout secp256k1_pubkey, _ tweak: [UInt8]) -> Bool
func secp256k1_ec_privkey_tweak_mul(_ ctx: secp256k1_context, _ seckey: inout [UInt8], _ tweak: [UInt8]) -> Bool
func secp256k1_ec_pubkey_tweak_mul(_ ctx: secp256k1_context, _ pubkey: inout secp256k1_pubkey, _ tweak: [UInt8]) -> Bool
func secp256k1_context_randomize(_ ctx: inout secp256k1_context, _ seed32: [UInt8]?) -> Bool
func secp256k1_ec_pubkey_combine(_ ctx: secp256k1_context, _ pubnonce: inout secp256k1_pubkey, _ pubnonces:[secp256k1_pubkey], _ n: UInt) -> Bool

## Implementation

It is ported from [bitcoin C implementation](https://github.com/bitcoin-core/secp256k1)

## Performance

WIP


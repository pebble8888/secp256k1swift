# secp256k1
secp256k1 by pure swift

## License
secp256k1 can be used, distributed and modified user the MIT license.

## Requirements
secp256k1 requires Swift4.

macOS

## Install

WIP

## Dependency

None

## How to use

``` swift
struct secp256k1_pubkey  // 64 bytes
struct secp256k1_ecdsa_signature //64 bytes and opaque
struct secp256k1_context // opaque
struct secp256k1_ecdsa_recoverable_signature // 64 bytes + recovery id 1 bytes

struct SECP256K1_FLAGS: OptionSet {
    /** Flags to pass to secp256k1_context_create. */
    public static let SECP256K1_CONTEXT_VERIFY: SECP256K1_FLAGS
    public static let SECP256K1_CONTEXT_SIGN: SECP256K1_FLAGS
    public static let SECP256K1_CONTEXT_NONE: SECP256K1_FLAGS
    /** Flag to pass to secp256k1_ec_pubkey_serialize and secp256k1_ec_privkey_export. */
    public static let SECP256K1_EC_COMPRESSED: SECP256K1_FLAGS
    public static let SECP256K1_EC_UNCOMPRESSED: SECP256K1_FLAGS
}

/**
 * context 
 */
func secp256k1_context_create(_ flags: SECP256K1_FLAGS) -> secp256k1_context?
func secp256k1_context_clone(_ ctx: secp256k1_context) -> secp256k1_context
func secp256k1_context_destroy(_ ctx: inout secp256k1_context)
func secp256k1_context_randomize(_ ctx: inout secp256k1_context, _ seed32: [UInt8]?) -> Bool

/**
 * convert 65 bytes (uncompressed) or 33bytes (compressed) pubkey data to secp256k1_pubkey.
 */
func secp256k1_ec_pubkey_parse(_ ctx: secp256k1_context, _ pubkey: inout secp256k1_pubkey, _ input: [UInt8], _ inputlen: UInt) -> Bool

/**
 * convert secp256k1_pubkey to 65 bytes or 33 bytes pubkey data.
 * flags: .SECP256K1_EC_COMPRESSED or .SECP256K1_EC_UNCOMPRESSED
 */
func secp256k1_ec_pubkey_serialize(_ ctx: secp256k1_context, _ output: inout [UInt8], _ outputlen: inout UInt, _ pubkey: secp256k1_pubkey, _ flags: SECP256K1_FLAGS) -> Bool

/**
 * convert DER encoded signature to 64 bytes secp256k1_ecdsa_signature.
 *
 * DER encoded signagure format:
 *   0x30 : a header byte indicating a compound structure.
 *   A 1-byte length descriptor for all what follows.
 *   0x02 : a header byte indicating an integer.
 *   A 1-byte length descriptor for the R value.
 *   The R coordinate, as a big-endian integer.
 *   0x02 : a header byte indicating an integer.
 *   A 1-byte length descriptor for the S value.
 *   The S coordinate, as a big-endian integer.
 */
func secp256k1_ecdsa_signature_parse_der(_ ctx: secp256k1_context, _ sig: inout secp256k1_ecdsa_signature, _ input: [UInt8], _ inputlen: UInt) -> Bool

/**
 * convert compressed signature to 64 bytes secp256k1_ecdsa_signature.
 * input64 has 64bytes
 * bigendian 32bytes R and bigendian 32 bytes S
 */
func secp256k1_ecdsa_signature_parse_compact(_ ctx: secp256k1_context, _ sig: inout secp256k1_ecdsa_signature, _ input64: [UInt8]) -> Bool

/**
 * convert secp256k1_ecdsa_signature to DER encoded signature.
 */
func secp256k1_ecdsa_signature_serialize_der(_ ctx: secp256k1_context, _ output: inout [UInt8], _ outputlen: inout UInt, _ sig: secp256k1_ecdsa_signature) -> Bool

/**
 * convert secp256k1_ecdsa_signature to compressed signature.
 */
func secp256k1_ecdsa_signature_serialize_compact(_ ctx: secp256k1_context, _ output64: inout [UInt8], _ sig: secp256k1_ecdsa_signature) -> Bool

/**
 * normalize secp256k1_ecdsa_signature to lower-S form.
 * The secp256k1_ecdsa_sign function will by default create signatures in the
 * lower-S form, and secp256k1_ecdsa_verify will not accept others
 */
func secp256k1_ecdsa_signature_normalize(_ ctx: secp256k1_context, _ sigout: inout secp256k1_ecdsa_signature , _ sigin: secp256k1_ecdsa_signature) -> Bool

/**
 * verify 32 bytes message by means of signature and pubkey
 */
func secp256k1_ecdsa_verify(_ ctx: secp256k1_context, _ sig: secp256k1_ecdsa_signature, _ msg32: [UInt8], _ pubkey: secp256k1_pubkey) -> Bool

/**
 * create signature for 32 bytes message by means of 32 bytes seckey and nonce
 */
func secp256k1_ecdsa_sign(_ ctx: secp256k1_context, _ signature: inout secp256k1_ecdsa_signature, _ msg32: [UInt8], _ seckey: [UInt8], _ noncefp: secp256k1_nonce_function?, _ noncedata: [UInt8]?) -> Bool

/**
 * seckey has 32 bytes and [1, n-1], n is the order of the base point G
 * if seckey is in this range, return true
 * You must make random 32bytes by means of an enough complex pseudorandom producer.
 * You check that number by this function and if fails you pickup another random number and continue to not fail.
 */
func secp256k1_ec_seckey_verify(_ ctx: secp256k1_context, _ seckey: [UInt8]) -> Bool

/**
 * pubkey from a seckey
 */
func secp256k1_ec_pubkey_create(_ ctx: secp256k1_context, _ pubkey: inout secp256k1_pubkey, _ seckey: [UInt8]) -> Bool

/**
 * negate, add, mul for privkey and pubkey
 */
func secp256k1_ec_privkey_negate(_ ctx: secp256k1_context, _ seckey: inout [UInt8]) -> Bool
func secp256k1_ec_pubkey_negate(_ ctx: secp256k1_context, _ pubkey: inout secp256k1_pubkey) -> Bool
func secp256k1_ec_privkey_tweak_add(_ ctx: secp256k1_context, _ seckey: inout [UInt8], _ tweak: [UInt8]) -> Bool
func secp256k1_ec_pubkey_tweak_add(_ ctx: secp256k1_context, _ pubkey: inout secp256k1_pubkey, _ tweak: [UInt8]) -> Bool
func secp256k1_ec_privkey_tweak_mul(_ ctx: secp256k1_context, _ seckey: inout [UInt8], _ tweak: [UInt8]) -> Bool
func secp256k1_ec_pubkey_tweak_mul(_ ctx: secp256k1_context, _ pubkey: inout secp256k1_pubkey, _ tweak: [UInt8]) -> Bool

func secp256k1_ec_pubkey_combine(_ ctx: secp256k1_context, _ pubnonce: inout secp256k1_pubkey, _ pubnonces:[secp256k1_pubkey], _ n: UInt) -> Bool

/**
 * recoverable signature (compact 64 bytes + recocery id 1 bytes)
 *
 * recovery id
 * R : affine point
 *   0: R.x not overflow, R.y is even
 *   1: R.x not overflow, R.y is odd
 *   2: R.x overflow (R.x >= order of BasePoint G), R.y is odd
 *   3: R.x overflow (R.x >= order of BasePoint G), R.y is odd
 */
func secp256k1_ecdsa_recoverable_signature_parse_compact(_ ctx: secp256k1_context, _ sig: inout secp256k1_ecdsa_recoverable_signature, _ input64: [UInt8], _ recid: Int) -> Bool
func secp256k1_ecdsa_recoverable_signature_serialize_compact( _ ctx: secp256k1_context, _ output64: inout [UInt8], _ recid: inout Int, _ sig: secp256k1_ecdsa_recoverable_signature) -> Bool
func secp256k1_ecdsa_recoverable_signature_convert( _ ctx: secp256k1_context, _ sig: inout secp256k1_ecdsa_signature, _ sigin: secp256k1_ecdsa_recoverable_signature) -> Bool
func secp256k1_ecdsa_sign_recoverable( _ ctx: secp256k1_context, _ signature: inout secp256k1_ecdsa_recoverable_signature, _ msg32: [UInt8], _ seckey: [UInt8], _ noncefp: secp256k1_nonce_function?, _ noncedata:[UInt8]?) -> Bool
func secp256k1_ecdsa_recover( _ ctx: secp256k1_context, _ pubkey: inout secp256k1_pubkey, _ signature: secp256k1_ecdsa_recoverable_signature, _ msg32: [UInt8]) -> Bool
```

## Implementation

It is ported from [bitcoin implementation in C89](https://github.com/bitcoin-core/secp256k1)

## Performance

WIP


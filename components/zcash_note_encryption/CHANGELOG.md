# Changelog
All notable changes to this library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this library adheres to Rust's notion of
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Added
- `zcash_note_encryption::Domain`:
  - `Domain::PreparedEphemeralPublicKey` associated type.
  - `Domain::prepare_epk` method, which produces the above type.
- Feature `encrypt-to-recipient`, which allows the encryption of an arbitrary
  payload decryptable by the recipient of a shielded note. This adds the
  following trats and functions:
  - `PayloadEncryptionDomain`
  - `decrypt_associated_ciphertext_ivk`
  - `decrypt_associated_ciphertext_ovk`
- A new `KeyedOutput` supertrait for `zcash_note_encryption::ShieldedOutput`
- A new `RecoverableOutput` subtrait for `zcash_note_encryption::ShieldedOutput`,
  which is used to simplify the type signatures of `try_output_recovery_with_ock`
  and `try_output_recovery_with_ovk`.

### Changed
- MSRV is now 1.56.1.
- Migrated to `group 0.13`.
- `zcash_note_encryption::Domain` now requires `epk` to be converted to
  `Domain::PreparedEphemeralPublicKey` before being passed to
  `Domain::ka_agree_dec`.
- Changes to batch decryption APIs:
  - The return types of `batch::try_note_decryption` and
    `batch::try_compact_note_decryption` have changed. Now, instead of
    returning entries corresponding to the cartesian product of the IVKs used for
    decryption with the outputs being decrypted, this now returns a vector of
    decryption results of the same length and in the same order as the `outputs`
    argument to the function. Each successful result includes the index of the
    entry in `ivks` used to decrypt the value.
- Changes to the `zcash_note_encryption::ShieldedOutput` trait:
  - The `ephemeral_key` and `cmstar_bytes` method have been moved into
    a `KeyedOutput` supertrait of `ShieldedOutput`, for use in methods that
    do not require the `enc_ciphertext` capability, such as
    `decrypt_associated_ciphertext_ivk`.
- The signatures of `try_output_recovery_with_ovk` and
  `try_output_recovery_with_ock` have been changed to no longer take `cv` and
  `out_ciphertext` parameters; instead, the output passed to these functions
  must implement the `RecoverableOutput` trait. This ensures that the value
  commitment and `out_ciphertext` values must correspond to the output being
  decrypted, and simplifies the API.

## [0.1.0] - 2021-12-17
Initial release.

# snp-sim-kms

Lab-only simulated AMD SEV-SNP key service for the Eggomi harness.

It follows the dstack KMS onboarding shape:

1. `bootstrap` mints a root and a simulated VCEK quote over that public key.
2. `onboard_from` copies the root only after the source quote verifies.
3. `release_app_key` returns one app key when `MEASUREMENT` and `report_data` match.
4. `release_signed` (v2) binds a caller nonce and signs the record with the
   attested root key. `onboard_from_attested` adds the target's own quote, and
   `bootstrap_attestation` exposes the bootstrap evidence.
5. `fixtures::fixture_set` builds the checked keeper-side fixture set that
   `snp-sim-kms fixtures` and `test-suites/eggomi/scripts/kms-fixtures.sh`
   write.

The `snp-sim-kms` binary serves these over HTTP for the S2 harness. See
[docs/eggomi/simulated-snp-kms.md](../../../docs/eggomi/simulated-snp-kms.md)
for the wire formats.

The quote chain comes from `mock-attestation`. The lab verifier uses that
throwaway ARK. `LabSnpKms::production_gate` calls `QuoteVerifier::new_prod`
and still returns an error if that verifier were ever to accept the bytes.
Released records set `simulated` to true and `production_accepted` to false.

This crate does not change Phala TDX, production KMS key derivation, or the
production `sev_snp_key_release` config. Do not point a production KMS at
these roots.

From the repository root:

```bash
cargo test --manifest-path dstack/Cargo.toml -p snp-sim-kms
```

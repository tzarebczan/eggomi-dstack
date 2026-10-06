# snp-sim-kms

Lab-only simulated AMD SEV-SNP key service for the Eggomi harness.

It follows the dstack KMS onboarding shape:

1. `bootstrap` mints a root and a simulated VCEK quote over that public key.
2. `onboard_from` copies the root only after the source quote verifies.
3. `release_app_key` returns one app key when `MEASUREMENT` and `report_data` match.

The quote chain comes from `mock-attestation`. The lab verifier uses that
throwaway ARK. `LabSnpKms::production_gate` calls `QuoteVerifier::new_prod`
and still returns an error if that verifier were ever to accept the bytes.
Released records set `simulated` to true and `production_accepted` to false.

This crate does not change Phala TDX, production KMS key derivation, or the
production `sev_snp_key_release` config. Do not point a production KMS at
these roots.

```bash
cargo test -p snp-sim-kms
```

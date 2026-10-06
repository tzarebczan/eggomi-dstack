# Lab-only simulated SNP KMS

`snp-sim-kms` (`dstack/crates/snp-sim-kms`) is the in-process stand-in for a
bare-metal SEV-SNP KMS while there is no SNP hardware. It sits on the
simulated-SNP harness from PR #1. The keeper still owns the platform-tagged
verdict. This crate does not tag a cell as confidential.

The flow matches dstack onboarding:

- `bootstrap` generates a lab root and a simulated VCEK quote whose
  `report_data` commits to the domain and the root public key. The root is
  stored only after that quote verifies under the enrolled mock ARK.
- `onboard_from` copies the source root only after the same checks. A
  measurement mismatch or a different mock ARK leaves the target unkeyed.
- `release_app_key` requires the SNP release gate to be enabled, then
  requires the guest quote's `MEASUREMENT` and `report_data` to match the
  enrolled measurement and `app_report_data(app_id)`.

The app key is an HKDF-SHA256 output under the salt `lab-snp-sim-kms/v1`.
It is not `derive_k256_key` and it is not a production app key.

`LabSnpKms::production_gate` refuses every simulated quote. The usual reason
is that `QuoteVerifier::new_prod` rejects the mock ARK. A quote the
production verifier accepted would still be refused. Released JSON sets
`simulated` to true and `production_accepted` to false.

Phala TDX is unchanged. A TDX quote presented to `release_app_key` fails the
SNP verifier. `HOST_DATA` and the MrConfigV3 identity spec stay with the
keeper until hardware vectors exist. Do not install this ARK, seed, or key
in a production KMS, verifier, or image.

From the repository root:

```bash
cargo test --manifest-path dstack/Cargo.toml -p snp-sim-kms
```

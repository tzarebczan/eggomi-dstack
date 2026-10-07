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

## v2 outputs (eggomi#757 items 1-3)

The v1 records above keep their exact serde form. Three v2 outputs exist
alongside them. All bytes are JSON arrays of numbers, as in v1, and every
record carries `simulated: true` and `production_accepted: false`. Each
digest below uses the crate's tagged construction: SHA-256 over the ASCII
tag, then each part as its u32 big-endian length followed by its bytes. A
`report_data` is that 32-byte digest followed by 32 zero bytes.

**Signed, nonced release (`SignedAppKeyRelease`).** The caller picks a nonce
of 16 to 64 bytes. The guest quotes
`app_release_report_data(app_id, nonce)`, which is the tag
`lab-snp-kms-app/v2` over the parts `app_id` and `nonce`. The record's fields,
in order, are `version` (2), `kms_domain`, `kms_public`, `app_id`, `nonce`,
`key`, `key_commitment`, `measurement`, `report_data`, `simulated`,
`production_accepted`, and `signature`.

- `key_commitment` is the digest with tag `lab-snp-kms-key-commit/v1` over
  `key`.
- `signature` is a 64-byte compact secp256k1 ECDSA signature (r || s, low S)
  by the KMS root key. The 32-byte message hash is the digest with tag
  `lab-snp-kms-release-sig/v1` over `version` (4 bytes, big-endian),
  `kms_domain`, `kms_public`, `app_id`, `nonce`, `key_commitment`,
  `measurement`, and `report_data`.
- The signature covers the commitment, not the key, so a keeper that drops
  `key` can still verify it. `kms_public` must equal the `k256_public` of the
  KMS's bootstrap attestation.

A quote recorded for one nonce does not answer another. A v1 quote does not
answer a v2 release, and a v2 quote does not answer a v1 release. The key is
the same lab KDF output as in v1.

**Attested onboard (`AttestedOnboardReceipt`).** `onboard_from_attested`
makes the target quote `onboard_report_data(domain, source_domain,
k256_public)`, which is the tag `lab-snp-kms-onboard/v1` over those three
parts, where `k256_public` is the root public key the target adopts. The
receipt carries `domain`, `source_domain`, `k256_public`, `report_data`,
`measurement`, and `evidence`. If that quote fails, the target stays unkeyed.

**Serialised evidence.** `SimEvidence` serialises as
`{"report":[..],"cert_chain":[[..],..]}`. An empty `cert_chain` means the
verifier fetches ASK and VCEK from an AMD-KDS-shaped endpoint, which is what
guest quotes from the simulated TSM need. `BootstrapAttestation` is the
bootstrap receipt plus its `evidence`. Each v2 type has a `verify` method.

## Fixture-dump target (eggomi#757 item 3)

```bash
CARGO_TARGET_DIR=... ./test-suites/eggomi/scripts/kms-fixtures.sh [OUT]
```

The script builds `snp-sim-kms`, runs `snp-sim-kms fixtures --seed HEX
--out FILE`, and adds the source commit (`source_sha`, and `source_dirty`
when the KMS or mock-attestation crates have local changes) to the
provenance. The default seed is the crate tests' `0x11 x 32`; it derives only
the mock ARK, ASK, and VCEK keys. The default output is
`test-suites/eggomi/.state/work/snp-sim-kms-fixtures.json`.

`snp_sim_kms::fixtures::fixture_set` builds the set and checks it before
anything is written. Every positive output verifies through the crate's
public `verify` methods. The onboarded KMS must release the source's key.
Every negative must be refused by the KMS, and the production gate must
refuse every quote. If any check fails, nothing is written.
`check_fixture_set` repeats the keeper-side checks on a set read back from
disk.

Schema `snp-sim-kms-fixtures/v2`. Each `record`, `receipt`, `evidence`, and
v2 `bootstrap`/`onboard` value is the exact `serde_json` string the crate
emits. Hex is lower case.

| Key | Contents |
| --- | --- |
| `seed`, `ark_pem` | the mock-attestation seed and its ARK |
| `measurement`, `unlisted_measurement` | `0x33 x 48`, enrolled by the source and target KMSs; `0x44 x 48`, enrolled only by a third KMS |
| `host_data` | 32 zero bytes, as in every simulated quote (item 4) |
| `app_report_data` | v1 `report_data` for `app-a` and `app-b` |
| `v1.bootstrap` | `BootstrapReceipt` and its evidence |
| `v1.onboard` | `OnboardReceipt` of `kms-2.lab.example`, onboarded from `kms.lab.example` |
| `v1.releases` | `AppKeyRecord`s with evidence: `app_a`, `app_b`, `app_a_onboarded` (released by the onboarded KMS, same key), and `unlisted` (the third KMS) |
| `v2.bootstrap`, `v2.onboard` | `BootstrapAttestation`; `AttestedOnboardReceipt` |
| `v2.releases` | `SignedAppKeyRelease`s with `nonce` and evidence: `app_a`, `app_b`, `app_a_onboarded` (signed by the same root under `kms_domain` `kms-2.lab.example`) |
| `negatives` | `stale_nonce` (`v2.releases.app_a`'s quote, presented for another nonce), `wrong_report_data`, and `tdx_quote` (hex). The KMS refuses each |

Root keys are minted fresh in each run and discarded. Two runs therefore
differ in every byte that depends on a root, and every key in the set opens
nothing. Mock certificates are valid from one day before `generated_at_unix`
to 30 days after it.

## HOST_DATA and MrConfigV3 (eggomi#757 item 4)

Not implemented; this is the record. `SimTsm::quote` passes 32 zero bytes
as `HOST_DATA`, so every simulated quote has `HOST_DATA` = 0 and there is no
MrConfigV3 identity to bind. The mock generator already takes a `host_data`
argument (`SevSnpGenerator::attest_with_measurement`), so the KMS change is
small once the format is fixed. What it waits on is S6 on real SEV-SNP
hardware: the `HOST_DATA` that dstack's VMM sets for a launch, and the
MrConfigV3 layout it commits to, have to be read from a hardware quote
before the lab mints them. Until then the keeper must not treat
`HOST_DATA` as an identity, and the fixture set records it as zero.

## Long-running server (S2)

`snp-sim-kms serve` holds one bootstrapped `LabSnpKms` and answers:

| Endpoint | Purpose |
| --- | --- |
| `GET /health` | domain, `kms_public`, enrolled MEASUREMENT, gate state |
| `GET /v1/bootstrap` | `BootstrapAttestation` |
| `GET /v1/report-data?app_id=HEX&nonce=HEX` | the report_data a guest must quote |
| `POST /v1/release` | body `{app_id, nonce, attestation}`; 200 with a `SignedAppKeyRelease`, or 403 `{refused, error}` |

`attestation` is the hex `VersionedAttestation` from the guest agent's
`/Attest`. The KMS takes the seed from the harness `tee-simulator.json`, so
its ARK is the job's mock root. It enrolls the MEASUREMENT recomputed from a
VM's `vm_config` with `dstack-mr`, and fetches VCEKs from the mock collateral
server. The release gate stays closed unless `--release-enabled` is passed.
Other subcommands are `measurement`, `verify-release` (the keeper-side check
of bootstrap plus signature), `production-gate`, and `fixtures` (above).

Releases travel over plain HTTP between the guest and the host, and the
guest client returns the key to the host. This is acceptable only because
every key here is throwaway lab material.

## Test

From the repository root:

```bash
cargo test --manifest-path dstack/Cargo.toml -p snp-sim-kms
./test-suites/eggomi/scripts/kms-fixtures.sh   # the checked fixture set
./test-suites/eggomi/scripts/s2-kms.sh   # needs the L1 lab
```

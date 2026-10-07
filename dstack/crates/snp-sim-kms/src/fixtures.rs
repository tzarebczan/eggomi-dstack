// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! The keeper-side fixture set (eggomi#757 item 3): every KMS output a
//! keeper's acceptance path checks, v1 and v2, with the evidence each was
//! decided on and the vectors the KMS must refuse.
//!
//! [`fixture_set`] builds the set in process and checks it before returning:
//! each positive output verifies through this crate's public `verify`
//! methods, each negative is refused by the KMS, and the production gate
//! refuses every quote. A set that fails a check is never returned, so a
//! keeper never records one. `snp-sim-kms fixtures` writes it, and
//! `test-suites/eggomi/scripts/kms-fixtures.sh` is the one-command target.
//!
//! Every record and evidence is the exact `serde_json` string this crate
//! emits, so a keeper can compare byte for byte. Root keys are minted fresh
//! per run and discarded, so two runs differ in every root-dependent byte.

use anyhow::{bail, ensure, Context, Result};
use mock_attestation::tdx::TdxGenerator;
use serde::Serialize;
use serde_json::{json, Value};

use crate::{
    app_release_report_data, app_report_data, LabSnpKms, SignedAppKeyRelease, SimEvidence, SimTsm,
    MEASUREMENT_LEN, REPORT_DATA_LEN,
};

/// `schema` of the fixture set.
pub const FIXTURE_SCHEMA: &str = "snp-sim-kms-fixtures/v2";

/// Enrolled launch measurement of the fixture KMSs.
pub const FIXTURE_MEASUREMENT: [u8; MEASUREMENT_LEN] = [0x33; MEASUREMENT_LEN];
/// Measurement of the third KMS, which no other KMS enrolls.
pub const FIXTURE_UNLISTED_MEASUREMENT: [u8; MEASUREMENT_LEN] = [0x44; MEASUREMENT_LEN];
/// Seed of the TDX quote the SNP path must refuse (the crate tests' seed).
pub const FIXTURE_TDX_SEED: [u8; 32] = [0x09; 32];

const SOURCE_DOMAIN: &str = "kms.lab.example";
const TARGET_DOMAIN: &str = "kms-2.lab.example";
const OTHER_DOMAIN: &str = "kms-other.lab.example";
const APP_A: &[u8] = b"app-a";
const APP_B: &[u8] = b"app-b";
const NONCE_A: [u8; 32] = [0x5a; 32];
const NONCE_B: [u8; 32] = [0x5b; 32];
const NONCE_ONBOARDED: [u8; 32] = [0x5c; 32];
const NONCE_STALE: [u8; 32] = [0x5d; 32];

/// Build and check the fixture set for one mock-attestation seed.
pub fn fixture_set(seed: [u8; 32]) -> Result<Value> {
    let tsm = SimTsm::from_seed(seed)?;
    let ark = tsm.ark_pem();
    let quote = |report_data, measurement| tsm.quote(report_data, measurement);

    // Three KMSs: the source, a target onboarded from it (attested, v2), a
    // v1 target onboarded the same way without its own quote, and a third
    // enrolled to another measurement.
    let mut source = LabSnpKms::enroll(ark.clone(), FIXTURE_MEASUREMENT, true);
    let bootstrap_v1 = source.bootstrap(&tsm, SOURCE_DOMAIN)?;
    let bootstrap = source
        .bootstrap_attestation()
        .context("kms has not been bootstrapped")?;
    let mut target = LabSnpKms::enroll(ark.clone(), FIXTURE_MEASUREMENT, true);
    let onboard = target.onboard_from_attested(&tsm, &source, TARGET_DOMAIN)?;
    let mut target_v1 = LabSnpKms::enroll(ark.clone(), FIXTURE_MEASUREMENT, true);
    let onboard_v1 = target_v1.onboard_from(&source, TARGET_DOMAIN)?;
    let mut other = LabSnpKms::enroll(ark.clone(), FIXTURE_UNLISTED_MEASUREMENT, true);
    other.bootstrap(&tsm, OTHER_DOMAIN)?;

    // v1 releases, as Eggomi's acceptance path records them.
    let v1 = |kms: &LabSnpKms, app: &[u8], measurement| -> Result<(String, SimEvidence)> {
        let evidence = quote(app_report_data(app), measurement)?;
        let record = kms.release_app_key(app, &evidence)?;
        Ok((serde_json::to_string(&record)?, evidence))
    };
    let (v1_a, v1_a_ev) = v1(&source, APP_A, FIXTURE_MEASUREMENT)?;
    let (v1_b, v1_b_ev) = v1(&source, APP_B, FIXTURE_MEASUREMENT)?;
    let (v1_ao, v1_ao_ev) = v1(&target_v1, APP_A, FIXTURE_MEASUREMENT)?;
    let (v1_un, v1_un_ev) = v1(&other, APP_A, FIXTURE_UNLISTED_MEASUREMENT)?;

    // v2: signed, nonced releases from the source and the attested target.
    let v2 =
        |kms: &LabSnpKms, app: &[u8], nonce: &[u8]| -> Result<(SignedAppKeyRelease, SimEvidence)> {
            let evidence = quote(app_release_report_data(app, nonce), FIXTURE_MEASUREMENT)?;
            Ok((kms.release_signed(app, nonce, &evidence)?, evidence))
        };
    let (v2_a, v2_a_ev) = v2(&source, APP_A, &NONCE_A)?;
    let (v2_b, v2_b_ev) = v2(&source, APP_B, &NONCE_B)?;
    let (v2_ao, v2_ao_ev) = v2(&target, APP_A, &NONCE_ONBOARDED)?;

    // Negatives: each must be refused.
    let wrong_report_data = quote([0x77; REPORT_DATA_LEN], FIXTURE_MEASUREMENT)?;
    let tdx = TdxGenerator::from_seed(FIXTURE_TDX_SEED)?.attest(app_report_data(APP_A))?;
    let tdx_evidence = SimEvidence {
        report: tdx.quote.clone(),
        cert_chain: Vec::new(),
    };

    // Self-check. Positives verify under the public API.
    bootstrap.verify(&ark, &FIXTURE_MEASUREMENT)?;
    onboard.verify(&ark, &FIXTURE_MEASUREMENT)?;
    ensure!(
        onboard.k256_public == bootstrap.k256_public,
        "onboarded root differs from the bootstrapped root"
    );
    for (release, app, nonce) in [
        (&v2_a, APP_A, &NONCE_A),
        (&v2_b, APP_B, &NONCE_B),
        (&v2_ao, APP_A, &NONCE_ONBOARDED),
    ] {
        release.verify(&bootstrap.k256_public)?;
        ensure!(
            release.app_id == app && release.nonce == nonce,
            "release binding"
        );
    }
    ensure!(v2_a.kms_domain == SOURCE_DOMAIN && v2_ao.kms_domain == TARGET_DOMAIN);
    ensure!(
        v2_a.key == v2_ao.key,
        "onboarded kms released a different key"
    );
    // Negatives are refused by the KMS that would answer them.
    let stale = source.release_signed(APP_A, &NONCE_STALE, &v2_a_ev);
    ensure!(stale.is_err(), "a quote for one nonce answered another");
    ensure!(
        source.release_app_key(APP_A, &v2_a_ev).is_err(),
        "a v2 quote answered v1"
    );
    ensure!(
        source.release_signed(APP_A, &NONCE_A, &v1_a_ev).is_err(),
        "a v1 quote answered v2"
    );
    ensure!(source.release_app_key(APP_A, &wrong_report_data).is_err());
    ensure!(source.release_app_key(APP_A, &tdx_evidence).is_err());
    ensure!(
        source.release_app_key(APP_A, &v1_un_ev).is_err(),
        "unlisted quote released"
    );
    // The production gate refuses every quote recorded here.
    for (evidence, report_data) in [
        (&bootstrap.evidence, bootstrap.report_data),
        (&onboard.evidence, onboard.report_data),
        (&v1_a_ev, app_report_data(APP_A)),
        (&v1_b_ev, app_report_data(APP_B)),
        (&v1_ao_ev, app_report_data(APP_A)),
        (&v1_un_ev, app_report_data(APP_A)),
        (&v2_a_ev, v2_a.report_data),
        (&v2_b_ev, v2_b.report_data),
        (&v2_ao_ev, v2_ao.report_data),
    ] {
        if let Ok(never) = LabSnpKms::production_gate(evidence, &report_data) {
            match never {}
        }
    }

    let release_v1 = |app: &[u8], record: String, evidence: &SimEvidence| -> Result<Value> {
        Ok(json!({ "app_id": hex::encode(app), "record": record, "evidence": s(evidence)? }))
    };
    let release_v2 = |release: &SignedAppKeyRelease, evidence: &SimEvidence| -> Result<Value> {
        Ok(json!({
            "app_id": hex::encode(&release.app_id),
            "nonce": hex::encode(&release.nonce),
            "record": s(release)?,
            "evidence": s(evidence)?,
        }))
    };
    Ok(json!({
        "schema": FIXTURE_SCHEMA,
        "provenance": {
            "crate": "snp-sim-kms",
            "version": env!("CARGO_PKG_VERSION"),
            "command": "snp-sim-kms fixtures",
            "lab_only": true,
            "generated_at_unix": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or_default(),
            "checked": [
                "bootstrap, onboard and every v2 release verify under ark_pem and the bootstrap root",
                "the onboarded kms releases the source's key for app-a, v1 and v2",
                "negatives.* are refused by the kms; the production gate refuses every quote",
            ],
        },
        "seed": hex::encode(seed),
        "ark_pem": ark,
        "measurement": hex::encode(FIXTURE_MEASUREMENT),
        "unlisted_measurement": hex::encode(FIXTURE_UNLISTED_MEASUREMENT),
        // SimTsm::quote sets HOST_DATA to zero. MrConfigV3 waits on hardware
        // vectors (eggomi#757 item 4).
        "host_data": hex::encode([0u8; 32]),
        "app_report_data": {
            "app-a": hex::encode(app_report_data(APP_A)),
            "app-b": hex::encode(app_report_data(APP_B)),
        },
        "v1": {
            "bootstrap": {
                "receipt": s(&bootstrap_v1)?,
                "evidence": s(&bootstrap.evidence)?,
            },
            "onboard": { "receipt": s(&onboard_v1)? },
            "releases": {
                "app_a": release_v1(APP_A, v1_a, &v1_a_ev)?,
                "app_b": release_v1(APP_B, v1_b, &v1_b_ev)?,
                "app_a_onboarded": release_v1(APP_A, v1_ao, &v1_ao_ev)?,
                "unlisted": release_v1(APP_A, v1_un, &v1_un_ev)?,
            },
        },
        "v2": {
            "bootstrap": s(&bootstrap)?,
            "onboard": s(&onboard)?,
            "releases": {
                "app_a": release_v2(&v2_a, &v2_a_ev)?,
                "app_b": release_v2(&v2_b, &v2_b_ev)?,
                "app_a_onboarded": release_v2(&v2_ao, &v2_ao_ev)?,
            },
        },
        "negatives": {
            "stale_nonce": {
                "app_id": hex::encode(APP_A),
                "nonce": hex::encode(NONCE_STALE),
                "evidence": s(&v2_a_ev)?,
                "why": "v2.releases.app_a's quote, presented for another nonce",
            },
            "wrong_report_data": {
                "app_id": hex::encode(APP_A),
                "evidence": s(&wrong_report_data)?,
            },
            "tdx_quote": {
                "app_id": hex::encode(APP_A),
                "quote": hex::encode(&tdx.quote),
            },
        },
    }))
}

/// Serialise with the crate's own serde form, as a string.
fn s<T: Serialize>(value: &T) -> Result<String> {
    serde_json::to_string(value).context("failed to serialise a fixture record")
}

/// Check a fixture set read back from disk, the way a keeper would: parse
/// every v2 record with this crate's types and verify it under the set's
/// `ark_pem` and bootstrap root.
pub fn check_fixture_set(set: &Value) -> Result<()> {
    use crate::{AttestedOnboardReceipt, BootstrapAttestation};

    if set["schema"] != FIXTURE_SCHEMA {
        bail!("unknown fixture schema {}", set["schema"]);
    }
    let field = |path: &[&str]| -> Result<&str> {
        let mut node = set;
        for key in path {
            node = &node[*key];
        }
        node.as_str()
            .with_context(|| format!("fixture field {} is missing", path.join(".")))
    };
    let ark = field(&["ark_pem"])?;
    let bootstrap: BootstrapAttestation = serde_json::from_str(field(&["v2", "bootstrap"])?)?;
    bootstrap.verify(ark, &FIXTURE_MEASUREMENT)?;
    let onboard: AttestedOnboardReceipt = serde_json::from_str(field(&["v2", "onboard"])?)?;
    onboard.verify(ark, &FIXTURE_MEASUREMENT)?;
    ensure!(onboard.k256_public == bootstrap.k256_public);
    for name in ["app_a", "app_b", "app_a_onboarded"] {
        let release: SignedAppKeyRelease =
            serde_json::from_str(field(&["v2", "releases", name, "record"])?)?;
        release
            .verify(&bootstrap.k256_public)
            .with_context(|| format!("v2.releases.{name}"))?;
        ensure!(hex::encode(&release.nonce) == field(&["v2", "releases", name, "nonce"])?);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_fixture_set_checks_and_reads_back() {
        let set = fixture_set([0x11; 32]).unwrap();
        let text = serde_json::to_string_pretty(&set).unwrap();
        let back: Value = serde_json::from_str(&text).unwrap();
        check_fixture_set(&back).unwrap();
        // The v1 records keep their exact serde form.
        let record: Value =
            serde_json::from_str(back["v1"]["releases"]["app_a"]["record"].as_str().unwrap())
                .unwrap();
        assert_eq!(record["simulated"], true);
        assert_eq!(record["production_accepted"], false);
        // The onboarded KMS released the same key under its own domain.
        let a: SignedAppKeyRelease =
            serde_json::from_str(back["v2"]["releases"]["app_a"]["record"].as_str().unwrap())
                .unwrap();
        let ao: SignedAppKeyRelease = serde_json::from_str(
            back["v2"]["releases"]["app_a_onboarded"]["record"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(a.key, ao.key);
        assert_eq!(ao.kms_domain, TARGET_DOMAIN);
    }

    #[test]
    fn a_tampered_fixture_set_is_refused() {
        let mut set = fixture_set([0x11; 32]).unwrap();
        let record = set["v2"]["releases"]["app_b"]["record"]
            .as_str()
            .unwrap()
            .to_string();
        let mut release: SignedAppKeyRelease = serde_json::from_str(&record).unwrap();
        release.nonce = NONCE_STALE.to_vec();
        set["v2"]["releases"]["app_b"]["record"] = json!(serde_json::to_string(&release).unwrap());
        assert!(check_fixture_set(&set).is_err());
    }

    #[test]
    fn the_stale_nonce_negative_is_refused_by_a_fresh_kms() {
        let set = fixture_set([0x11; 32]).unwrap();
        let tsm = SimTsm::from_seed([0x11; 32]).unwrap();
        let mut kms = LabSnpKms::enroll(tsm.ark_pem(), FIXTURE_MEASUREMENT, true);
        kms.bootstrap(&tsm, SOURCE_DOMAIN).unwrap();
        let evidence: SimEvidence = serde_json::from_str(
            set["negatives"]["stale_nonce"]["evidence"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        assert!(kms.release_signed(APP_A, &NONCE_STALE, &evidence).is_err());
        assert!(kms.release_signed(APP_A, &NONCE_A, &evidence).is_ok());
    }
}

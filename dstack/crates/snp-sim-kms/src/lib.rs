// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Lab-only simulated AMD SEV-SNP key service.
//!
//! The flow follows dstack KMS onboarding: `bootstrap` mints a root and
//! attests it, `onboard_from` copies that root only after the source quote
//! verifies, and `release_app_key` returns one app key bound to `MEASUREMENT`
//! and `report_data`. Quotes are signed by a simulated VCEK chain from
//! `mock-attestation`. This crate does not derive production KMS keys and
//! does not admit evidence through [`LabSnpKms::production_gate`].

use anyhow::{bail, Context, Result};
use hkdf::Hkdf;
use k256::ecdsa::SigningKey;
use mock_attestation::sev_snp::SevSnpGenerator;
use rand::rngs::OsRng;
use serde::{Serialize, Serializer};
use sev_snp_qvl::QuoteVerifier;
use sha2::{Digest, Sha256};

const MEASUREMENT_LEN: usize = 48;
const REPORT_DATA_LEN: usize = 64;
const LAB_KDF_SALT: &[u8] = b"lab-snp-sim-kms/v1";
const BOOTSTRAP_TAG: &[u8] = b"lab-snp-kms-bootstrap/v1";
const APP_TAG: &[u8] = b"lab-snp-kms-app/v1";

/// Simulated SNP report plus the ASK and VCEK certificates that signed it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SimEvidence {
    pub report: Vec<u8>,
    pub cert_chain: Vec<Vec<u8>>,
}

/// Quote issuer for the lab VCEK chain. It is not a production AMD KDS.
pub struct SimTsm {
    generator: SevSnpGenerator,
}

impl SimTsm {
    pub fn from_seed(seed: [u8; 32]) -> Result<Self> {
        Ok(Self {
            generator: SevSnpGenerator::from_seed(seed)?,
        })
    }

    pub fn ark_pem(&self) -> String {
        self.generator.root_ca_pem()
    }

    /// Sign one report under this simulator's VCEK.
    pub fn quote(
        &self,
        report_data: [u8; REPORT_DATA_LEN],
        measurement: [u8; MEASUREMENT_LEN],
    ) -> Result<SimEvidence> {
        let evidence =
            self.generator
                .attest_with_measurement(report_data, [0u8; 32], measurement)?;
        Ok(SimEvidence {
            report: evidence.report,
            cert_chain: evidence.cert_chain,
        })
    }
}

/// `report_data` a guest must present to receive `app_id`'s lab key.
pub fn app_report_data(app_id: &[u8]) -> [u8; REPORT_DATA_LEN] {
    tagged_report_data(APP_TAG, &[app_id])
}

/// `report_data` covering the bootstrap domain and the root public key.
pub fn bootstrap_report_data(domain: &str, k256_public: &[u8]) -> [u8; REPORT_DATA_LEN] {
    tagged_report_data(BOOTSTRAP_TAG, &[domain.as_bytes(), k256_public])
}

#[derive(Clone, Debug, Serialize)]
struct BootstrapRecord {
    domain: String,
    k256_public: Vec<u8>,
    evidence: EvidenceRecord,
    #[serde(serialize_with = "serialize_array")]
    report_data: [u8; REPORT_DATA_LEN],
    #[serde(serialize_with = "serialize_array")]
    measurement: [u8; MEASUREMENT_LEN],
    simulated: bool,
    production_accepted: bool,
}

#[derive(Clone, Debug, Serialize)]
struct EvidenceRecord {
    report: Vec<u8>,
    cert_chain: Vec<Vec<u8>>,
}

impl From<&SimEvidence> for EvidenceRecord {
    fn from(evidence: &SimEvidence) -> Self {
        Self {
            report: evidence.report.clone(),
            cert_chain: evidence.cert_chain.clone(),
        }
    }
}

impl From<&EvidenceRecord> for SimEvidence {
    fn from(evidence: &EvidenceRecord) -> Self {
        Self {
            report: evidence.report.clone(),
            cert_chain: evidence.cert_chain.clone(),
        }
    }
}

/// Public result of bootstrap. The root secret stays inside the KMS.
#[derive(Clone, Debug, Serialize)]
pub struct BootstrapReceipt {
    pub domain: String,
    pub k256_public: Vec<u8>,
    #[serde(serialize_with = "serialize_array")]
    pub report_data: [u8; REPORT_DATA_LEN],
    #[serde(serialize_with = "serialize_array")]
    pub measurement: [u8; MEASUREMENT_LEN],
    pub simulated: bool,
    pub production_accepted: bool,
}

/// Public result of onboarding from an already bootstrapped lab KMS.
#[derive(Clone, Debug, Serialize)]
pub struct OnboardReceipt {
    pub domain: String,
    pub source_domain: String,
    pub simulated: bool,
    pub production_accepted: bool,
}

/// One lab app key. `simulated` is true and `production_accepted` is false.
#[derive(Clone, Debug, Serialize)]
pub struct AppKeyRecord {
    app_id: Vec<u8>,
    key: [u8; 32],
    #[serde(serialize_with = "serialize_array")]
    measurement: [u8; MEASUREMENT_LEN],
    #[serde(serialize_with = "serialize_array")]
    report_data: [u8; REPORT_DATA_LEN],
    simulated: bool,
    production_accepted: bool,
}

impl AppKeyRecord {
    pub fn app_id(&self) -> &[u8] {
        &self.app_id
    }

    pub fn key(&self) -> &[u8; 32] {
        &self.key
    }

    pub fn measurement(&self) -> &[u8; MEASUREMENT_LEN] {
        &self.measurement
    }

    pub fn report_data(&self) -> &[u8; REPORT_DATA_LEN] {
        &self.report_data
    }

    pub fn simulated(&self) -> bool {
        self.simulated
    }

    pub fn production_accepted(&self) -> bool {
        self.production_accepted
    }
}

/// In-process lab KMS enrolled to one simulated ARK and one launch measurement.
pub struct LabSnpKms {
    ark_pem: String,
    measurement: [u8; MEASUREMENT_LEN],
    release_enabled: bool,
    root: Option<[u8; 32]>,
    bootstrap: Option<BootstrapRecord>,
}

impl LabSnpKms {
    /// Enroll a lab verifier to `ark_pem`. Key release stays off until
    /// `release_enabled` is set, matching the production SNP release gate.
    pub fn enroll(
        ark_pem: impl Into<String>,
        measurement: [u8; MEASUREMENT_LEN],
        release_enabled: bool,
    ) -> Self {
        Self {
            ark_pem: ark_pem.into(),
            measurement,
            release_enabled,
            root: None,
            bootstrap: None,
        }
    }

    pub fn is_keyed(&self) -> bool {
        self.root.is_some()
    }

    /// Mint a fresh root, attest its public key, and store the root only
    /// after the lab chain accepts that quote.
    pub fn bootstrap(&mut self, tsm: &SimTsm, domain: &str) -> Result<BootstrapReceipt> {
        validate_domain(domain)?;
        if self.root.is_some() {
            bail!("kms has already been bootstrapped");
        }
        let signing = SigningKey::random(&mut OsRng);
        let secret: [u8; 32] = signing
            .to_bytes()
            .as_slice()
            .try_into()
            .context("k256 secret must be 32 bytes")?;
        let public = signing.verifying_key().to_sec1_bytes().to_vec();
        let report_data = bootstrap_report_data(domain, &public);
        let evidence = tsm.quote(report_data, self.measurement)?;
        let verified = self.verify_lab(&evidence, &report_data)?;
        if verified.measurement != self.measurement {
            bail!("amd sev-snp measurement mismatch");
        }
        let record = BootstrapRecord {
            domain: domain.to_string(),
            k256_public: public.clone(),
            evidence: EvidenceRecord::from(&evidence),
            report_data,
            measurement: verified.measurement,
            simulated: true,
            production_accepted: false,
        };
        self.root = Some(secret);
        self.bootstrap = Some(record);
        Ok(BootstrapReceipt {
            domain: domain.to_string(),
            k256_public: public,
            report_data,
            measurement: self.measurement,
            simulated: true,
            production_accepted: false,
        })
    }

    /// Copy the source root only after its bootstrap quote verifies against
    /// this KMS's enrolled ARK, measurement, and `report_data`.
    pub fn onboard_from(&mut self, source: &Self, domain: &str) -> Result<OnboardReceipt> {
        validate_domain(domain)?;
        if self.root.is_some() {
            bail!("kms has already been onboarded");
        }
        let source_root = source
            .root
            .context("source kms has not been bootstrapped")?;
        let record = source
            .bootstrap
            .as_ref()
            .context("source kms has not been bootstrapped")?;
        let expected = bootstrap_report_data(&record.domain, &record.k256_public);
        if expected != record.report_data {
            bail!("bootstrap report_data mismatch");
        }
        let evidence = SimEvidence::from(&record.evidence);
        let verified = self.verify_lab(&evidence, &expected)?;
        if verified.measurement != self.measurement {
            bail!("amd sev-snp measurement mismatch");
        }
        if verified.report_data != expected {
            bail!("bootstrap report_data mismatch");
        }
        self.root = Some(source_root);
        self.bootstrap = Some(record.clone());
        Ok(OnboardReceipt {
            domain: domain.to_string(),
            source_domain: record.domain.clone(),
            simulated: true,
            production_accepted: false,
        })
    }

    /// Release one app key when the quote's measurement and `report_data`
    /// match this KMS. The key bytes are a lab KDF, not production
    /// `derive_k256_key`.
    pub fn release_app_key(&self, app_id: &[u8], evidence: &SimEvidence) -> Result<AppKeyRecord> {
        if app_id.is_empty() {
            bail!("app id is empty");
        }
        let root = self.root.context("kms has not been bootstrapped")?;
        if !self.release_enabled {
            bail!("amd sev-snp key release is not enabled");
        }
        let expected = app_report_data(app_id);
        let verified = self.verify_lab(evidence, &expected)?;
        if verified.measurement != self.measurement {
            bail!("amd sev-snp measurement mismatch");
        }
        Ok(AppKeyRecord {
            app_id: app_id.to_vec(),
            key: lab_app_key(&root, app_id, &verified.measurement)?,
            measurement: verified.measurement,
            report_data: verified.report_data,
            simulated: true,
            production_accepted: false,
        })
    }

    /// Refuse simulated evidence. The success type cannot be constructed.
    ///
    /// The production quote verifier is consulted so a lab chain that it
    /// rejected is the usual path. An unexpected acceptance is still refused.
    pub fn production_gate(
        evidence: &SimEvidence,
        report_data: &[u8; REPORT_DATA_LEN],
    ) -> Result<std::convert::Infallible> {
        let prod = QuoteVerifier::new_prod();
        match prod.verify(&evidence.report, &evidence.cert_chain, report_data) {
            Ok(_) => {
                bail!("simulated snp output refused: production verifier accepted lab evidence")
            }
            Err(_) => bail!("simulated snp evidence is refused by the production gate"),
        }
    }

    fn verify_lab(
        &self,
        evidence: &SimEvidence,
        report_data: &[u8; REPORT_DATA_LEN],
    ) -> Result<sev_snp_qvl::VerifiedAmdSnpReport> {
        let pem = self.ark_pem.as_bytes().to_vec();
        let verifier = QuoteVerifier::new(pem.clone(), pem.clone(), pem);
        verifier
            .verify(&evidence.report, &evidence.cert_chain, report_data)
            .context("lab sev-snp verification failed")
    }
}

fn lab_app_key(
    root: &[u8; 32],
    app_id: &[u8],
    measurement: &[u8; MEASUREMENT_LEN],
) -> Result<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(LAB_KDF_SALT), root);
    let mut info = Vec::with_capacity(APP_TAG.len() + app_id.len() + measurement.len());
    info.extend_from_slice(APP_TAG);
    info.extend_from_slice(app_id);
    info.extend_from_slice(measurement);
    let mut okm = [0u8; 32];
    hk.expand(&info, &mut okm)
        .map_err(|_| anyhow::anyhow!("failed to derive lab app key"))?;
    Ok(okm)
}

fn serialize_array<S, const N: usize>(
    value: &[u8; N],
    serializer: S,
) -> std::result::Result<S::Ok, S::Error>
where
    S: Serializer,
{
    value.as_slice().serialize(serializer)
}

fn tagged_report_data(tag: &[u8], parts: &[&[u8]]) -> [u8; REPORT_DATA_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(tag);
    for part in parts {
        hasher.update((part.len() as u32).to_be_bytes());
        hasher.update(part);
    }
    let digest = hasher.finalize();
    let mut out = [0u8; REPORT_DATA_LEN];
    out[..32].copy_from_slice(&digest);
    out
}

fn validate_domain(domain: &str) -> Result<()> {
    if domain.is_empty() || domain.len() > 253 || !domain.is_ascii() {
        bail!("domain must be a non-empty ASCII DNS name of at most 253 bytes");
    }
    for label in domain.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            bail!("domain contains an invalid DNS label");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use mock_attestation::tdx::TdxGenerator;

    const MEASUREMENT: [u8; 48] = [0x33; 48];
    const OTHER_MEASUREMENT: [u8; 48] = [0x44; 48];

    fn lab() -> (LabSnpKms, SimTsm) {
        let tsm = SimTsm::from_seed([0x11; 32]).unwrap();
        let kms = LabSnpKms::enroll(tsm.ark_pem(), MEASUREMENT, true);
        (kms, tsm)
    }

    fn boot(kms: &mut LabSnpKms, tsm: &SimTsm) {
        kms.bootstrap(tsm, "kms.lab.example").unwrap();
    }

    #[test]
    fn release_requires_measurement_and_report_data() {
        let (mut kms, tsm) = lab();
        boot(&mut kms, &tsm);
        let app_id = b"app-a";
        let quote = tsm.quote(app_report_data(app_id), MEASUREMENT).unwrap();
        let released = kms.release_app_key(app_id, &quote).unwrap();
        assert!(released.simulated());
        assert!(!released.production_accepted());
        assert_eq!(released.measurement(), &MEASUREMENT);
        assert_eq!(released.report_data(), &app_report_data(app_id));
        let again = kms.release_app_key(app_id, &quote).unwrap();
        assert_eq!(released.key(), again.key());

        let wrong_measurement = tsm
            .quote(app_report_data(app_id), OTHER_MEASUREMENT)
            .unwrap();
        let err = kms.release_app_key(app_id, &wrong_measurement).unwrap_err();
        assert!(err.to_string().contains("measurement mismatch"));

        let wrong_report = tsm.quote([0xab; 64], MEASUREMENT).unwrap();
        let err = kms.release_app_key(app_id, &wrong_report).unwrap_err();
        assert!(format!("{err:#}").contains("report_data"), "{err:#}");
    }

    #[test]
    fn release_stays_off_until_the_gate_is_enabled() {
        let tsm = SimTsm::from_seed([0x11; 32]).unwrap();
        let mut kms = LabSnpKms::enroll(tsm.ark_pem(), MEASUREMENT, false);
        boot(&mut kms, &tsm);
        let quote = tsm.quote(app_report_data(b"app-a"), MEASUREMENT).unwrap();
        let err = kms.release_app_key(b"app-a", &quote).unwrap_err();
        assert!(err.to_string().contains("not enabled"));
        assert!(kms.is_keyed());
    }

    #[test]
    fn onboard_copies_the_root_only_after_the_source_quote_verifies() {
        let (mut source, tsm) = lab();
        boot(&mut source, &tsm);
        let mut target = LabSnpKms::enroll(tsm.ark_pem(), MEASUREMENT, true);
        let receipt = target.onboard_from(&source, "kms-2.lab.example").unwrap();
        assert!(receipt.simulated);
        assert!(!receipt.production_accepted);
        assert_eq!(receipt.source_domain, "kms.lab.example");
        let quote = tsm.quote(app_report_data(b"app-a"), MEASUREMENT).unwrap();
        let from_source = source.release_app_key(b"app-a", &quote).unwrap();
        let from_target = target.release_app_key(b"app-a", &quote).unwrap();
        assert_eq!(from_source.key(), from_target.key());

        let mut wrong_measurement = LabSnpKms::enroll(tsm.ark_pem(), OTHER_MEASUREMENT, true);
        let err = wrong_measurement
            .onboard_from(&source, "kms-3.lab.example")
            .unwrap_err();
        assert!(err.to_string().contains("measurement mismatch"));
        assert!(!wrong_measurement.is_keyed());

        let outsider = SimTsm::from_seed([0x22; 32]).unwrap();
        let mut foreign = LabSnpKms::enroll(outsider.ark_pem(), MEASUREMENT, true);
        let err = foreign
            .onboard_from(&source, "kms-4.lab.example")
            .unwrap_err();
        assert!(err.to_string().contains("lab sev-snp verification failed"));
        assert!(!foreign.is_keyed());
    }

    #[test]
    fn a_tdx_quote_is_refused_on_the_snp_path() {
        let (mut kms, tsm) = lab();
        boot(&mut kms, &tsm);
        let tdx = TdxGenerator::from_seed([0x9; 32]).unwrap();
        let quote = tdx.attest(app_report_data(b"app-a")).unwrap();
        let evidence = SimEvidence {
            report: quote.quote,
            cert_chain: Vec::new(),
        };
        let err = kms.release_app_key(b"app-a", &evidence).unwrap_err();
        assert!(err.to_string().contains("lab sev-snp verification failed"));
    }

    #[test]
    fn production_gate_rejects_lab_evidence() {
        let (mut kms, tsm) = lab();
        boot(&mut kms, &tsm);
        let report_data = app_report_data(b"app-a");
        let quote = tsm.quote(report_data, MEASUREMENT).unwrap();
        let released = kms.release_app_key(b"app-a", &quote).unwrap();
        let encoded = serde_json::to_value(&released).unwrap();
        assert_eq!(encoded["simulated"], true);
        assert_eq!(encoded["production_accepted"], false);

        let prod = QuoteVerifier::new_prod();
        assert!(prod
            .verify(&quote.report, &quote.cert_chain, &report_data)
            .is_err());
        match LabSnpKms::production_gate(&quote, &report_data) {
            Ok(never) => match never {},
            Err(err) => {
                assert_eq!(
                    err.to_string(),
                    "simulated snp evidence is refused by the production gate"
                );
            }
        }
    }

    #[test]
    fn a_mock_root_outside_the_lab_enrollment_is_refused() {
        let (mut kms, tsm) = lab();
        boot(&mut kms, &tsm);
        let outsider = SimTsm::from_seed([0x22; 32]).unwrap();
        let quote = outsider
            .quote(app_report_data(b"app-a"), MEASUREMENT)
            .unwrap();
        assert!(kms.release_app_key(b"app-a", &quote).is_err());

        let pem = outsider.ark_pem().into_bytes();
        let outside = QuoteVerifier::new(pem.clone(), pem.clone(), pem);
        assert!(outside
            .verify(&quote.report, &quote.cert_chain, &app_report_data(b"app-a"))
            .is_ok());
        let lab_quote = tsm.quote(app_report_data(b"app-a"), MEASUREMENT).unwrap();
        assert!(outside
            .verify(
                &lab_quote.report,
                &lab_quote.cert_chain,
                &app_report_data(b"app-a")
            )
            .is_err());
    }

    #[test]
    fn bootstrap_rejects_a_bad_domain_and_a_foreign_chain() {
        let (mut kms, tsm) = lab();
        assert!(kms.bootstrap(&tsm, "").is_err());
        assert!(kms.bootstrap(&tsm, "-bad.example").is_err());
        assert!(!kms.is_keyed());
        let outsider = SimTsm::from_seed([0x22; 32]).unwrap();
        assert!(kms.bootstrap(&outsider, "kms.lab.example").is_err());
        assert!(!kms.is_keyed());
        boot(&mut kms, &tsm);
        assert!(kms.bootstrap(&tsm, "other.lab.example").is_err());
        assert!(kms.is_keyed());
    }
}

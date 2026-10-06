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
//!
//! Two output generations exist. The v1 records ([`BootstrapReceipt`],
//! [`OnboardReceipt`], [`AppKeyRecord`]) are unchanged because Eggomi parses
//! their exact serde form. The v2 outputs answer eggomi#757 items 1-3:
//! [`SignedAppKeyRelease`] is signed by the attested root key and binds a
//! caller nonce, [`AttestedOnboardReceipt`] carries the target's own quote
//! and the root it now holds, and [`BootstrapAttestation`] carries the
//! bootstrap evidence in a public serde form ([`SimEvidence`]).

use anyhow::{bail, Context, Result};
use hkdf::Hkdf;
use k256::ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use k256::ecdsa::{Signature, SigningKey, VerifyingKey};
use mock_attestation::sev_snp::SevSnpGenerator;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize, Serializer};
use sev_snp_qvl::{AmdKdsClient, QuoteVerifier};
use sha2::{Digest, Sha256};

const MEASUREMENT_LEN: usize = 48;
const REPORT_DATA_LEN: usize = 64;
const LAB_KDF_SALT: &[u8] = b"lab-snp-sim-kms/v1";
const BOOTSTRAP_TAG: &[u8] = b"lab-snp-kms-bootstrap/v1";
const APP_TAG: &[u8] = b"lab-snp-kms-app/v1";
const APP_RELEASE_TAG: &[u8] = b"lab-snp-kms-app/v2";
const ONBOARD_TAG: &[u8] = b"lab-snp-kms-onboard/v1";
const RELEASE_SIG_TAG: &[u8] = b"lab-snp-kms-release-sig/v1";
const KEY_COMMIT_TAG: &[u8] = b"lab-snp-kms-key-commit/v1";

/// `version` of a [`SignedAppKeyRelease`].
pub const SIGNED_RELEASE_VERSION: u32 = 2;
/// Shortest caller nonce a v2 release accepts.
pub const MIN_NONCE_LEN: usize = 16;
/// Longest caller nonce a v2 release accepts.
pub const MAX_NONCE_LEN: usize = 64;

/// Simulated SNP report plus the ASK and VCEK certificates that signed it.
///
/// The serde form is public: `{"report":[..],"cert_chain":[[..],..]}` with
/// bytes as arrays of numbers, the same encoding as the v1 records. An empty
/// `cert_chain` means the verifier fetches ASK and VCEK from an AMD-KDS-shaped
/// endpoint, as it does for a guest quote from the simulated TSM.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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

/// `report_data` a guest presents for a v2 release: the app and the caller's
/// nonce. A recorded release therefore answers only the nonce it was made for.
pub fn app_release_report_data(app_id: &[u8], nonce: &[u8]) -> [u8; REPORT_DATA_LEN] {
    tagged_report_data(APP_RELEASE_TAG, &[app_id, nonce])
}

/// `report_data` of an onboarded KMS's own quote: its domain, the source
/// domain, and the root public key it now holds.
pub fn onboard_report_data(
    domain: &str,
    source_domain: &str,
    k256_public: &[u8],
) -> [u8; REPORT_DATA_LEN] {
    tagged_report_data(
        ONBOARD_TAG,
        &[domain.as_bytes(), source_domain.as_bytes(), k256_public],
    )
}

/// Commitment to a released key. A v2 release signs this, not the key, so a
/// party that dropped the key can still check the signature.
pub fn key_commitment(key: &[u8; 32]) -> [u8; 32] {
    tagged_digest(KEY_COMMIT_TAG, &[key])
}

#[derive(Clone, Debug, Serialize)]
struct BootstrapRecord {
    domain: String,
    k256_public: Vec<u8>,
    evidence: SimEvidence,
    #[serde(serialize_with = "serialize_array")]
    report_data: [u8; REPORT_DATA_LEN],
    #[serde(serialize_with = "serialize_array")]
    measurement: [u8; MEASUREMENT_LEN],
    simulated: bool,
    production_accepted: bool,
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

/// Bootstrap quote and the public facts it binds, with its evidence.
///
/// [`BootstrapReceipt`] is the v1 form and leaves the evidence out. This form
/// lets a keeper verify the bootstrap quote itself and learn the root public
/// key that signs every [`SignedAppKeyRelease`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootstrapAttestation {
    pub domain: String,
    pub k256_public: Vec<u8>,
    #[serde(with = "byte_array")]
    pub report_data: [u8; REPORT_DATA_LEN],
    #[serde(with = "byte_array")]
    pub measurement: [u8; MEASUREMENT_LEN],
    pub evidence: SimEvidence,
    pub simulated: bool,
    pub production_accepted: bool,
}

impl BootstrapAttestation {
    /// Check the evidence under `ark_pem`, its `report_data` against the
    /// domain and root key, and its `MEASUREMENT` against `measurement`.
    pub fn verify(&self, ark_pem: &str, measurement: &[u8; MEASUREMENT_LEN]) -> Result<()> {
        validate_domain(&self.domain)?;
        let expected = bootstrap_report_data(&self.domain, &self.k256_public);
        if expected != self.report_data {
            bail!("bootstrap report_data mismatch");
        }
        let verified = verify_under_ark(ark_pem, &self.evidence, &expected)?;
        if &verified.measurement != measurement || verified.measurement != self.measurement {
            bail!("amd sev-snp measurement mismatch");
        }
        check_flags(self.simulated, self.production_accepted)
    }
}

/// Onboard result that binds the target to its own quote (eggomi#757 item 2).
///
/// `report_data` is [`onboard_report_data`] over this KMS's domain, the source
/// domain, and `k256_public`, the root public key it now holds. `evidence` is
/// the target's quote over it, verified before the root was adopted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestedOnboardReceipt {
    pub domain: String,
    pub source_domain: String,
    pub k256_public: Vec<u8>,
    #[serde(with = "byte_array")]
    pub report_data: [u8; REPORT_DATA_LEN],
    #[serde(with = "byte_array")]
    pub measurement: [u8; MEASUREMENT_LEN],
    pub evidence: SimEvidence,
    pub simulated: bool,
    pub production_accepted: bool,
}

impl AttestedOnboardReceipt {
    /// Check the target's quote under `ark_pem` and its binding to the two
    /// domains and the root key.
    pub fn verify(&self, ark_pem: &str, measurement: &[u8; MEASUREMENT_LEN]) -> Result<()> {
        validate_domain(&self.domain)?;
        validate_domain(&self.source_domain)?;
        let expected = onboard_report_data(&self.domain, &self.source_domain, &self.k256_public);
        if expected != self.report_data {
            bail!("onboard report_data mismatch");
        }
        let verified = verify_under_ark(ark_pem, &self.evidence, &expected)?;
        if &verified.measurement != measurement || verified.measurement != self.measurement {
            bail!("amd sev-snp measurement mismatch");
        }
        check_flags(self.simulated, self.production_accepted)
    }
}

/// Signed, nonced app-key release (eggomi#757 item 1).
///
/// `signature` is a 64-byte compact secp256k1 ECDSA signature (r || s, low S)
/// by the KMS root key `kms_public` over [`SignedAppKeyRelease::signing_digest`],
/// a SHA-256 digest that is used directly as the prehash. `kms_public` is the
/// `k256_public` of the KMS's [`BootstrapAttestation`]. The signature covers
/// `key_commitment`, not `key`, so a keeper may drop `key` and still verify.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedAppKeyRelease {
    pub version: u32,
    pub kms_domain: String,
    pub kms_public: Vec<u8>,
    pub app_id: Vec<u8>,
    pub nonce: Vec<u8>,
    #[serde(with = "byte_array")]
    pub key: [u8; 32],
    #[serde(with = "byte_array")]
    pub key_commitment: [u8; 32],
    #[serde(with = "byte_array")]
    pub measurement: [u8; MEASUREMENT_LEN],
    #[serde(with = "byte_array")]
    pub report_data: [u8; REPORT_DATA_LEN],
    pub simulated: bool,
    pub production_accepted: bool,
    #[serde(with = "byte_array")]
    pub signature: [u8; 64],
}

impl SignedAppKeyRelease {
    /// SHA-256 over the tag `lab-snp-kms-release-sig/v1`, then each field as
    /// a u32 big-endian length and its bytes: `version` (4 bytes big-endian),
    /// `kms_domain`, `kms_public`, `app_id`, `nonce`, `key_commitment`,
    /// `measurement`, `report_data`. This is the crate's `tagged_report_data`
    /// construction without the zero padding.
    pub fn signing_digest(&self) -> [u8; 32] {
        release_signing_digest(
            self.version,
            &self.kms_domain,
            &self.kms_public,
            &self.app_id,
            &self.nonce,
            &self.key_commitment,
            &self.measurement,
            &self.report_data,
        )
    }

    /// Check the record's internal bindings and its signature under
    /// `kms_public`, including that `key` matches `key_commitment`. It does
    /// not check the quote; the caller holds that.
    pub fn verify(&self, kms_public: &[u8]) -> Result<()> {
        if key_commitment(&self.key) != self.key_commitment {
            bail!("released key does not match its commitment");
        }
        self.verify_signed_fields(kms_public)
    }

    /// [`Self::verify`] without the key: every signed field and the signature.
    /// A keeper that discarded `key` (for example by zeroing it) uses this.
    pub fn verify_signed_fields(&self, kms_public: &[u8]) -> Result<()> {
        if self.version != SIGNED_RELEASE_VERSION {
            bail!("unsupported release version {}", self.version);
        }
        validate_domain(&self.kms_domain)?;
        validate_nonce(&self.nonce)?;
        if self.app_id.is_empty() {
            bail!("app id is empty");
        }
        if self.kms_public != kms_public {
            bail!("release was signed by a different kms");
        }
        if app_release_report_data(&self.app_id, &self.nonce) != self.report_data {
            bail!("release report_data does not bind the app and nonce");
        }
        check_flags(self.simulated, self.production_accepted)?;
        let verifying =
            VerifyingKey::from_sec1_bytes(kms_public).context("invalid kms public key")?;
        let signature = Signature::from_slice(&self.signature).context("invalid signature")?;
        verifying
            .verify_prehash(&self.signing_digest(), &signature)
            .context("release signature does not verify")
    }
}

/// In-process lab KMS enrolled to one simulated ARK and one launch measurement.
pub struct LabSnpKms {
    ark_pem: String,
    measurement: [u8; MEASUREMENT_LEN],
    release_enabled: bool,
    root: Option<[u8; 32]>,
    domain: Option<String>,
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
            domain: None,
            bootstrap: None,
        }
    }

    pub fn is_keyed(&self) -> bool {
        self.root.is_some()
    }

    pub fn release_enabled(&self) -> bool {
        self.release_enabled
    }

    pub fn measurement(&self) -> &[u8; MEASUREMENT_LEN] {
        &self.measurement
    }

    /// The domain this KMS was bootstrapped or onboarded under.
    pub fn domain(&self) -> Option<&str> {
        self.domain.as_deref()
    }

    /// Root public key (SEC1 compressed) that signs v2 releases.
    pub fn root_public(&self) -> Option<Vec<u8>> {
        let root = self.root?;
        let signing = SigningKey::from_slice(&root).ok()?;
        Some(signing.verifying_key().to_sec1_bytes().to_vec())
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
            evidence,
            report_data,
            measurement: verified.measurement,
            simulated: true,
            production_accepted: false,
        };
        self.root = Some(secret);
        self.domain = Some(domain.to_string());
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

    /// The bootstrap quote with its evidence, in the public serde form
    /// (eggomi#757 item 3). An onboarded KMS returns its source's bootstrap.
    pub fn bootstrap_attestation(&self) -> Option<BootstrapAttestation> {
        let record = self.bootstrap.as_ref()?;
        Some(BootstrapAttestation {
            domain: record.domain.clone(),
            k256_public: record.k256_public.clone(),
            report_data: record.report_data,
            measurement: record.measurement,
            evidence: record.evidence.clone(),
            simulated: record.simulated,
            production_accepted: record.production_accepted,
        })
    }

    /// Copy the source root only after its bootstrap quote verifies against
    /// this KMS's enrolled ARK, measurement, and `report_data`.
    pub fn onboard_from(&mut self, source: &Self, domain: &str) -> Result<OnboardReceipt> {
        let (source_root, record) = self.check_onboard_source(source, domain)?;
        let source_domain = record.domain.clone();
        self.adopt(source_root, record, domain);
        Ok(OnboardReceipt {
            domain: domain.to_string(),
            source_domain,
            simulated: true,
            production_accepted: false,
        })
    }

    /// [`Self::onboard_from`], plus this KMS's own quote over its domain, the
    /// source domain, and the root public key it adopts. The root is adopted
    /// only after that quote verifies too.
    pub fn onboard_from_attested(
        &mut self,
        tsm: &SimTsm,
        source: &Self,
        domain: &str,
    ) -> Result<AttestedOnboardReceipt> {
        let (source_root, record) = self.check_onboard_source(source, domain)?;
        let report_data = onboard_report_data(domain, &record.domain, &record.k256_public);
        let evidence = tsm.quote(report_data, self.measurement)?;
        let verified = self.verify_lab(&evidence, &report_data)?;
        if verified.measurement != self.measurement {
            bail!("amd sev-snp measurement mismatch");
        }
        let receipt = AttestedOnboardReceipt {
            domain: domain.to_string(),
            source_domain: record.domain.clone(),
            k256_public: record.k256_public.clone(),
            report_data,
            measurement: verified.measurement,
            evidence,
            simulated: true,
            production_accepted: false,
        };
        self.adopt(source_root, record, domain);
        Ok(receipt)
    }

    fn check_onboard_source(
        &self,
        source: &Self,
        domain: &str,
    ) -> Result<([u8; 32], BootstrapRecord)> {
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
        let verified = self.verify_lab(&record.evidence, &expected)?;
        if verified.measurement != self.measurement {
            bail!("amd sev-snp measurement mismatch");
        }
        if verified.report_data != expected {
            bail!("bootstrap report_data mismatch");
        }
        Ok((source_root, record.clone()))
    }

    fn adopt(&mut self, root: [u8; 32], record: BootstrapRecord, domain: &str) {
        self.root = Some(root);
        self.domain = Some(domain.to_string());
        self.bootstrap = Some(record);
    }

    /// Release one app key when the quote's measurement and `report_data`
    /// match this KMS. The key bytes are a lab KDF, not production
    /// `derive_k256_key`.
    pub fn release_app_key(&self, app_id: &[u8], evidence: &SimEvidence) -> Result<AppKeyRecord> {
        let root = self.release_preconditions(app_id)?;
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

    /// v2 release: the quote must carry [`app_release_report_data`] for
    /// `app_id` and the caller's `nonce`, and the record is signed by the
    /// root key. The key is the same lab KDF output as the v1 release.
    pub fn release_signed(
        &self,
        app_id: &[u8],
        nonce: &[u8],
        evidence: &SimEvidence,
    ) -> Result<SignedAppKeyRelease> {
        let root = self.release_preconditions(app_id)?;
        validate_nonce(nonce)?;
        let expected = app_release_report_data(app_id, nonce);
        let verified = self.verify_lab(evidence, &expected)?;
        self.sign_release(&root, app_id, nonce, &verified)
    }

    /// [`Self::release_signed`] for a quote whose ASK and VCEK are not
    /// attached: they are fetched from `kds`, an AMD-KDS-shaped endpoint such
    /// as `dstack-mock-attestation serve`, and still checked against the
    /// enrolled lab ARK.
    pub async fn release_signed_fetching_collateral(
        &self,
        kds: &AmdKdsClient,
        app_id: &[u8],
        nonce: &[u8],
        evidence: &SimEvidence,
    ) -> Result<SignedAppKeyRelease> {
        let root = self.release_preconditions(app_id)?;
        validate_nonce(nonce)?;
        let expected = app_release_report_data(app_id, nonce);
        let verified = self
            .lab_verifier()
            .fetch_and_verify(kds, &evidence.report, &evidence.cert_chain, &expected)
            .await
            .context("lab sev-snp verification failed")?;
        self.sign_release(&root, app_id, nonce, &verified)
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

    /// [`Self::production_gate`] for a quote without attached certificates:
    /// the production verifier fetches them from `kds`, so the refusal comes
    /// from the production ARK and not from a missing chain.
    pub async fn production_gate_fetching_collateral(
        kds: &AmdKdsClient,
        evidence: &SimEvidence,
        report_data: &[u8; REPORT_DATA_LEN],
    ) -> Result<std::convert::Infallible> {
        let prod = QuoteVerifier::new_prod();
        match prod
            .fetch_and_verify(kds, &evidence.report, &evidence.cert_chain, report_data)
            .await
        {
            Ok(_) => {
                bail!("simulated snp output refused: production verifier accepted lab evidence")
            }
            Err(err) => {
                Err(err.context("simulated snp evidence is refused by the production gate"))
            }
        }
    }

    fn release_preconditions(&self, app_id: &[u8]) -> Result<[u8; 32]> {
        if app_id.is_empty() {
            bail!("app id is empty");
        }
        let root = self.root.context("kms has not been bootstrapped")?;
        if !self.release_enabled {
            bail!("amd sev-snp key release is not enabled");
        }
        Ok(root)
    }

    fn sign_release(
        &self,
        root: &[u8; 32],
        app_id: &[u8],
        nonce: &[u8],
        verified: &sev_snp_qvl::VerifiedAmdSnpReport,
    ) -> Result<SignedAppKeyRelease> {
        if verified.measurement != self.measurement {
            bail!("amd sev-snp measurement mismatch");
        }
        let signing = SigningKey::from_slice(root).context("invalid kms root")?;
        let kms_public = signing.verifying_key().to_sec1_bytes().to_vec();
        let kms_domain = self
            .domain
            .clone()
            .context("kms has not been bootstrapped")?;
        let key = lab_app_key(root, app_id, &verified.measurement)?;
        let mut release = SignedAppKeyRelease {
            version: SIGNED_RELEASE_VERSION,
            kms_domain,
            kms_public,
            app_id: app_id.to_vec(),
            nonce: nonce.to_vec(),
            key,
            key_commitment: key_commitment(&key),
            measurement: verified.measurement,
            report_data: verified.report_data,
            simulated: true,
            production_accepted: false,
            signature: [0u8; 64],
        };
        let signature: Signature = signing
            .sign_prehash(&release.signing_digest())
            .context("failed to sign release")?;
        release.signature = signature.to_bytes().into();
        Ok(release)
    }

    fn lab_verifier(&self) -> QuoteVerifier {
        let pem = self.ark_pem.as_bytes().to_vec();
        QuoteVerifier::new(pem.clone(), pem.clone(), pem)
    }

    fn verify_lab(
        &self,
        evidence: &SimEvidence,
        report_data: &[u8; REPORT_DATA_LEN],
    ) -> Result<sev_snp_qvl::VerifiedAmdSnpReport> {
        self.lab_verifier()
            .verify(&evidence.report, &evidence.cert_chain, report_data)
            .context("lab sev-snp verification failed")
    }
}

fn verify_under_ark(
    ark_pem: &str,
    evidence: &SimEvidence,
    report_data: &[u8; REPORT_DATA_LEN],
) -> Result<sev_snp_qvl::VerifiedAmdSnpReport> {
    let pem = ark_pem.as_bytes().to_vec();
    QuoteVerifier::new(pem.clone(), pem.clone(), pem)
        .verify(&evidence.report, &evidence.cert_chain, report_data)
        .context("lab sev-snp verification failed")
}

fn check_flags(simulated: bool, production_accepted: bool) -> Result<()> {
    if !simulated || production_accepted {
        bail!("lab kms output must be simulated and never production accepted");
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn release_signing_digest(
    version: u32,
    kms_domain: &str,
    kms_public: &[u8],
    app_id: &[u8],
    nonce: &[u8],
    key_commitment: &[u8; 32],
    measurement: &[u8; MEASUREMENT_LEN],
    report_data: &[u8; REPORT_DATA_LEN],
) -> [u8; 32] {
    tagged_digest(
        RELEASE_SIG_TAG,
        &[
            &version.to_be_bytes(),
            kms_domain.as_bytes(),
            kms_public,
            app_id,
            nonce,
            key_commitment,
            measurement,
            report_data,
        ],
    )
}

fn validate_nonce(nonce: &[u8]) -> Result<()> {
    if !(MIN_NONCE_LEN..=MAX_NONCE_LEN).contains(&nonce.len()) {
        bail!("nonce must be {MIN_NONCE_LEN} to {MAX_NONCE_LEN} bytes");
    }
    Ok(())
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

fn tagged_digest(tag: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(tag);
    for part in parts {
        hasher.update((part.len() as u32).to_be_bytes());
        hasher.update(part);
    }
    hasher.finalize().into()
}

fn tagged_report_data(tag: &[u8], parts: &[&[u8]]) -> [u8; REPORT_DATA_LEN] {
    let mut out = [0u8; REPORT_DATA_LEN];
    out[..32].copy_from_slice(&tagged_digest(tag, parts));
    out
}

/// Fixed-size byte arrays as serde sequences of numbers, both directions.
mod byte_array {
    use serde::{de::Error, Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer, const N: usize>(
        value: &[u8; N],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        value.as_slice().serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>, const N: usize>(
        deserializer: D,
    ) -> Result<[u8; N], D::Error> {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        let len = bytes.len();
        bytes
            .try_into()
            .map_err(|_| D::Error::custom(format!("expected {N} bytes, got {len}")))
    }
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

    const NONCE: [u8; 32] = [0x5a; 32];

    #[test]
    fn signed_release_binds_the_nonce_and_verifies_under_the_attested_root() {
        let (mut kms, tsm) = lab();
        boot(&mut kms, &tsm);
        let bootstrap = kms.bootstrap_attestation().unwrap();
        bootstrap.verify(&tsm.ark_pem(), &MEASUREMENT).unwrap();
        assert_eq!(kms.root_public().unwrap(), bootstrap.k256_public);

        let quote = tsm
            .quote(app_release_report_data(b"app-a", &NONCE), MEASUREMENT)
            .unwrap();
        let release = kms.release_signed(b"app-a", &NONCE, &quote).unwrap();
        release.verify(&bootstrap.k256_public).unwrap();
        assert_eq!(release.version, SIGNED_RELEASE_VERSION);
        assert_eq!(release.kms_domain, "kms.lab.example");
        assert_eq!(release.nonce, NONCE);
        assert!(release.simulated && !release.production_accepted);
        // Same lab KDF as v1: the nonce is freshness, not key material.
        let v1_quote = tsm.quote(app_report_data(b"app-a"), MEASUREMENT).unwrap();
        let v1 = kms.release_app_key(b"app-a", &v1_quote).unwrap();
        assert_eq!(&release.key, v1.key());

        // A quote recorded for one nonce does not answer another.
        let err = kms
            .release_signed(b"app-a", &[0x6b; 32], &quote)
            .unwrap_err();
        assert!(format!("{err:#}").contains("report_data"), "{err:#}");
        // A v1 quote does not answer a v2 release, and the reverse.
        assert!(kms.release_signed(b"app-a", &NONCE, &v1_quote).is_err());
        assert!(kms.release_app_key(b"app-a", &quote).is_err());
        // Nonces outside 16..=64 bytes are refused before verification.
        let err = kms.release_signed(b"app-a", &[1; 8], &quote).unwrap_err();
        assert!(err.to_string().contains("nonce"));
        let wrong_measurement = tsm
            .quote(app_release_report_data(b"app-a", &NONCE), OTHER_MEASUREMENT)
            .unwrap();
        let err = kms
            .release_signed(b"app-a", &NONCE, &wrong_measurement)
            .unwrap_err();
        assert!(err.to_string().contains("measurement mismatch"));
    }

    #[test]
    fn signed_release_rejects_tampering_and_a_foreign_kms() {
        let (mut kms, tsm) = lab();
        boot(&mut kms, &tsm);
        let quote = tsm
            .quote(app_release_report_data(b"app-a", &NONCE), MEASUREMENT)
            .unwrap();
        let release = kms.release_signed(b"app-a", &NONCE, &quote).unwrap();
        let public = kms.root_public().unwrap();

        let mut other = LabSnpKms::enroll(tsm.ark_pem(), MEASUREMENT, true);
        other.bootstrap(&tsm, "kms.lab.example").unwrap();
        let err = release.verify(&other.root_public().unwrap()).unwrap_err();
        assert!(err.to_string().contains("different kms"));

        let mut tampered = release.clone();
        tampered.nonce = vec![0x6b; 32];
        assert!(tampered.verify(&public).is_err());
        let mut tampered = release.clone();
        tampered.key[0] ^= 1;
        assert!(tampered
            .verify(&public)
            .unwrap_err()
            .to_string()
            .contains("commitment"));
        // A keeper that zeroes the key still verifies every signed field.
        let mut dropped = release.clone();
        dropped.key = [0u8; 32];
        dropped.verify_signed_fields(&public).unwrap();
        dropped.key_commitment[0] ^= 1;
        assert!(dropped.verify_signed_fields(&public).is_err());
        let mut tampered = release.clone();
        tampered.measurement = OTHER_MEASUREMENT;
        assert!(tampered.verify(&public).is_err());
        let mut tampered = release.clone();
        tampered.production_accepted = true;
        assert!(tampered.verify(&public).is_err());
        // A re-signed record under another key does not pass as this KMS.
        let mut forged = release.clone();
        forged.kms_public = other.root_public().unwrap();
        assert!(forged.verify(&public).is_err());
        assert!(forged.verify(&other.root_public().unwrap()).is_err());
    }

    #[test]
    fn serde_forms_round_trip() {
        let (mut kms, tsm) = lab();
        boot(&mut kms, &tsm);
        let bootstrap = kms.bootstrap_attestation().unwrap();
        let json = serde_json::to_string(&bootstrap).unwrap();
        let back: BootstrapAttestation = serde_json::from_str(&json).unwrap();
        assert_eq!(back, bootstrap);
        back.verify(&tsm.ark_pem(), &MEASUREMENT).unwrap();

        let evidence_json = serde_json::to_value(&bootstrap.evidence).unwrap();
        assert!(evidence_json["report"].is_array());
        assert_eq!(evidence_json["cert_chain"].as_array().unwrap().len(), 2);

        let quote = tsm
            .quote(app_release_report_data(b"app-a", &NONCE), MEASUREMENT)
            .unwrap();
        let release = kms.release_signed(b"app-a", &NONCE, &quote).unwrap();
        let back: SignedAppKeyRelease =
            serde_json::from_str(&serde_json::to_string(&release).unwrap()).unwrap();
        assert_eq!(back, release);
        let short = serde_json::to_string(&release).unwrap().replacen(
            "\"signature\":[",
            "\"signature\":[1,",
            1,
        );
        assert!(serde_json::from_str::<SignedAppKeyRelease>(&short).is_err());

        // The v1 records keep their exact serde field order.
        let v1_quote = tsm.quote(app_report_data(b"app-a"), MEASUREMENT).unwrap();
        let v1 = serde_json::to_value(kms.release_app_key(b"app-a", &v1_quote).unwrap()).unwrap();
        let keys: Vec<_> = v1.as_object().unwrap().keys().cloned().collect();
        assert_eq!(
            keys,
            [
                "app_id",
                "key",
                "measurement",
                "report_data",
                "simulated",
                "production_accepted"
            ]
        );
    }

    #[test]
    fn attested_onboard_binds_the_target_quote_and_root() {
        let (mut source, tsm) = lab();
        boot(&mut source, &tsm);
        let mut target = LabSnpKms::enroll(tsm.ark_pem(), MEASUREMENT, true);
        let receipt = target
            .onboard_from_attested(&tsm, &source, "kms-2.lab.example")
            .unwrap();
        receipt.verify(&tsm.ark_pem(), &MEASUREMENT).unwrap();
        assert_eq!(receipt.k256_public, source.root_public().unwrap());
        assert_eq!(receipt.source_domain, "kms.lab.example");
        assert_eq!(
            receipt.report_data,
            onboard_report_data("kms-2.lab.example", "kms.lab.example", &receipt.k256_public)
        );
        let json = serde_json::to_string(&receipt).unwrap();
        assert_eq!(
            serde_json::from_str::<AttestedOnboardReceipt>(&json).unwrap(),
            receipt
        );

        // The target signs releases under the same root, as its own domain.
        let quote = tsm
            .quote(app_release_report_data(b"app-a", &NONCE), MEASUREMENT)
            .unwrap();
        let release = target.release_signed(b"app-a", &NONCE, &quote).unwrap();
        release.verify(&receipt.k256_public).unwrap();
        assert_eq!(release.kms_domain, "kms-2.lab.example");

        let mut swapped = receipt.clone();
        swapped.source_domain = "kms-9.lab.example".into();
        assert!(swapped.verify(&tsm.ark_pem(), &MEASUREMENT).is_err());
        assert!(receipt.verify(&tsm.ark_pem(), &OTHER_MEASUREMENT).is_err());
        let outsider = SimTsm::from_seed([0x22; 32]).unwrap();
        assert!(receipt.verify(&outsider.ark_pem(), &MEASUREMENT).is_err());

        // A target whose own quote fails stays unkeyed.
        let mut foreign_tsm_target = LabSnpKms::enroll(tsm.ark_pem(), MEASUREMENT, true);
        let err = foreign_tsm_target
            .onboard_from_attested(&outsider, &source, "kms-3.lab.example")
            .unwrap_err();
        assert!(err.to_string().contains("lab sev-snp verification failed"));
        assert!(!foreign_tsm_target.is_keyed());
    }

    #[test]
    fn signed_release_stays_off_until_the_gate_is_enabled() {
        let tsm = SimTsm::from_seed([0x11; 32]).unwrap();
        let mut kms = LabSnpKms::enroll(tsm.ark_pem(), MEASUREMENT, false);
        boot(&mut kms, &tsm);
        let quote = tsm
            .quote(app_release_report_data(b"app-a", &NONCE), MEASUREMENT)
            .unwrap();
        let err = kms.release_signed(b"app-a", &NONCE, &quote).unwrap_err();
        assert!(err.to_string().contains("not enabled"));
        match LabSnpKms::production_gate(&quote, &app_release_report_data(b"app-a", &NONCE)) {
            Ok(never) => match never {},
            Err(err) => assert!(err.to_string().contains("production gate")),
        }
    }

    #[tokio::test]
    async fn release_fetches_the_vcek_from_a_kds_and_production_roots_refuse_it() {
        use mock_attestation::server::{serve_listener, MockCollateralState};
        use std::sync::Arc;

        let (mut kms, tsm) = lab();
        boot(&mut kms, &tsm);
        let state =
            Arc::new(MockCollateralState::from_seed([0x11; 32], "http://127.0.0.1").unwrap());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(serve_listener(listener, state));
        let kds = AmdKdsClient::with_base_url(format!("http://{addr}/vcek/v1")).unwrap();

        // A guest quote from the simulated TSM carries no certificates.
        let report_data = app_release_report_data(b"app-a", &NONCE);
        let mut quote = tsm.quote(report_data, MEASUREMENT).unwrap();
        quote.cert_chain.clear();
        assert!(kms.release_signed(b"app-a", &NONCE, &quote).is_err());
        let release = kms
            .release_signed_fetching_collateral(&kds, b"app-a", &NONCE, &quote)
            .await
            .unwrap();
        release.verify(&kms.root_public().unwrap()).unwrap();

        // The same quote and collateral fail under production roots.
        match LabSnpKms::production_gate_fetching_collateral(&kds, &quote, &report_data).await {
            Ok(never) => match never {},
            Err(err) => assert!(format!("{err:#}").contains("production gate"), "{err:#}"),
        }

        // Collateral from another seed does not chain to the enrolled ARK.
        let foreign =
            Arc::new(MockCollateralState::from_seed([0x22; 32], "http://127.0.0.1").unwrap());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let foreign_addr = listener.local_addr().unwrap();
        let foreign_task = tokio::spawn(serve_listener(listener, foreign));
        let foreign_kds =
            AmdKdsClient::with_base_url(format!("http://{foreign_addr}/vcek/v1")).unwrap();
        let err = kms
            .release_signed_fetching_collateral(&foreign_kds, b"app-a", &NONCE, &quote)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("lab sev-snp verification failed"));
        task.abort();
        foreign_task.abort();
    }
}

// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Lab-only long-running simulated SNP KMS for the Eggomi L1 harness (S2).
//!
//! `serve` boots one [`LabSnpKms`] from the harness's job seed, enrolls the
//! launch measurement that a VM's `vm_config` recomputes to, and answers
//! release requests from a simulated-SNP CVM over plain HTTP. Guest quotes
//! carry no certificates, so the VCEK chain is fetched from the mock
//! AMD-KDS-shaped collateral endpoint and checked against the job's mock ARK.
//! Nothing here is a production KMS: the roots, the seed, the root key, and
//! every released key are throwaway lab material.

use std::{net::SocketAddr, path::Path, path::PathBuf, sync::Arc};

use anyhow::{bail, Context, Result};
use axum::{
    extract::{Query, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use clap::{Args, Parser, Subcommand};
use dstack_attest::attestation::{PlatformEvidence, VersionedAttestation};
use serde::Deserialize;
use serde_json::{json, Value};
use sev_snp_qvl::AmdKdsClient;
use snp_sim_kms::{
    app_release_report_data, app_report_data, BootstrapAttestation, LabSnpKms, SignedAppKeyRelease,
    SimEvidence, SimTsm,
};

#[derive(Parser)]
#[command(about = "Lab-only simulated AMD SEV-SNP KMS. Never point production at it.")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Serve bootstrap and signed releases over HTTP.
    Serve(ServeArgs),
    /// Print the launch MEASUREMENT that a vm_config recomputes to.
    Measurement {
        /// A VM's `shared/.tee-simulator.json`, or a bare vm_config JSON file.
        #[arg(long)]
        vm_config: PathBuf,
    },
    /// Check one guest attestation against both trust roots. Exits 0 only when
    /// the job's mock root accepts it (so the collateral and report are
    /// sound) and the production AMD roots refuse it.
    ProductionGate {
        #[command(flatten)]
        seed: SeedArgs,
        /// File holding the hex attestation from the guest's /Attest.
        #[arg(long)]
        attestation: PathBuf,
        /// Hex report_data the attestation was requested for.
        #[arg(long)]
        report_data: String,
        /// AMD-KDS-shaped base URL used to fetch the ASK and VCEK.
        #[arg(long)]
        kds_url: String,
    },
    /// Check a signed release the way a keeper does: the bootstrap quote under
    /// the mock ARK, then the release signature under the attested root key.
    VerifyRelease {
        #[command(flatten)]
        seed: SeedArgs,
        /// JSON from GET /v1/bootstrap.
        #[arg(long)]
        bootstrap: PathBuf,
        /// JSON from POST /v1/release.
        #[arg(long)]
        release: PathBuf,
        /// Expected 48-byte hex MEASUREMENT.
        #[arg(long)]
        measurement: String,
        /// Expected hex app id.
        #[arg(long)]
        app_id: String,
        /// Expected hex nonce, the one the caller chose.
        #[arg(long)]
        nonce: String,
    },
    /// Write the checked keeper-side fixture set: every KMS output, v1 and
    /// v2, with its evidence, and the vectors the KMS must refuse.
    Fixtures {
        #[command(flatten)]
        seed: SeedArgs,
        /// Output JSON file.
        #[arg(long)]
        out: PathBuf,
    },
}

#[derive(Args)]
struct SeedArgs {
    /// `mock-roots/tee-simulator.json` from `mock-collateral.sh generate`.
    #[arg(long, conflicts_with = "seed")]
    mock_config: Option<PathBuf>,
    /// 32-byte hex seed, for fixtures that need no harness state.
    #[arg(long)]
    seed: Option<String>,
}

#[derive(Args)]
struct ServeArgs {
    #[arg(long, default_value = "127.0.0.1:18101")]
    listen: SocketAddr,
    #[command(flatten)]
    seed: SeedArgs,
    /// AMD-KDS-shaped base URL, for example http://127.0.0.1:18100/vcek/v1.
    #[arg(long)]
    kds_url: String,
    /// DNS name this KMS bootstraps under.
    #[arg(long, default_value = "kms.l1.eggomi.lab")]
    domain: String,
    /// Enroll the MEASUREMENT this vm_config recomputes to.
    #[arg(long, required_unless_present = "measurement")]
    enroll_vm_config: Option<PathBuf>,
    /// Enroll this 48-byte hex MEASUREMENT instead.
    #[arg(long, conflicts_with = "enroll_vm_config")]
    measurement: Option<String>,
    /// Open the SNP release gate. Off by default, as `sev_snp_key_release`.
    #[arg(long)]
    release_enabled: bool,
}

struct AppState {
    kms: LabSnpKms,
    kds: AmdKdsClient,
}

type Reply = (StatusCode, Json<Value>);

#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Serve(args) => serve(args).await,
        Command::Measurement { vm_config } => {
            println!("{}", hex::encode(measurement_from_vm_config(&vm_config)?));
            Ok(())
        }
        Command::ProductionGate {
            seed,
            attestation,
            report_data,
            kds_url,
        } => production_gate(&seed, &attestation, &report_data, &kds_url).await,
        Command::VerifyRelease {
            seed,
            bootstrap,
            release,
            measurement,
            app_id,
            nonce,
        } => verify_release(&seed, &bootstrap, &release, &measurement, &app_id, &nonce),
        Command::Fixtures { seed, out } => fixtures(&seed, &out),
    }
}

async fn serve(args: ServeArgs) -> Result<()> {
    let tsm = SimTsm::from_seed(load_seed(&args.seed)?)?;
    let measurement = match (&args.enroll_vm_config, &args.measurement) {
        (Some(path), _) => measurement_from_vm_config(path)?,
        (None, Some(hex)) => decode_fixed::<48>("measurement", hex)?,
        (None, None) => bail!("pass --enroll-vm-config or --measurement"),
    };
    let mut kms = LabSnpKms::enroll(tsm.ark_pem(), measurement, args.release_enabled);
    kms.bootstrap(&tsm, &args.domain)?;
    let kds = AmdKdsClient::with_base_url(&args.kds_url)?;
    eprintln!(
        "snp-sim-kms: lab only; domain={} measurement={} release_enabled={} kms_public={} listen={}",
        args.domain,
        hex::encode(measurement),
        args.release_enabled,
        hex::encode(kms.root_public().unwrap_or_default()),
        args.listen
    );
    let state = Arc::new(AppState { kms, kds });
    let app = Router::new()
        .route("/health", get(health))
        .route("/v1/bootstrap", get(bootstrap))
        .route("/v1/report-data", get(report_data))
        .route("/v1/release", post(release))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind(args.listen)
        .await
        .with_context(|| format!("failed to bind {}", args.listen))?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn health(State(state): State<Arc<AppState>>) -> Reply {
    (
        StatusCode::OK,
        Json(json!({
            "simulated": true,
            "production_accepted": false,
            "release_enabled": state.kms.release_enabled(),
            "domain": state.kms.domain(),
            "measurement": hex::encode(state.kms.measurement()),
            "kms_public": hex::encode(state.kms.root_public().unwrap_or_default()),
        })),
    )
}

async fn bootstrap(State(state): State<Arc<AppState>>) -> Reply {
    match state.kms.bootstrap_attestation() {
        Some(attestation) => (StatusCode::OK, Json(json!(attestation))),
        None => error(
            StatusCode::SERVICE_UNAVAILABLE,
            "kms has not been bootstrapped",
        ),
    }
}

#[derive(Deserialize)]
struct ReportDataQuery {
    app_id: String,
    nonce: Option<String>,
}

/// Public helper: the report_data a guest must quote. Wrong input only
/// produces a quote that the release endpoint refuses.
async fn report_data(Query(query): Query<ReportDataQuery>) -> Reply {
    let Ok(app_id) = hex::decode(&query.app_id) else {
        return error(StatusCode::BAD_REQUEST, "app_id is not hex");
    };
    let report_data = match &query.nonce {
        None => app_report_data(&app_id),
        Some(nonce) => match hex::decode(nonce) {
            Ok(nonce) => app_release_report_data(&app_id, &nonce),
            Err(_) => return error(StatusCode::BAD_REQUEST, "nonce is not hex"),
        },
    };
    (
        StatusCode::OK,
        Json(json!({ "report_data": hex::encode(report_data) })),
    )
}

#[derive(Deserialize)]
struct ReleaseRequest {
    /// Hex app id.
    app_id: String,
    /// Hex caller nonce, 16 to 64 bytes.
    nonce: String,
    /// Hex `VersionedAttestation` from the guest agent's /Attest.
    attestation: Option<String>,
    /// Or the SNP evidence itself, in its serde form.
    evidence: Option<SimEvidence>,
}

async fn release(State(state): State<Arc<AppState>>, Json(request): Json<ReleaseRequest>) -> Reply {
    let parsed = (|| -> Result<(Vec<u8>, Vec<u8>, SimEvidence)> {
        let app_id = hex::decode(&request.app_id).context("app_id is not hex")?;
        let nonce = hex::decode(&request.nonce).context("nonce is not hex")?;
        let evidence = match (&request.attestation, &request.evidence) {
            (Some(attestation), None) => evidence_from_attestation(
                &hex::decode(attestation.trim()).context("attestation is not hex")?,
            )?,
            (None, Some(evidence)) => evidence.clone(),
            _ => bail!("pass exactly one of attestation or evidence"),
        };
        Ok((app_id, nonce, evidence))
    })();
    let (app_id, nonce, evidence) = match parsed {
        Ok(parsed) => parsed,
        Err(err) => return error(StatusCode::BAD_REQUEST, &format!("{err:#}")),
    };
    match state
        .kms
        .release_signed_fetching_collateral(&state.kds, &app_id, &nonce, &evidence)
        .await
    {
        Ok(released) => {
            eprintln!(
                "snp-sim-kms: released app_id={} nonce={}",
                hex::encode(&app_id),
                hex::encode(&nonce)
            );
            (StatusCode::OK, Json(json!(released)))
        }
        Err(err) => {
            let reason = format!("{err:#}");
            eprintln!(
                "snp-sim-kms: refused app_id={} nonce={}: {reason}",
                hex::encode(&app_id),
                hex::encode(&nonce)
            );
            error(StatusCode::FORBIDDEN, &reason)
        }
    }
}

fn error(status: StatusCode, reason: &str) -> Reply {
    (status, Json(json!({ "refused": true, "error": reason })))
}

async fn production_gate(
    seed: &SeedArgs,
    attestation: &Path,
    report_data: &str,
    kds_url: &str,
) -> Result<()> {
    let raw = std::fs::read_to_string(attestation)
        .with_context(|| format!("failed to read {}", attestation.display()))?;
    let evidence =
        evidence_from_attestation(&hex::decode(raw.trim()).context("attestation is not hex")?)?;
    let report_data = decode_fixed::<64>("report_data", report_data)?;
    let kds = AmdKdsClient::with_base_url(kds_url)?;
    // The mock root must accept the same bytes and collateral first. Without
    // this, a collateral outage or a malformed report would read as a
    // production-root rejection.
    let ark = SimTsm::from_seed(load_seed(seed)?)?.ark_pem().into_bytes();
    sev_snp_qvl::QuoteVerifier::new(ark.clone(), ark.clone(), ark)
        .fetch_and_verify(&kds, &evidence.report, &evidence.cert_chain, &report_data)
        .await
        .context("the mock root does not accept this evidence; the check proves nothing")?;
    match sev_snp_qvl::QuoteVerifier::new_prod()
        .fetch_and_verify(&kds, &evidence.report, &evidence.cert_chain, &report_data)
        .await
    {
        Ok(_) => bail!("production AMD roots accepted simulated evidence"),
        Err(err) => {
            // The lab KMS gate refuses unconditionally as well.
            let gate = LabSnpKms::production_gate(&evidence, &report_data);
            println!(
                "{}",
                json!({
                    "development_root_accepted": true,
                    "production_root_rejected": true,
                    "production_gate_refused": gate.is_err(),
                    "reason": format!("{err:#}"),
                })
            );
            Ok(())
        }
    }
}

fn verify_release(
    seed: &SeedArgs,
    bootstrap: &Path,
    release: &Path,
    measurement: &str,
    app_id: &str,
    nonce: &str,
) -> Result<()> {
    let ark_pem = SimTsm::from_seed(load_seed(seed)?)?.ark_pem();
    let measurement = decode_fixed::<48>("measurement", measurement)?;
    let bootstrap: BootstrapAttestation =
        serde_json::from_str(&std::fs::read_to_string(bootstrap)?)
            .context("bootstrap is not a BootstrapAttestation")?;
    bootstrap
        .verify(&ark_pem, &measurement)
        .context("bootstrap attestation does not verify")?;
    let release: SignedAppKeyRelease = serde_json::from_str(&std::fs::read_to_string(release)?)
        .context("release is not a SignedAppKeyRelease")?;
    release.verify(&bootstrap.k256_public)?;
    if release.app_id != hex::decode(app_id).context("app_id is not hex")? {
        bail!("release names another app");
    }
    if release.nonce != hex::decode(nonce).context("nonce is not hex")? {
        bail!("release answers another nonce");
    }
    if release.measurement != measurement {
        bail!("release names another measurement");
    }
    println!(
        "{}",
        json!({
            "release_verified": true,
            "kms_domain": release.kms_domain,
            "kms_public": hex::encode(&release.kms_public),
            "simulated": release.simulated,
            "production_accepted": release.production_accepted,
        })
    );
    Ok(())
}

fn fixtures(seed: &SeedArgs, out: &Path) -> Result<()> {
    // fixture_set checks every output before it returns; a set that fails a
    // check is never written.
    let set = snp_sim_kms::fixtures::fixture_set(load_seed(seed)?)?;
    std::fs::write(out, serde_json::to_string_pretty(&set)? + "\n")
        .with_context(|| format!("failed to write {}", out.display()))?;
    eprintln!(
        "snp-sim-kms: wrote checked lab fixtures to {}",
        out.display()
    );
    Ok(())
}

/// The SNP report and any attached certificates from a guest attestation.
fn evidence_from_attestation(bytes: &[u8]) -> Result<SimEvidence> {
    let attestation =
        VersionedAttestation::from_bytes(bytes).context("failed to decode attestation")?;
    match attestation.into_v1().platform {
        PlatformEvidence::SevSnp {
            report, cert_chain, ..
        } => Ok(SimEvidence { report, cert_chain }),
        _ => bail!("attestation is not amd sev-snp evidence"),
    }
}

fn measurement_from_vm_config(path: &Path) -> Result<[u8; 48]> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    let value: Value = serde_json::from_str(&raw).context("vm_config file is not JSON")?;
    // A VM's .tee-simulator.json carries vm_config as a JSON string.
    let vm_config = match value.get("vm_config").and_then(Value::as_str) {
        Some(nested) => nested.to_string(),
        None => raw,
    };
    let inputs = dstack_mr::sev::parse_snp_inputs_from_vm_config(&vm_config)?;
    dstack_mr::sev::validate_measurement_input(&inputs.input)?;
    dstack_mr::sev::compute_expected_measurement(&inputs.input)
}

fn load_seed(args: &SeedArgs) -> Result<[u8; 32]> {
    match (&args.mock_config, &args.seed) {
        (Some(path), None) => {
            let raw = std::fs::read_to_string(path)
                .with_context(|| format!("failed to read {}", path.display()))?;
            let value: Value = serde_json::from_str(&raw).context("mock config is not JSON")?;
            let seed = value
                .get("mock_attestation_seed")
                .and_then(Value::as_str)
                .context("mock config has no mock_attestation_seed")?;
            let seed = decode_fixed::<32>("mock_attestation_seed", seed)?;
            check_sibling_root(path, &seed)?;
            Ok(seed)
        }
        (None, Some(seed)) => decode_fixed::<32>("seed", seed),
        _ => bail!("pass exactly one of --mock-config or --seed"),
    }
}

/// When the mock config sits beside the generated SNP root, require that root
/// to verify a quote from this seed, so the KMS and the collateral server
/// agree. The PEM bytes differ per process (rcgen re-signs the certificate
/// with a fresh validity window and nonce); only the keys derive from the
/// seed, so compare by verification, not by bytes.
fn check_sibling_root(mock_config: &Path, seed: &[u8; 32]) -> Result<()> {
    let Some(dir) = mock_config.parent() else {
        return Ok(());
    };
    let root = dir.join("sev-snp-root-ca.pem");
    let Ok(root_pem) = std::fs::read(&root) else {
        return Ok(());
    };
    let probe = SimTsm::from_seed(*seed)?.quote([0x5e; 64], [0u8; 48])?;
    sev_snp_qvl::QuoteVerifier::new(root_pem.clone(), root_pem.clone(), root_pem)
        .verify(&probe.report, &probe.cert_chain, &[0x5e; 64])
        .with_context(|| format!("seed does not match the root in {}", root.display()))?;
    Ok(())
}

fn decode_fixed<const N: usize>(name: &str, value: &str) -> Result<[u8; N]> {
    let bytes = hex::decode(value.trim()).with_context(|| format!("{name} is not hex"))?;
    let len = bytes.len();
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("{name} must be {N} bytes, got {len}"))
}

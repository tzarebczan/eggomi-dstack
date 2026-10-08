// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Pause and resume over a VM's QMP socket (`qmp_socket = true`): QEMU's
//! `stop` and `cont`. The guest's RAM stays committed and the VM stays on
//! this host; nothing is saved or migrated, which is all an SEV-SNP guest
//! allows (no snapshot, no migration, no balloon).

use std::path::Path;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

/// A QMP exchange never waits longer than this.
const QMP_TIMEOUT: Duration = Duration::from_secs(10);

/// What QEMU says the VM is doing (`query-status`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RunState {
    pub running: bool,
    pub status: String,
}

/// Runs `command` on the QMP socket and returns its `return` value.
pub(crate) async fn execute(socket: &Path, command: &str) -> Result<Value> {
    tokio::time::timeout(QMP_TIMEOUT, execute_inner(socket, command))
        .await
        .with_context(|| format!("QMP {command}: no answer in {QMP_TIMEOUT:?}"))?
}

async fn execute_inner(socket: &Path, command: &str) -> Result<Value> {
    let stream = UnixStream::connect(socket)
        .await
        .with_context(|| format!("QMP socket {} (is qmp_socket on?)", socket.display()))?;
    let (read, mut write) = stream.into_split();
    let mut lines = BufReader::new(read).lines();
    let greeting = next_message(&mut lines).await?;
    if greeting.get("QMP").is_none() {
        bail!("QMP: no greeting");
    }
    for request in ["qmp_capabilities", command] {
        let mut line = serde_json::to_vec(&json!({ "execute": request }))?;
        line.push(b'\n');
        write.write_all(&line).await?;
        // Events (STOP, RESUME, ...) may come before the answer.
        loop {
            let message = next_message(&mut lines).await?;
            if let Some(error) = message.get("error") {
                bail!(
                    "QMP {request}: {}",
                    error["desc"].as_str().unwrap_or("error")
                );
            }
            if let Some(value) = message.get("return") {
                if request == command {
                    return Ok(value.clone());
                }
                break;
            }
        }
    }
    bail!("QMP {command}: no answer")
}

async fn next_message(
    lines: &mut tokio::io::Lines<BufReader<tokio::net::unix::OwnedReadHalf>>,
) -> Result<Value> {
    let line = lines.next_line().await?.context("QMP socket closed")?;
    serde_json::from_str(&line).context("QMP: not JSON")
}

pub(crate) async fn query_status(socket: &Path) -> Result<RunState> {
    let value = execute(socket, "query-status").await?;
    Ok(RunState {
        running: value["running"].as_bool().unwrap_or(false),
        status: value["status"].as_str().unwrap_or("").to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::UnixListener;

    /// A QEMU stand-in: a greeting, an event before each answer, and the
    /// commands it was sent.
    async fn fake_qemu(socket: &Path, answers: Vec<Value>) -> tokio::task::JoinHandle<Vec<String>> {
        let listener = UnixListener::bind(socket).unwrap();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (read, mut write) = stream.into_split();
            let mut lines = BufReader::new(read).lines();
            write
                .write_all(b"{\"QMP\":{\"version\":{},\"capabilities\":[]}}\n")
                .await
                .unwrap();
            let mut seen = Vec::new();
            for answer in answers {
                let Some(line) = lines.next_line().await.unwrap() else {
                    break;
                };
                let request: Value = serde_json::from_str(&line).unwrap();
                seen.push(request["execute"].as_str().unwrap().to_string());
                write
                    .write_all(b"{\"event\":\"STOP\",\"timestamp\":{}}\n")
                    .await
                    .unwrap();
                write
                    .write_all(format!("{answer}\n").as_bytes())
                    .await
                    .unwrap();
            }
            seen
        })
    }

    #[tokio::test]
    async fn sends_capabilities_then_the_command_and_skips_events() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("qmp.sock");
        let qemu = fake_qemu(
            &socket,
            vec![
                json!({"return": {}}),
                json!({"return": {"running": false, "status": "paused"}}),
            ],
        )
        .await;
        let state = query_status(&socket).await.unwrap();
        assert_eq!(
            state,
            RunState {
                running: false,
                status: "paused".into()
            }
        );
        assert_eq!(
            qemu.await.unwrap(),
            vec!["qmp_capabilities", "query-status"]
        );
    }

    #[tokio::test]
    async fn a_qmp_error_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("qmp.sock");
        let _qemu = fake_qemu(
            &socket,
            vec![
                json!({"return": {}}),
                json!({"error": {"class": "GenericError", "desc": "nope"}}),
            ],
        )
        .await;
        let error = execute(&socket, "cont").await.unwrap_err();
        assert!(format!("{error:#}").contains("QMP cont: nope"), "{error:#}");
    }

    #[tokio::test]
    async fn no_socket_says_qmp_is_off() {
        let dir = tempfile::tempdir().unwrap();
        let error = execute(&dir.path().join("qmp.sock"), "stop")
            .await
            .unwrap_err();
        assert!(
            format!("{error:#}").contains("is qmp_socket on?"),
            "{error:#}"
        );
    }
}

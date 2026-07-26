use std::{
    os::unix::fs::{MetadataExt, PermissionsExt},
    time::Duration,
};

use anyhow::{Context, Result};
use serde::Deserialize;
use tokio::process::Command;

use crate::config::RiverConfig;

const ACTION_TIMEOUT: Duration = Duration::from_secs(30);
const BAN_TIMEOUT: Duration = Duration::from_secs(70);
const MAX_OUTPUT_BYTES: usize = 16 * 1024;

#[derive(Debug, Deserialize)]
struct ActionResponse {
    status: String,
    action: String,
}

#[derive(Debug, Deserialize)]
struct ContractKeyResponse {
    room_owner_key: String,
    contract_key: String,
}

#[derive(Debug, Deserialize)]
struct BanResponse {
    success: bool,
    banned_member_id: String,
}

pub async fn send_fixed_reply(
    config: &RiverConfig,
    room_owner: &str,
    message_id: &str,
    text: &'static str,
) -> Result<()> {
    validate_executable(config.riverctl_path.as_path())?;
    let mut command = Command::new(&config.riverctl_path);
    command
        .env_clear()
        .env("RIVERCTL_NO_VERSION_CHECK", "1")
        .arg("--no-version-check")
        .arg("--node-url")
        .arg(&config.node_url)
        .arg("--config-dir")
        .arg(&config.config_dir)
        .arg("--format")
        .arg("json")
        .arg("message")
        .arg("reply")
        .arg(room_owner)
        // River message IDs are signed i64 values. `--` prevents a negative
        // ID from being parsed as a command-line option by older riverctl
        // builds, even after riverctl itself gains allow_hyphen_values.
        .arg("--")
        .arg(message_id)
        .arg(text)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    let output = tokio::time::timeout(ACTION_TIMEOUT, command.output())
        .await
        .context("River reply timed out and was not retried")??;
    anyhow::ensure!(
        output.stdout.len() <= MAX_OUTPUT_BYTES,
        "River reply output is oversized"
    );
    anyhow::ensure!(
        output.stderr.len() <= MAX_OUTPUT_BYTES,
        "River reply error is oversized"
    );
    anyhow::ensure!(
        output.status.success(),
        "River reply failed with status {}; stderr={:?}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    let response: ActionResponse =
        serde_json::from_slice(&output.stdout).context("invalid River reply response")?;
    anyhow::ensure!(
        response.status == "success" && response.action == "reply",
        "unexpected River reply response"
    );
    Ok(())
}

/// Execute a leaf-only ban after verifying the installed riverctl derives the
/// pinned production contract. Riverctl repeats all membership predicates on
/// the fresh state it fetches immediately before signing the ban.
pub async fn ban_member_safely(
    config: &RiverConfig,
    room_owner: &str,
    member_id: &str,
) -> Result<String> {
    validate_executable(config.riverctl_path.as_path())?;
    validate_secret_file(config.ban_signing_key_file.as_path())?;

    let mut key_command = base_command(config);
    key_command
        .arg("debug")
        .arg("contract-key")
        .arg(room_owner)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    let key_output = tokio::time::timeout(ACTION_TIMEOUT, key_command.output())
        .await
        .context("River contract-key preflight timed out")??;
    validate_output(&key_output, "River contract-key preflight")?;
    let derived: ContractKeyResponse = serde_json::from_slice(&key_output.stdout)
        .context("invalid River contract-key response")?;
    anyhow::ensure!(
        derived.room_owner_key == room_owner
            && derived.contract_key == config.expected_contract_key,
        "River contract-key preflight mismatch"
    );

    let mut command = base_command(config);
    command
        .arg("--signing-key-file")
        .arg(&config.ban_signing_key_file)
        .arg("member")
        .arg("ban")
        .arg(room_owner)
        .arg(member_id)
        .arg("--require-exact-member-id")
        .arg("--require-no-descendants")
        .arg("--require-not-deputy")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    let output = tokio::time::timeout(BAN_TIMEOUT, command.output())
        .await
        .context("River ban timed out and was not retried")??;
    validate_output(&output, "River ban")?;
    let response: BanResponse =
        serde_json::from_slice(&output.stdout).context("invalid River ban response")?;
    anyhow::ensure!(
        response.success && response.banned_member_id == member_id,
        "unexpected River ban response"
    );
    String::from_utf8(output.stdout).context("River ban response is not UTF-8")
}

fn base_command(config: &RiverConfig) -> Command {
    let mut command = Command::new(&config.riverctl_path);
    command
        .env_clear()
        .env("RIVERCTL_NO_VERSION_CHECK", "1")
        .arg("--no-version-check")
        .arg("--node-url")
        .arg(&config.node_url)
        .arg("--config-dir")
        .arg(&config.config_dir)
        .arg("--format")
        .arg("json");
    command
}

fn validate_output(output: &std::process::Output, operation: &str) -> Result<()> {
    anyhow::ensure!(
        output.stdout.len() <= MAX_OUTPUT_BYTES,
        "{operation} output is oversized"
    );
    anyhow::ensure!(
        output.stderr.len() <= MAX_OUTPUT_BYTES,
        "{operation} error is oversized"
    );
    anyhow::ensure!(
        output.status.success(),
        "{operation} failed with status {}; stderr={:?}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

fn validate_executable(path: &std::path::Path) -> Result<()> {
    anyhow::ensure!(path.is_absolute(), "riverctl path is not absolute");
    let metadata = std::fs::metadata(path).context("cannot stat riverctl")?;
    anyhow::ensure!(metadata.is_file(), "riverctl path is not a file");
    anyhow::ensure!(metadata.uid() == 0, "riverctl must be owned by root");
    anyhow::ensure!(
        metadata.permissions().mode() & 0o022 == 0,
        "riverctl must not be group/world writable"
    );
    Ok(())
}

fn validate_secret_file(path: &std::path::Path) -> Result<()> {
    anyhow::ensure!(
        path.starts_with("/run/credentials/"),
        "ban signing key is outside systemd credentials"
    );
    let metadata = std::fs::metadata(path).context("cannot stat ban signing credential")?;
    anyhow::ensure!(metadata.is_file(), "ban signing credential is not a file");
    anyhow::ensure!(
        metadata.uid() == 0,
        "ban signing credential must be owned by root"
    );
    anyhow::ensure!(
        metadata.permissions().mode() & 0o007 == 0 && metadata.permissions().mode() & 0o022 == 0,
        "ban signing credential must not be world-readable or writable"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_has_closed_success_shape() {
        let response: ActionResponse =
            serde_json::from_slice(br#"{"status":"success","action":"reply"}"#).unwrap();
        assert_eq!(response.status, "success");
        assert_eq!(response.action, "reply");
    }
}

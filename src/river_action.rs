use std::{
    os::unix::fs::{MetadataExt, PermissionsExt},
    time::Duration,
};

use anyhow::{Context, Result};
use serde::Deserialize;
use tokio::process::Command;

use crate::config::RiverConfig;

const ACTION_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_OUTPUT_BYTES: usize = 16 * 1024;

#[derive(Debug, Deserialize)]
struct ActionResponse {
    status: String,
    action: String,
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
        "River reply failed with status {}",
        output.status
    );
    let response: ActionResponse =
        serde_json::from_slice(&output.stdout).context("invalid River reply response")?;
    anyhow::ensure!(
        response.status == "success" && response.action == "reply",
        "unexpected River reply response"
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

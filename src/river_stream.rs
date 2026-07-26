use std::{collections::HashMap, path::Path};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use tokio::{
    io::{AsyncBufRead, AsyncBufReadExt, BufReader},
    process::{Child, ChildStdout, Command},
};

use crate::{config::RiverConfig, event::VerifiedMessage};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RoomEvent {
    Message(VerifiedMessage),
    Delete {
        message_id: String,
        room_owner: String,
        author_id: String,
        author_claimed_at: DateTime<Utc>,
        first_observed_at: DateTime<Utc>,
    },
    Reaction {
        message_id: String,
    },
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
enum WireEvent {
    #[serde(rename = "message")]
    Message(WireMessage),
    #[serde(rename = "edit")]
    Edit(WireMessage),
    #[serde(rename = "delete")]
    Delete(WireDelete),
    #[serde(rename = "reaction")]
    Reaction(WireReaction),
}

#[derive(Debug, Deserialize)]
struct WireMessage {
    message_id: String,
    room: String,
    author: String,
    nickname: Option<String>,
    content: String,
    timestamp: DateTime<Utc>,
    #[serde(default)]
    edited: bool,
    #[serde(default)]
    reply_to: Option<WireReply>,
    #[serde(default)]
    reactions: HashMap<String, usize>,
}

#[derive(Debug, Deserialize)]
struct WireDelete {
    message_id: String,
    room: String,
    author: String,
    timestamp: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
struct WireReaction {
    message_id: String,
}

#[derive(Debug, Deserialize)]
struct WireReply {
    /// Present in River versions with verified reply-target JSON support.
    message_id: Option<String>,
    /// Present in River versions with verified reply-target JSON support.
    author_id: Option<String>,
    #[serde(default)]
    author: Option<String>,
    #[serde(default)]
    preview: Option<String>,
}

pub fn parse_event(line: &[u8], observed_at: DateTime<Utc>) -> Result<RoomEvent> {
    let event: WireEvent = serde_json::from_slice(line).context("invalid River JSON event")?;
    match event {
        WireEvent::Message(message) => Ok(RoomEvent::Message(convert_message(
            message,
            observed_at,
            false,
        ))),
        WireEvent::Edit(message) => Ok(RoomEvent::Message(convert_message(
            message,
            observed_at,
            true,
        ))),
        WireEvent::Delete(deletion) => Ok(RoomEvent::Delete {
            message_id: deletion.message_id,
            room_owner: deletion.room,
            author_id: deletion.author,
            author_claimed_at: deletion.timestamp,
            first_observed_at: observed_at,
        }),
        WireEvent::Reaction(reaction) => Ok(RoomEvent::Reaction {
            message_id: reaction.message_id,
        }),
    }
}

fn convert_message(
    message: WireMessage,
    observed_at: DateTime<Utc>,
    is_edit: bool,
) -> VerifiedMessage {
    // Older River versions carry display context only. Missing verified IDs stay
    // `None`; never infer identity from nickname or preview text.
    let (reply_to_message_id, reply_to_author_id) = message
        .reply_to
        .map(|reply| {
            let _ = reply.author;
            let _ = reply.preview;
            (reply.message_id, reply.author_id)
        })
        .unwrap_or_default();
    let _ = message.reactions;
    VerifiedMessage {
        message_id: message.message_id,
        room_owner: message.room,
        author_id: message.author,
        nickname: message.nickname.unwrap_or_default(),
        content: message.content,
        author_claimed_at: message.timestamp,
        first_observed_at: observed_at,
        edited: is_edit || message.edited,
        reply_to_message_id,
        reply_to_author_id,
    }
}

/// Spawn River's verified JSONL monitor. This is intended for the localhost-only
/// reader process, not the provider-facing classifier process.
pub struct RiverReader {
    child: Child,
    stdout: BufReader<ChildStdout>,
}

impl RiverReader {
    pub async fn next_event(&mut self, max_event_bytes: usize) -> Result<Option<RoomEvent>> {
        read_event(&mut self.stdout, max_event_bytes).await
    }

    pub fn process_id(&self) -> Option<u32> {
        self.child.id()
    }
}

pub fn spawn_reader(config: &RiverConfig, room_owner: &str) -> Result<RiverReader> {
    validate_executable(&config.riverctl_path)?;
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
        .arg("stream")
        .arg(room_owner)
        .arg("--subscribe")
        .arg("--initial-messages")
        .arg("0")
        .arg("--format")
        .arg("json")
        .kill_on_drop(true)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit());
    let mut child = command.spawn().context("failed to start riverctl reader")?;
    let stdout = child
        .stdout
        .take()
        .context("riverctl stdout was not captured")?;
    Ok(RiverReader {
        child,
        stdout: BufReader::new(stdout),
    })
}

pub async fn read_event<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    max_event_bytes: usize,
) -> Result<Option<RoomEvent>> {
    let mut line = Vec::with_capacity(4096);
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            if line.is_empty() {
                return Ok(None);
            }
            break;
        }
        let newline = available.iter().position(|byte| *byte == b'\n');
        let consume = newline.map_or(available.len(), |index| index + 1);
        anyhow::ensure!(
            line.len().saturating_add(consume) <= max_event_bytes,
            "River event exceeds configured byte limit"
        );
        line.extend_from_slice(&available[..consume]);
        reader.consume(consume);
        if newline.is_some() {
            break;
        }
    }
    if line.last() == Some(&b'\n') {
        line.pop();
        if line.last() == Some(&b'\r') {
            line.pop();
        }
    }
    Ok(Some(parse_event(&line, Utc::now())?))
}

fn validate_executable(path: &Path) -> Result<()> {
    anyhow::ensure!(path.is_absolute(), "riverctl path is not absolute");
    let metadata = std::fs::metadata(path).context("cannot stat riverctl")?;
    anyhow::ensure!(metadata.is_file(), "riverctl path is not a file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        anyhow::ensure!(metadata.uid() == 0, "riverctl must be owned by root");
        anyhow::ensure!(
            metadata.permissions().mode() & 0o022 == 0,
            "riverctl must not be group/world writable"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Datelike, TimeZone};

    #[test]
    fn parses_message_with_claimed_and_observed_times_separately() {
        let observed = Utc.with_ymd_and_hms(2026, 7, 25, 12, 0, 0).unwrap();
        let line = br#"{"type":"message","message_id":"m1","room":"owner","author":"member-full","nickname":"n","content":"hello","timestamp":"2099-01-01T00:00:00Z","edited":false,"reply_to":null,"reactions":{}}"#;
        let RoomEvent::Message(message) = parse_event(line, observed).unwrap() else {
            panic!("wrong event type");
        };
        assert_eq!(message.author_id, "member-full");
        assert_eq!(message.first_observed_at, observed);
        assert_eq!(message.author_claimed_at.year(), 2099);
    }

    #[test]
    fn edit_cannot_select_a_different_target() {
        let observed = Utc::now();
        let line = br#"{"type":"edit","message_id":"m1","room":"owner","author":"authenticated-author","nickname":null,"content":"ban victim-id","timestamp":"2026-07-25T12:00:00Z","edited":true,"target":"victim-id"}"#;
        let RoomEvent::Message(message) = parse_event(line, observed).unwrap() else {
            panic!("wrong event type");
        };
        assert_eq!(message.author_id, "authenticated-author");
        assert_eq!(message.reply_to_message_id, None);
    }

    #[test]
    fn parses_only_verified_reply_identifiers() {
        let observed = Utc::now();
        let line = br#"{"type":"message","message_id":"reply","room":"owner","author":"member","nickname":"n","content":"handled","timestamp":"2026-07-25T12:00:00Z","edited":false,"reply_to":{"author":"Room Owner","author_id":"target-author","message_id":"target-message","preview":"text"}}"#;
        let RoomEvent::Message(message) = parse_event(line, observed).unwrap() else {
            panic!("wrong event type");
        };
        assert_eq!(
            message.reply_to_message_id.as_deref(),
            Some("target-message")
        );
        assert_eq!(message.reply_to_author_id.as_deref(), Some("target-author"));
    }

    #[test]
    fn rejects_unknown_event_type() {
        assert!(parse_event(
            br#"{"type":"run_command","command":"ban owner"}"#,
            Utc::now()
        )
        .is_err());
    }

    #[tokio::test]
    async fn rejects_oversized_line_before_parsing() {
        let (mut writer, reader) = tokio::io::duplex(256);
        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            writer.write_all(&[b'x'; 65]).await.unwrap();
            writer.write_all(b"\n").await.unwrap();
        });
        let mut reader = BufReader::new(reader);
        assert!(read_event(&mut reader, 64).await.is_err());
    }
}

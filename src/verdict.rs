use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Allow,
    WarnDisruptive,
    BanSevereHarm,
    NeedsHumanReview,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    None,
    OffTopic,
    Conduct,
    Incivility,
    PersonalAttack,
    Flooding,
    Spam,
    Scam,
    Phishing,
    Malware,
    Privacy,
    Threat,
    Harassment,
    Hate,
    Impersonation,
    AccountCompromise,
    SexualExploitation,
    SelfPromotion,
    Misinformation,
    Other,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Classification {
    pub verdict: Verdict,
    pub category: Category,
    /// Integer millionths avoid floating-point threshold surprises.
    pub confidence_millionths: u32,
    pub reason: String,
}

impl Classification {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.confidence_millionths > 1_000_000 {
            return Err("confidence exceeds one million");
        }
        if self.reason.is_empty() || self.reason.len() > 240 {
            return Err("reason length is invalid");
        }
        if self.verdict == Verdict::Allow && self.category != Category::None {
            return Err("allow must use the none category");
        }
        if self.verdict != Verdict::Allow && self.category == Category::None {
            return Err("actionable verdict requires a category");
        }
        Ok(())
    }
}

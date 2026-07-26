use serde::{Deserialize, Serialize};

use crate::{
    config::PolicyConfig,
    membership::TrustTier,
    verdict::{Category, Classification, Verdict},
};

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PolicyAction {
    None,
    RecordDisruption,
    WarnAsOwner,
    BanAsModerator,
    BanAsOwnerPolicyEscalation,
    BanAsOwnerEmergency,
    HumanReview,
}

#[derive(Clone, Debug)]
pub struct PolicyInput<'a> {
    pub classification: &'a Classification,
    pub verifier: Option<&'a Classification>,
    pub trust_tier: TrustTier,
    pub prior_category_observations: u32,
    pub has_active_warning: bool,
    pub descendant_count: usize,
}

pub fn decide(input: &PolicyInput<'_>, policy: &PolicyConfig) -> PolicyAction {
    if input.classification.validate().is_err() {
        return PolicyAction::HumanReview;
    }

    match input.classification.verdict {
        Verdict::Allow => PolicyAction::None,
        Verdict::NeedsHumanReview => PolicyAction::HumanReview,
        Verdict::WarnDisruptive => decide_disruption(input, policy),
        Verdict::BanSevereHarm => decide_severe(input, policy),
    }
}

fn decide_disruption(input: &PolicyInput<'_>, policy: &PolicyConfig) -> PolicyAction {
    if input.classification.confidence_millionths < policy.warning_confidence_millionths {
        return PolicyAction::None;
    }
    let is_off_topic = input.classification.category == Category::OffTopic;
    if input.trust_tier == TrustTier::Deputy && is_off_topic {
        return PolicyAction::RecordDisruption;
    }
    if input.has_active_warning {
        return if input.descendant_count <= policy.max_ban_descendants {
            if input.trust_tier == TrustTier::Deputy {
                PolicyAction::BanAsOwnerPolicyEscalation
            } else {
                PolicyAction::BanAsModerator
            }
        } else {
            PolicyAction::HumanReview
        };
    }
    match input.trust_tier {
        TrustTier::Probationary | TrustTier::Regular => PolicyAction::WarnAsOwner,
        TrustTier::Established if !is_off_topic || input.prior_category_observations >= 2 => {
            PolicyAction::WarnAsOwner
        }
        TrustTier::Established => PolicyAction::RecordDisruption,
        TrustTier::Deputy => PolicyAction::WarnAsOwner,
    }
}

fn decide_severe(input: &PolicyInput<'_>, policy: &PolicyConfig) -> PolicyAction {
    let Some(verifier) = input.verifier else {
        return PolicyAction::HumanReview;
    };
    if verifier.validate().is_err()
        || verifier.verdict != Verdict::BanSevereHarm
        || verifier.category != input.classification.category
    {
        return PolicyAction::HumanReview;
    }
    if input.descendant_count > policy.max_ban_descendants {
        return PolicyAction::HumanReview;
    }

    let required_confidence = if input.trust_tier == TrustTier::Deputy {
        policy.deputy_ban_confidence_millionths
    } else {
        policy.ban_confidence_millionths
    };
    if input.classification.confidence_millionths < required_confidence
        || verifier.confidence_millionths < required_confidence
    {
        return PolicyAction::HumanReview;
    }

    if input.trust_tier == TrustTier::Deputy {
        if deputy_emergency_category(input.classification.category) {
            PolicyAction::BanAsOwnerEmergency
        } else {
            PolicyAction::HumanReview
        }
    } else {
        PolicyAction::BanAsModerator
    }
}

fn deputy_emergency_category(category: Category) -> bool {
    matches!(
        category,
        Category::Flooding
            | Category::Spam
            | Category::Scam
            | Category::Phishing
            | Category::Malware
            | Category::Privacy
            | Category::Threat
            | Category::Harassment
            | Category::Hate
            | Category::Impersonation
            | Category::AccountCompromise
            | Category::SexualExploitation
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> PolicyConfig {
        PolicyConfig {
            warning_window_hours: 24,
            max_ban_descendants: 0,
            ban_confidence_millionths: 980_000,
            deputy_ban_confidence_millionths: 995_000,
            warning_confidence_millionths: 900_000,
            regular_after_days: 7,
            regular_after_messages: 10,
            established_after_days: 30,
            established_after_active_days: 10,
            established_after_messages: 50,
        }
    }

    fn classification(verdict: Verdict, category: Category, confidence: u32) -> Classification {
        Classification {
            verdict,
            category,
            confidence_millionths: confidence,
            reason: "test evidence".into(),
        }
    }

    #[test]
    fn deputy_is_not_nagged_for_off_topic() {
        let c = classification(Verdict::WarnDisruptive, Category::OffTopic, 999_000);
        let input = PolicyInput {
            classification: &c,
            verifier: None,
            trust_tier: TrustTier::Deputy,
            prior_category_observations: 20,
            has_active_warning: true,
            descendant_count: 0,
        };
        assert_eq!(decide(&input, &policy()), PolicyAction::RecordDisruption);
    }

    #[test]
    fn obvious_verified_deputy_compromise_uses_owner_emergency_path() {
        let c = classification(Verdict::BanSevereHarm, Category::AccountCompromise, 999_000);
        let v = c.clone();
        let input = PolicyInput {
            classification: &c,
            verifier: Some(&v),
            trust_tier: TrustTier::Deputy,
            prior_category_observations: 0,
            has_active_warning: false,
            descendant_count: 0,
        };
        assert_eq!(decide(&input, &policy()), PolicyAction::BanAsOwnerEmergency);
    }

    #[test]
    fn deputy_emergency_requires_high_confidence_agreement_and_no_collateral() {
        let c = classification(Verdict::BanSevereHarm, Category::Spam, 994_999);
        let v = classification(Verdict::BanSevereHarm, Category::Spam, 999_000);
        let mut input = PolicyInput {
            classification: &c,
            verifier: Some(&v),
            trust_tier: TrustTier::Deputy,
            prior_category_observations: 0,
            has_active_warning: false,
            descendant_count: 0,
        };
        assert_eq!(decide(&input, &policy()), PolicyAction::HumanReview);
        let high = classification(Verdict::BanSevereHarm, Category::Spam, 999_000);
        input.classification = &high;
        input.descendant_count = 1;
        assert_eq!(decide(&input, &policy()), PolicyAction::HumanReview);
    }

    #[test]
    fn established_member_needs_sustained_off_topic_pattern_before_warning() {
        let c = classification(Verdict::WarnDisruptive, Category::OffTopic, 999_000);
        let mut input = PolicyInput {
            classification: &c,
            verifier: None,
            trust_tier: TrustTier::Established,
            prior_category_observations: 1,
            has_active_warning: false,
            descendant_count: 0,
        };
        assert_eq!(decide(&input, &policy()), PolicyAction::RecordDisruption);
        input.prior_category_observations = 2;
        assert_eq!(decide(&input, &policy()), PolicyAction::WarnAsOwner);
    }

    #[test]
    fn established_members_and_deputies_are_warned_for_personal_attacks() {
        let c = classification(Verdict::WarnDisruptive, Category::PersonalAttack, 999_000);
        for tier in [TrustTier::Established, TrustTier::Deputy] {
            let input = PolicyInput {
                classification: &c,
                verifier: None,
                trust_tier: tier,
                prior_category_observations: 0,
                has_active_warning: false,
                descendant_count: 0,
            };
            assert_eq!(decide(&input, &policy()), PolicyAction::WarnAsOwner);
        }
    }

    #[test]
    fn deputy_repeating_warned_personal_attacks_uses_owner_signer() {
        let c = classification(Verdict::WarnDisruptive, Category::PersonalAttack, 999_000);
        let input = PolicyInput {
            classification: &c,
            verifier: None,
            trust_tier: TrustTier::Deputy,
            prior_category_observations: 1,
            has_active_warning: true,
            descendant_count: 0,
        };
        assert_eq!(
            decide(&input, &policy()),
            PolicyAction::BanAsOwnerPolicyEscalation
        );
    }

    #[test]
    fn model_cannot_ban_without_independent_verifier() {
        let c = classification(Verdict::BanSevereHarm, Category::Spam, 999_000);
        let input = PolicyInput {
            classification: &c,
            verifier: None,
            trust_tier: TrustTier::Probationary,
            prior_category_observations: 0,
            has_active_warning: false,
            descendant_count: 0,
        };
        assert_eq!(decide(&input, &policy()), PolicyAction::HumanReview);
    }
}

use crate::verdict::Category;

pub const CONDUCT_NUDGE: &str = "Easy. Attack the idea, not the person.";
/// Off-topic covers every unrelated tangent, so this text must not name one.
/// It previously read "Take the politics elsewhere", which was delivered to a
/// chess-engine discussion on 2026-07-30 and made a misfire look absurd rather
/// than merely wrong. A reply that names the wrong offence is worse than a
/// generic one: it is unarguable evidence to every reader that the moderator did
/// not understand the message.
pub const TOPIC_NUDGE: &str = "Let's keep this room on topic. Back to Freenet.";

/// Shown when a message claims a timestamp far enough in the future to pin
/// itself to the bottom of the room.
///
/// River sorts and prunes by the SENDER-SUPPLIED time, so a future-dated message
/// sits last forever and is the last thing evicted while legitimate messages
/// roll off. Deleting it is the only remedy, and only its author can do that.
///
/// Deliberately non-accusatory: measured against 2523 production messages, the
/// three real cases split into one obvious abuse ("welcome from the future")
/// and two that look like ordinary broken device clocks ("hlo", "oh hi chat").
/// Nothing in the message distinguishes them, so the wording has to be correct
/// for the innocent case while still stating the consequence.
pub const FUTURE_TIMESTAMP_WARNING: &str = "Your message is dated in the future, so it sticks to the bottom of the room and never scrolls away. This is usually a device clock set wrong — worth checking yours. Please delete the message within 2 minutes, or it will be removed along with your access.";

/// Shown when a message embeds an image.
///
/// River renders message text as GFM markdown, so `![](...)` becomes a live
/// `<img>` pointing anywhere the author likes. The capability is not yet widely
/// known and is not yet bounded, so until it is, embedded images are refused
/// outright rather than judged case by case.
pub const EMBEDDED_IMAGE_WARNING: &str = "Embedded images aren't allowed in this room yet. Please delete the message within 1 minute, or it will be removed along with your access. Links are fine.";

pub fn fixed_nudge(category: Category) -> &'static str {
    if category == Category::OffTopic {
        TOPIC_NUDGE
    } else {
        CONDUCT_NUDGE
    }
}

pub fn fixed_warning(category: Category) -> &'static str {
    match category {
        Category::OffTopic => "Keep this room on topic. Keep at it and you're gone.",
        Category::Incivility | Category::PersonalAttack | Category::Conduct => {
            "Easy. Attack the idea, not the person. Next one and you're out."
        }
        Category::Flooding => "Cut the flood. Do it again and you're gone.",
        Category::SelfPromotion => "Cut the promotion. Do it again and you're gone.",
        Category::Misinformation => {
            "Back that up or drop it. Keep spreading harmful nonsense and you're gone."
        }
        Category::Hate | Category::Harassment => {
            "Knock it off. No slurs or hateful abuse. Next one and you're out."
        }
        _ => "Knock it off. Do it again and you're out.",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn warning_text_is_fixed_and_does_not_accept_model_content() {
        assert_eq!(
            fixed_warning(Category::PersonalAttack),
            "Easy. Attack the idea, not the person. Next one and you're out."
        );
        assert_eq!(CONDUCT_NUDGE, "Easy. Attack the idea, not the person.");
        assert_eq!(fixed_nudge(Category::OffTopic), TOPIC_NUDGE);
        assert_eq!(fixed_nudge(Category::Incivility), CONDUCT_NUDGE);
    }

    /// Measured against 2523 production messages, two of the three real
    /// future-dated cases looked like ordinary broken device clocks, not abuse.
    /// The wording therefore has to be correct for an innocent author: name the
    /// likely cause, say what to do, and state the consequence without accusing.
    #[test]
    fn future_timestamp_warning_is_actionable_and_not_accusatory() {
        let text = FUTURE_TIMESTAMP_WARNING.to_lowercase();
        assert!(
            text.contains("clock"),
            "must name the likely innocent cause"
        );
        assert!(text.contains("delete"), "must say what to do");
        assert!(text.contains("2 minutes"), "must state the deadline");
        for accusation in ["spam", "abuse", "attack", "deliberate", "stop"] {
            assert!(
                !text.contains(accusation),
                "must not accuse the author: {accusation:?}"
            );
        }
    }

    /// Off-topic is one category covering every unrelated tangent, so its texts
    /// must not name a particular one. "Take the politics elsewhere" went to a
    /// chess-engine discussion on 2026-07-30; naming the wrong offence turns a
    /// misfire into visible proof the moderator misread the room.
    #[test]
    fn off_topic_texts_do_not_name_a_specific_subject() {
        for text in [TOPIC_NUDGE, fixed_warning(Category::OffTopic)] {
            let lower = text.to_lowercase();
            for subject in ["politic", "religio", "sex", "crypto", "sport"] {
                assert!(
                    !lower.contains(subject),
                    "off-topic text names {subject:?}: {text:?}"
                );
            }
        }
    }
}

use crate::verdict::Category;

pub const CONDUCT_NUDGE: &str = "Easy. Attack the idea, not the person.";
/// A nudge-tier `Hate` finding is reserved for a hate-trope nickname on an
/// otherwise benign message, so `CONDUCT_NUDGE`'s "attack the idea" framing is
/// wrong here — there is no idea being attacked, there is a nickname to change.
pub const HATE_NICKNAME_NUDGE: &str =
    "Your nickname reads as a hateful reference. Please change it — repeated or ignored, it leads to removal.";
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
pub const FUTURE_TIMESTAMP_WARNING: &str = "Your message is dated in the future, so it sticks to the bottom of the room and never scrolls away. This is usually a device clock set wrong — worth checking yours. Please delete the message within 2 minutes, or you'll get one more notice before your access is removed.";

/// Second and final notice, sent if the first `FUTURE_TIMESTAMP_WARNING` goes
/// unactioned. A new member's first message in the room is routinely the one
/// that trips this (a wrong device clock, not misconduct), so this restates
/// the same likely-innocent cause and remedy rather than escalating tone --
/// the only thing that changes is that there is no third notice.
pub const FUTURE_TIMESTAMP_STERN_WARNING: &str = "Your message is still dated in the future. This is the second and final notice: if your device clock is wrong, please delete the message within 2 minutes, or your access to the room will be removed.";

/// Shown when a message embeds an image.
///
/// River renders message text as GFM markdown, so `![](...)` becomes a live
/// `<img>` pointing anywhere the author likes. The capability is not yet widely
/// known and is not yet bounded, so until it is, embedded images are refused
/// outright rather than judged case by case.
pub const EMBEDDED_IMAGE_WARNING: &str = "Embedded images aren't allowed in this room yet. Please delete the message within 1 minute, or it will be removed along with your access. Links are fine.";

/// Shown when a message contains a `?invitation=` link.
///
/// The link is not an inert code, it is a real one-time member keypair,
/// generated for exactly one person -- see the Invite Member modal's own
/// notice. Posting it publicly hands that identity to everyone reading. Each
/// claimant CAN use it -- it keeps working for all of them -- but they all
/// share the one identity, appear as the same member, and a ban on that
/// identity removes everyone who claimed it (2026-08-01: exactly this
/// happened in the room). An earlier version of this text incorrectly said
/// the link "stops working" for a second claimant, which Ian corrected: it
/// does not stop working, it gets shared, which is worse -- an innocent
/// claimant is now banned alongside a spammer with no way to tell them apart.
pub const LEAKED_INVITATION_WARNING: &str = "That link is a real, one-time invitation keypair, not just a code. Anyone who uses it CAN join with it, but everyone who does shares one identity and appears as the same member -- if that identity ever gets banned (e.g. a spammer picks it up), everyone sharing it is banned too. To invite someone to a different room, click their name in the member list here, choose Share Invite, and pick that room. Please delete this message within 5 minutes, or it will be removed along with your access.";

/// Body of the reaction notice, appended after the offender's `@` mention.
///
/// Posted as a TOP-LEVEL message rather than a reply: a reaction has no message
/// of its own, and replying to the reacted-to message would render the notice
/// under an innocent party's post. The mention is what notifies the offender.
pub const BAD_REACTION_NOTICE: &str = " that reaction isn't a standard emoji, so please remove it within 2 minutes or you'll lose access to the room. Ordinary emoji reactions are fine.";

pub fn fixed_nudge(category: Category) -> &'static str {
    match category {
        Category::OffTopic => TOPIC_NUDGE,
        Category::Hate => HATE_NICKNAME_NUDGE,
        _ => CONDUCT_NUDGE,
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

    /// A nudge-tier `Hate` finding is nickname-only (see `policy.rs`), so its
    /// text must tell the member to change their NICKNAME. `CONDUCT_NUDGE`'s
    /// "attack the idea, not the person" framing is nonsensical here -- there
    /// is no idea being attacked.
    #[test]
    fn hate_nudge_names_the_actual_remedy() {
        assert_eq!(fixed_nudge(Category::Hate), HATE_NICKNAME_NUDGE);
        let text = HATE_NICKNAME_NUDGE.to_lowercase();
        assert!(text.contains("nickname"), "must name the actual remedy");
        assert_ne!(HATE_NICKNAME_NUDGE, CONDUCT_NUDGE);
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

    /// Same bar as the first notice: an unmissed device clock, not misconduct,
    /// is still the likely cause the second time around.
    #[test]
    fn future_timestamp_stern_warning_is_actionable_and_not_accusatory() {
        let text = FUTURE_TIMESTAMP_STERN_WARNING.to_lowercase();
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

    /// The stern warning must actually read as distinct from the first, or a
    /// member re-reading the thread cannot tell whether they're on notice 1 or
    /// notice 2 -- which matters because notice 2 has no further grace after it.
    #[test]
    fn future_timestamp_stern_warning_differs_from_first_warning() {
        assert_ne!(FUTURE_TIMESTAMP_STERN_WARNING, FUTURE_TIMESTAMP_WARNING);
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

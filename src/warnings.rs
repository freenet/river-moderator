use crate::verdict::Category;

pub const CONDUCT_NUDGE: &str = "Easy. Attack the idea, not the person.";
/// Off-topic covers every unrelated tangent, so this text must not name one.
/// It previously read "Take the politics elsewhere", which was delivered to a
/// chess-engine discussion on 2026-07-30 and made a misfire look absurd rather
/// than merely wrong. A reply that names the wrong offence is worse than a
/// generic one: it is unarguable evidence to every reader that the moderator did
/// not understand the message.
pub const TOPIC_NUDGE: &str = "Let's keep this room on topic. Back to Freenet.";

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

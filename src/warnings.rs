use crate::verdict::Category;

/// What the notice is actually about.
///
/// A notice is posted as a reply, and for a join-name event the only thing
/// there to reply to is the member's "joined the room" line. Message copy
/// therefore reads as though joining was the offence and gives the member
/// nothing to act on. Name copy names the display name and says to change it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NoticeSubject {
    Message,
    DisplayName,
}

// Fixed, source-defined text. Model output can never reach these strings.
//
// Register: stern and factual. This is an automated moderator with authority in
// the room, and it should read like one — state the rule, state the consequence,
// stop. No slang, no banter, no first person, no attempt to sound like a person
// ("Easy.", "Knock it off", "you're gone"). A bot performing chumminess reads as
// either weak or sarcastic, and neither is what an enforcement notice is for.

/// First notice. States the rule; no consequence yet, because nothing has
/// escalated.
pub const CONDUCT_NUDGE: &str = "Address the argument, not the person.";
pub const TOPIC_NUDGE: &str = "Off topic. This room is for Freenet and related technical work.";

pub const NAME_TOPIC_NUDGE: &str =
    "Your display name is off topic. This room is for Freenet and related technical work. \
     Change it.";
pub const NAME_CONDUCT_NUDGE: &str = "Your display name is not appropriate here. Change it.";

pub fn fixed_nudge(category: Category, subject: NoticeSubject) -> &'static str {
    match (subject, category) {
        (NoticeSubject::DisplayName, Category::OffTopic) => NAME_TOPIC_NUDGE,
        (NoticeSubject::DisplayName, _) => NAME_CONDUCT_NUDGE,
        (NoticeSubject::Message, Category::OffTopic) => TOPIC_NUDGE,
        (NoticeSubject::Message, _) => CONDUCT_NUDGE,
    }
}

/// Formal warning. States the rule and the consequence of continuing.
pub fn fixed_warning(category: Category, subject: NoticeSubject) -> &'static str {
    if subject == NoticeSubject::DisplayName {
        return match category {
            Category::OffTopic => {
                "Your display name is off topic. This room is for Freenet and related \
                 technical work. Change it or you will be removed. Rejoining requires a new \
                 invitation, which may be unavailable for 24 hours."
            }
            _ => {
                "Your display name is not appropriate here. Change it or you will be removed. \
                 Rejoining requires a new invitation, which may be unavailable for 24 hours."
            }
        };
    }
    match category {
        Category::OffTopic => {
            "Off topic. This room is for Freenet and related technical work. \
             Continuing will result in removal. Rejoining requires a new invitation, which may be unavailable for 24 hours."
        }
        Category::Incivility | Category::PersonalAttack | Category::Conduct => {
            "Personal attacks are not permitted. Continuing will result in removal. Rejoining requires a new invitation, which may be unavailable for 24 hours."
        }
        Category::Flooding => {
            "Excessive message volume is not permitted. Continuing will result in removal. Rejoining requires a new invitation, which may be unavailable for 24 hours."
        }
        Category::SelfPromotion => {
            "Unsolicited promotion is not permitted. Continuing will result in removal. Rejoining requires a new invitation, which may be unavailable for 24 hours."
        }
        Category::Misinformation => {
            "Unsupported claims presented as fact are not permitted. \
             Continuing will result in removal. Rejoining requires a new invitation, which may be unavailable for 24 hours."
        }
        Category::Hate | Category::Harassment => {
            "Slurs and hateful abuse are not permitted. Continuing will result in removal. Rejoining requires a new invitation, which may be unavailable for 24 hours."
        }
        _ => "This conduct is not permitted. Continuing will result in removal. Rejoining requires a new invitation, which may be unavailable for 24 hours.",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn warning_text_is_fixed_and_does_not_accept_model_content() {
        assert_eq!(
            fixed_warning(Category::PersonalAttack, NoticeSubject::Message),
            "Personal attacks are not permitted. Continuing will result in removal. Rejoining requires a new invitation, which may be unavailable for 24 hours."
        );
        assert_eq!(CONDUCT_NUDGE, "Address the argument, not the person.");
        assert_eq!(
            fixed_nudge(Category::OffTopic, NoticeSubject::Message),
            TOPIC_NUDGE
        );
        assert_eq!(
            fixed_nudge(Category::Incivility, NoticeSubject::Message),
            CONDUCT_NUDGE
        );
    }

    /// The register is the point, so pin it. An automated authority states the
    /// rule and the consequence; it does not do slang, banter or first person.
    #[test]
    fn every_notice_reads_as_an_authority_not_a_person() {
        let categories = [
            Category::OffTopic,
            Category::Incivility,
            Category::PersonalAttack,
            Category::Conduct,
            Category::Flooding,
            Category::SelfPromotion,
            Category::Misinformation,
            Category::Hate,
            Category::Harassment,
            Category::Other,
        ];
        let banned = [
            "easy",
            "knock it off",
            "cut the",
            "you're gone",
            "you're out",
            "drop it",
            "back to",
            "keep at it",
            "nonsense",
            " i ",
            "we ",
            "let's",
            "please",
            "!",
        ];
        for category in categories {
            for subject in [NoticeSubject::Message, NoticeSubject::DisplayName] {
                for text in [
                    fixed_warning(category, subject),
                    fixed_nudge(category, subject),
                ] {
                    let lower = format!(" {} ", text.to_lowercase());
                    for phrase in banned {
                        assert!(
                            !lower.contains(phrase),
                            "{text:?} contains informal or first-person phrasing {phrase:?}"
                        );
                    }
                    assert!(
                        text.ends_with('.'),
                        "{text:?} should be a plain declarative statement"
                    );
                }
            }
        }
    }

    /// Every warning must state the consequence; every nudge must not, since a
    /// nudge is a first notice and nothing has escalated yet.
    #[test]
    fn warnings_state_the_consequence_and_nudges_do_not() {
        for category in [
            Category::OffTopic,
            Category::PersonalAttack,
            Category::Flooding,
            Category::Hate,
            Category::Other,
        ] {
            assert!(
                fixed_warning(category, NoticeSubject::Message).contains("result in removal"),
                "warning for {category:?} must state the consequence"
            );
            assert!(
                !fixed_nudge(category, NoticeSubject::Message).contains("removal"),
                "a first notice should not threaten removal"
            );
        }
    }
}

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
// TONE LADDER. Severity sets the register, and the register is what decides
// whether a public notice educates the room or humiliates the member. These are
// posted in front of everyone, which is deliberate -- visible enforcement is how
// a room learns its norms and how it feels tended rather than arbitrary. The
// cost of that visibility is paid in framing, not venue:
//
//   Nudge (first, minor)  -- states the NORM, impersonally. No "you", no
//                            characterisation, no consequence. A sign on a
//                            wall. Anyone can comply without losing face,
//                            which is what makes compliance likely.
//   Warning (repeat)      -- names the artifact ("Your display name") and the
//                            consequence. Personal now, because they have had
//                            their chance, but still about the thing, not them.
//   Severe               -- never reaches here. Hate and threats go to the ban
//                            path; the room sees the removal, which is the
//                            only statement needed.
//
// The invariant across all of them: describe the artifact, never the person.
// "Display names must be safe for work" and "you are being offensive" carry the
// same information and cost completely different amounts of goodwill.
//
// Register: stern and factual. This is an automated moderator with authority in
// the room, and it should read like one — state the rule, state the consequence,
// stop. No slang, no banter, no first person, no attempt to sound like a person
// ("Easy.", "Knock it off", "you're gone"). A bot performing chumminess reads as
// either weak or sarcastic, and neither is what an enforcement notice is for.

/// First notice. States the rule; no consequence yet, because nothing has
/// escalated.
pub const CONDUCT_NUDGE: &str = "This room addresses arguments, not people.";
pub const TOPIC_NUDGE: &str = "This room is for Freenet and related technical work.";

pub const NAME_TOPIC_NUDGE: &str = "Display names must be safe for work: no profanity, no slogans.";
pub const NAME_CONDUCT_NUDGE: &str = "Display names must be safe for work: no profanity, no slurs.";

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
                "Display names must be safe for work: no profanity, no slogans. Change it or \
                 you will be removed. Rejoining requires a new invitation, which may be \
                 unavailable for 24 hours."
            }
            _ => {
                "Display names must be safe for work: no profanity, no slurs. Change it or \
                 you will be removed. Rejoining requires a new invitation, which may be \
                 unavailable for 24 hours."
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
        assert_eq!(CONDUCT_NUDGE, "This room addresses arguments, not people.");
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

    /// A nudge must not address the member at all. Second person turns a norm
    /// posted in front of the room into a public verdict on a person, which is
    /// the difference between educating the room and humiliating someone.
    #[test]
    fn nudges_state_a_norm_without_addressing_the_member() {
        for category in [
            Category::OffTopic,
            Category::Incivility,
            Category::PersonalAttack,
            Category::Flooding,
            Category::Hate,
            Category::Other,
        ] {
            for subject in [NoticeSubject::Message, NoticeSubject::DisplayName] {
                let text = fixed_nudge(category, subject).to_lowercase();
                for second_person in ["you ", "your ", "you'", "yours"] {
                    assert!(
                        !text.contains(second_person),
                        "a first notice must not address the member: {text:?}"
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

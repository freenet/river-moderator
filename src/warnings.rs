use crate::verdict::Category;

pub const CONDUCT_NUDGE: &str = "Please keep criticism constructive and specific—describe what should improve without dismissive labels or personal remarks.";
pub const TOPIC_NUDGE: &str = "Please move unrelated polarizing discussion elsewhere. Broadly technical discussion and brief casual conversation are welcome here.";

pub fn fixed_nudge(category: Category) -> &'static str {
    if category == Category::OffTopic {
        TOPIC_NUDGE
    } else {
        CONDUCT_NUDGE
    }
}

pub fn fixed_warning(category: Category) -> &'static str {
    match category {
        Category::OffTopic => {
            "Moderation warning: Please move unrelated polarizing or persistently derailing discussion elsewhere. Broadly technical discussion is welcome. Continued derailment will result in a ban."
        }
        Category::Incivility | Category::PersonalAttack | Category::Conduct => {
            "Moderation warning: Disagreement is welcome, but rudeness and personal attacks are not. Critique ideas, not people. Continued conduct will result in a ban."
        }
        Category::Flooding => {
            "Moderation warning: Please slow down and avoid flooding the room. Continued flooding will result in a ban."
        }
        Category::SelfPromotion => {
            "Moderation warning: Please stop repetitive or unrelated promotion. Continued promotion will result in a ban."
        }
        Category::Misinformation => {
            "Moderation warning: Please stop repeatedly presenting harmful or demonstrably false claims as fact. Continued conduct will result in a ban."
        }
        _ => {
            "Moderation warning: This behavior is disruptive to the room. Continued conduct will result in a ban."
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn warning_text_is_fixed_and_does_not_accept_model_content() {
        assert_eq!(
            fixed_warning(Category::PersonalAttack),
            "Moderation warning: Disagreement is welcome, but rudeness and personal attacks are not. Critique ideas, not people. Continued conduct will result in a ban."
        );
        assert_eq!(
            CONDUCT_NUDGE,
            "Please keep criticism constructive and specific—describe what should improve without dismissive labels or personal remarks."
        );
        assert_eq!(fixed_nudge(Category::OffTopic), TOPIC_NUDGE);
        assert_eq!(fixed_nudge(Category::Incivility), CONDUCT_NUDGE);
    }
}

use crate::verdict::Category;

pub const CONDUCT_NUDGE: &str = "Please keep criticism constructive and specific—describe what should improve without dismissive labels or personal remarks.";

pub fn fixed_warning(category: Category) -> &'static str {
    match category {
        Category::OffTopic => {
            "Moderation warning: Please keep discussion focused on Freenet and closely related projects. Continued off-topic discussion will result in a ban."
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
    }
}

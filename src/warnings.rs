use crate::verdict::Category;

pub const CONDUCT_NUDGE: &str = "Easy. Attack the idea, not the person.";
pub const TOPIC_NUDGE: &str = "Take the politics elsewhere. Back to Freenet.";

pub fn fixed_nudge(category: Category) -> &'static str {
    if category == Category::OffTopic {
        TOPIC_NUDGE
    } else {
        CONDUCT_NUDGE
    }
}

pub fn fixed_warning(category: Category) -> &'static str {
    match category {
        Category::OffTopic => "Take the politics elsewhere. Keep at it and you're gone.",
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
}

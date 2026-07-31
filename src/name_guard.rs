use regex::RegexSet;

/// High-confidence display-name checks performed before a member's first
/// message. These are deliberately narrow; ambiguous names remain observable
/// but are not punitive without conduct context.
const SEVERE_NAME_PATTERNS: &[&str] = &[
    r"(?i)(^|[^a-z])(nigg(?:er|a)|faggot|fag|dyke|tranny|shemale|chink|gook|kike|spic|beaner|wetback|paki|coon|porch ?monkey|sand ?nigg(?:er|a)|raghead|towelhead|retard|spaz|mongoloid|cunt)([^a-z]|$)",
    r"(?i)^.{3,}(nigg(?:er|a)|faggot|fag|dyke|tranny|shemale|chink|gook|kike|spic|beaner|wetback|paki|coon|porch ?monkey|sand ?nigg(?:er|a)|raghead|towelhead|retard|spaz|mongoloid|cunt)$",
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NameGuardAction {
    Ban { reason: String },
    Observe,
}

pub fn inspect(nickname: &str, protected_nicknames: &[String]) -> NameGuardAction {
    let normalized = normalize(nickname);
    if normalized.is_empty() {
        return NameGuardAction::Observe;
    }

    let protected = protected_nicknames
        .iter()
        .map(|name| normalize(name))
        .any(|name| !name.is_empty() && name == normalized);
    if protected {
        return NameGuardAction::Ban {
            reason: "exact protected-identity nickname impersonation".into(),
        };
    }

    let compact = normalized.replace(' ', "");
    let patterns = RegexSet::new(SEVERE_NAME_PATTERNS).expect("static name patterns are valid");
    if patterns.is_match(&normalized) || patterns.is_match(&compact) {
        return NameGuardAction::Ban {
            reason: "unmistakable hateful or abusive nickname".into(),
        };
    }

    NameGuardAction::Observe
}

pub fn normalize(value: &str) -> String {
    value
        .chars()
        .flat_map(char::to_lowercase)
        .filter(|character| !is_zero_width(*character))
        .map(|character| confusable(character).unwrap_or(character))
        .filter(|character| character.is_alphanumeric() || character.is_whitespace())
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn is_zero_width(character: char) -> bool {
    matches!(character, '\u{200B}'..='\u{200D}' | '\u{FEFF}')
}

fn confusable(character: char) -> Option<char> {
    Some(match character {
        'а' => 'a',
        'е' => 'e',
        'о' => 'o',
        'р' => 'p',
        'с' => 'c',
        'х' => 'x',
        'у' => 'y',
        'і' => 'i',
        'ј' => 'j',
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_spacing_zero_width_and_common_confusables() {
        assert_eq!(normalize("R\u{200B}iver  Mаrshal"), "river marshal");
    }

    #[test]
    fn bans_clear_slur_and_compound_forms() {
        assert!(matches!(
            inspect("nignognigger", &[]),
            NameGuardAction::Ban { .. }
        ));
        assert!(matches!(
            inspect("n i g g e r", &[]),
            NameGuardAction::Ban { .. }
        ));
    }

    #[test]
    fn does_not_ban_ambiguous_or_benign_names() {
        assert_eq!(inspect("snigger", &[]), NameGuardAction::Observe);
        assert_eq!(inspect("River Marshal", &[]), NameGuardAction::Observe);
        assert_eq!(
            inspect("Ian Clarke", &["Ian Clarke".into()]),
            NameGuardAction::Ban {
                reason: "exact protected-identity nickname impersonation".into(),
            }
        );
    }
}

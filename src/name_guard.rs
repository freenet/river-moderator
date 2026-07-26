use regex::RegexSet;
use std::sync::LazyLock;

/// Slur stems matched only against a word boundary. Short or ambiguous stems
/// belong here because they occur inside ordinary words and names, so an
/// unanchored match would flag "Scunthorpe", "snigger", or "Wild Raccoon".
const BOUNDED_STEMS: &str = concat!(
    r"nigg(?:er|a|ah)|trann(?:y|ie)|faggot|fag|dyke|shemale|chink|gook|kike|",
    r"spic|beaner|wetback|paki|coon|porch ?monkey|sand ?nigg(?:er|a|ah)|",
    r"raghead|towelhead|retard|spaz|mongoloid|cunt"
);

/// Long, distinctive stems matched anywhere in the name, including across
/// stripped separators. These sequences do not occur inside ordinary words and
/// are not produced by joining two benign words, so dropping the boundary
/// requirement costs at most an occasional extra model call.
const EMBEDDED_STEMS: &str = concat!(
    r"nigg(?:er|a|ah)|trann(?:y|ie)|faggot|shemale|wetback|beaner|raghead|",
    r"towelhead|mongoloid|porch ?monkey"
);

/// Common English inflections appended to a stem. Without this, every plural
/// and participle escaped the guard: the trailing `[^a-z]` boundary rejected
/// any letter suffix, so "trannies", "niggers", and even "faggots" all passed
/// while their singular forms matched.
const INFLECTIONS: &str = r"(?:e?s|z(?:es)?|ed|ing)?";

/// High-confidence display-name checks performed before a member's first
/// message.
///
/// This is a prefilter, not a decision: a match only routes the join notice to
/// the classifier and the independent verifier, which apply
/// `JOIN_NAME_RULES` and make the actual call. Nothing here can ban on its
/// own, so the patterns are tuned to catch evasion rather than to avoid false
/// positives; the two-model gate is what prevents those. A miss here, by
/// contrast, is silent and final: the name is never reviewed at all.
static SEVERE_NAME_PATTERNS: LazyLock<RegexSet> = LazyLock::new(|| {
    RegexSet::new([
        // Stem at a word boundary, with inflections.
        format!(r"(?i)(^|[^a-z])(?:{BOUNDED_STEMS}){INFLECTIONS}([^a-z]|$)"),
        // Name ends with a stem that has no leading boundary ("iamacunt").
        // This also screens benign words that end in a short stem, such as
        // "Wild Raccoon". That is deliberate and unchanged from the original
        // guard: the cost is one model call, which the two-model gate then
        // resolves, and narrowing it would drop real coverage to avoid a
        // false positive that did not occur once in 1,344 joins sampled from
        // a full day of the Freenet room.
        format!(r"(?i)^.{{3,}}(?:{BOUNDED_STEMS}){INFLECTIONS}$"),
        // Distinctive stem anywhere in the name ("xXtranniesXx").
        format!(r"(?i)(?:{EMBEDDED_STEMS}){INFLECTIONS}"),
    ])
    .expect("static name patterns are valid")
});

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
    if SEVERE_NAME_PATTERNS.is_match(&normalized) || SEVERE_NAME_PATTERNS.is_match(&compact) {
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

    fn is_candidate(nickname: &str) -> bool {
        matches!(inspect(nickname, &[]), NameGuardAction::Ban { .. })
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

    /// The production miss that motivated the inflection group: this exact
    /// nickname joined the Freenet room on 2026-07-26, was allowed through by
    /// the guard, and was banned 111 seconds later for, among other things, a
    /// "hateful display name". The trailing `[^a-z]` boundary rejected any
    /// letter suffix, so the plural stem never matched.
    #[test]
    fn screens_the_plural_display_name_that_escaped_in_production() {
        assert!(is_candidate("All the Devs are Trannies that Vibecode"));
    }

    #[test]
    fn screens_plural_and_participle_forms_of_every_stem() {
        for nickname in [
            "trannies",
            "trannys",
            "niggers",
            "niggas",
            "niggahs",
            "fags",
            "faggots",
            "kikes",
            "dykes",
            "chinks",
            "gooks",
            "spics",
            "beaners",
            "wetbacks",
            "pakis",
            "coons",
            "ragheads",
            "towelheads",
            "retards",
            "retarded",
            "cunts",
            "mongoloids",
            "shemales",
        ] {
            assert!(is_candidate(nickname), "{nickname} should be screened");
        }
    }

    #[test]
    fn still_screens_singular_stems() {
        for nickname in [
            "tranny",
            "nigger",
            "nigga",
            "fag",
            "faggot",
            "kike",
            "dyke",
            "chink",
            "gook",
            "spic",
            "beaner",
            "wetback",
            "paki",
            "coon",
            "raghead",
            "towelhead",
            "retard",
            "spaz",
            "mongoloid",
            "cunt",
            "shemale",
            "porch monkey",
            "sand nigger",
        ] {
            assert!(is_candidate(nickname), "{nickname} should be screened");
        }
    }

    #[test]
    fn screens_distinctive_stems_embedded_without_a_word_boundary() {
        assert!(is_candidate("xXtranniesXx"));
        assert!(is_candidate("aaafaggotaaa"));
        assert!(is_candidate("1337niggers1337"));
    }

    /// Short stems stay boundary-anchored and out of the embedded tier.
    /// Matching them as bare substrings anywhere would make every one of these
    /// a model call on join, and River hands out auto-generated two-word
    /// nicknames by the thousand. "Viki Kelly" and "Disco Onyx" are the
    /// motivating shape: stripping the space to defeat separator evasion joins
    /// two benign words into "kike" and "coon".
    #[test]
    fn does_not_screen_ordinary_words_containing_a_short_stem() {
        for nickname in [
            "Scunthorpe",
            "Disco Onyx",
            "Viki Kelly",
            "Pakistan",
            "suspicious",
            "Spice Trader",
            "River Marshal",
            "Fractal Serpent",
            "Silent Archive",
            "Volt Matrix",
        ] {
            assert!(!is_candidate(nickname), "{nickname} should not be screened");
        }
    }

    /// A match routes the join to the classifier and verifier; it is not a ban.
    /// Words that merely contain a distinctive stem are cheap to review and are
    /// a common dogwhistle, so they are deliberately screened rather than
    /// dropped, and the two-model gate decides.
    #[test]
    fn screens_rather_than_bans_words_containing_a_distinctive_stem() {
        assert!(is_candidate("snigger"));
        assert!(is_candidate("niggardly"));
    }

    /// The tail tier catches a slur glued to the end of a name with no
    /// separator. It also screens benign words ending in a short stem, which is
    /// accepted rather than narrowed: screening costs one model call that the
    /// two-model gate resolves, while narrowing would drop real coverage to
    /// avoid a false positive that did not occur once in a full day of joins.
    #[test]
    fn screens_slurs_glued_to_the_end_of_a_name() {
        assert!(is_candidate("iamacunt"));
        assert!(is_candidate("killthefags"));
        assert!(is_candidate("Wild Raccoon"));
    }

    #[test]
    fn bans_exact_protected_identity_impersonation() {
        assert_eq!(
            inspect("Ian Clarke", &["Ian Clarke".into()]),
            NameGuardAction::Ban {
                reason: "exact protected-identity nickname impersonation".into(),
            }
        );
    }

    #[test]
    fn screens_slurs_hidden_with_separators_and_confusables() {
        assert!(is_candidate("t r a n n i e s"));
        assert!(is_candidate("f.a.g.g.o.t.s"));
        assert!(is_candidate("niggеrs")); // Cyrillic е
    }
}

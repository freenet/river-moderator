use regex::RegexSet;
use std::sync::LazyLock;

/// Slur stems matched only against a word boundary. Short or ambiguous stems
/// belong here because they occur inside ordinary words and surnames, so
/// matching them unanchored would flag "Scunthorpe", "Viki Kelly", or
/// "Disco Onyx" (the last two via the separator-stripped form, where the join
/// spells "kike" and "coon"). "Troon" is here for the same reason: it is a
/// Scottish town and a surname.
const BOUNDED_STEMS: &str = concat!(
    r"nigg(?:er|a|ah)|trann(?:y|ie)|troon|faggot|fag|dyke|shemale|chink|gook|",
    r"kike|spic|beaner|wetback|paki|coon|porch ?monkey|sand ?nigg(?:er|a|ah)|",
    r"raghead|towelhead|retard|spaz|mongoloid|cunt|jigaboo|zipperhead|",
    r"spearchucker|jungle ?bunn(?:y|ie)|shitskin"
);

/// Long, distinctive stems matched anywhere in the name, including across
/// separators, so "xXtranniesXx" is caught.
///
/// Dropping the boundary requirement here is a deliberate widening, and it does
/// produce occasional matches on ordinary text: "snigger" and "niggardly" match
/// this tier, and joining two benign words can reach it too ("Wet Backpack" ->
/// "wetbackpack", "Ashe Male" -> "ashemale"). Those are accepted because the
/// sequences are long enough that the join is rare, and because such names are
/// a common dogwhistle worth a look. Short stems are excluded precisely because
/// their word-joins are not rare.
const EMBEDDED_STEMS: &str = concat!(
    r"nigg(?:er|a|ah)|trann(?:y|ie)|faggot|shemale|wetback|beaner|raghead|",
    r"towelhead|mongoloid|porch ?monkey|jigaboo|zipperhead|spearchucker|",
    r"jungle ?bunn(?:y|ie)|shitskin"
);

/// Common English inflections appended to a stem. Without this, every plural
/// and participle escaped the guard: the trailing `[^a-z]` boundary rejected
/// any letter suffix, so "trannies", "niggers", and even "faggots" all passed
/// while their singular forms matched.
///
/// The optional `[zg]` covers the doubled final consonant English inserts
/// before a vowel suffix ("spazzed", "fagging"), and doubles as leetspeak
/// pluralisation ("fagz").
const INFLECTIONS: &str = r"(?:[zg]?(?:e?s|ed|ing)?)?";

/// High-confidence display-name checks performed before a member's first
/// message.
///
/// This is a prefilter for *review*, not a decision: a match routes the join
/// notice to the classifier and the verifier, which apply `JOIN_NAME_RULES` and
/// make the call. Nothing in this module bans.
///
/// It does not follow that a false positive is free. In `Enforce` mode a
/// screened name that both models independently rate `BanSevereHarm` above
/// `ban_confidence_millionths` is banned automatically, with no human in the
/// path, before the member has posted anything (`policy.rs::decide_severe` ->
/// `runtime.rs::enforce_severe_ban`). So the real cost of a false positive is
/// one model call *plus* whatever risk remains that both models are wrong
/// together, and the patterns should stay narrow enough that ordinary names do
/// not reach that gate.
///
/// A miss is still the worse failure, and it is what these tiers are tuned
/// against: the name is never reviewed at join time, so nothing acts on it
/// until the member posts a first message that draws review on its own.
static SEVERE_NAME_PATTERNS: LazyLock<RegexSet> = LazyLock::new(|| {
    RegexSet::new([
        // Stem at a word boundary, with inflections.
        format!(r"(?i)(^|[^a-z])(?:{BOUNDED_STEMS}){INFLECTIONS}([^a-z]|$)"),
        // Name ends with a stem that has no leading boundary ("iamacunt").
        // This also screens benign words ending in a short stem, such as
        // "Wild Raccoon", which the original guard screened too. Narrowing it
        // would drop real coverage to avoid a false positive that did not occur
        // once across 1,344 sampled joins or the 10,000 nicknames River can
        // auto-generate; see `tests::rejects_every_river_auto_generated_handle`.
        format!(r"(?i)^.{{3,}}(?:{BOUNDED_STEMS}){INFLECTIONS}$"),
        // Distinctive stem anywhere in the name. No inflection group: the
        // pattern is unanchored and the group is fully optional, so appending
        // it could not change whether this tier matches.
        format!(r"(?i)(?:{EMBEDDED_STEMS})"),
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

    if contains_severe_slur(nickname) {
        return NameGuardAction::Ban {
            reason: "unmistakable hateful or abusive nickname".into(),
        };
    }

    NameGuardAction::Observe
}

/// Whether `text` contains a slur the severe-name patterns recognise.
///
/// Shared by the join-name guard and the message router. On the message side
/// this is a routing signal only: it decides that a message is worth a model
/// call, exactly like a duplicate flood or an oversized wall of text, and the
/// classifier and verifier still make every decision from the full message and
/// its surrounding context.
///
/// Routing on content matters because the router was otherwise blind to what a
/// message says. On 2026-07-26 a member posted "redditfag" and then "tranny
/// faggots love to censor..." and neither drew any review; the account was only
/// examined four minutes later when another member reported it by hand.
pub fn contains_severe_slur(text: &str) -> bool {
    let normalized = normalize(text);
    if normalized.is_empty() {
        return false;
    }
    let compact = normalized.replace(' ', "");
    SEVERE_NAME_PATTERNS.is_match(&normalized) || SEVERE_NAME_PATTERNS.is_match(&compact)
}

pub fn normalize(value: &str) -> String {
    value
        .chars()
        .flat_map(char::to_lowercase)
        .filter(|character| !is_zero_width(*character))
        .map(|character| confusable(character).unwrap_or(character))
        // Punctuation becomes a separator rather than vanishing. Deleting it
        // destroyed the word boundary the bounded tier needs, which made the
        // most idiomatic username separators an evasion: "kike_lover" folded to
        // "kikelover" and matched nothing, while the plain "kike lover" was
        // caught. Non-ASCII non-alphanumerics are still dropped below, which is
        // what strips NFD combining marks so decomposed accents keep matching.
        .map(|character| {
            if character.is_ascii_punctuation() {
                ' '
            } else {
                character
            }
        })
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
            "niggers",
            "niggas",
            "niggahs",
            "trannies",
            "trannys",
            "troons",
            "faggots",
            "fags",
            "dykes",
            "shemales",
            "chinks",
            "gooks",
            "kikes",
            "spics",
            "beaners",
            "wetbacks",
            "pakis",
            "coons",
            "porch monkeys",
            "sand niggers",
            "ragheads",
            "towelheads",
            "retards",
            "spazzes",
            "mongoloids",
            "cunts",
            "jigaboos",
            "zipperheads",
            "spearchuckers",
            "jungle bunnies",
            "shitskins",
        ] {
            assert!(is_candidate(nickname), "{nickname} should be screened");
        }
    }

    /// English doubles a final consonant before a vowel suffix. Without the
    /// `[zg]` in `INFLECTIONS` these escaped while their `-s` forms matched,
    /// and `spaz` is exactly the stem the earlier "every stem" list omitted.
    #[test]
    fn screens_doubled_consonant_participles() {
        for nickname in ["spazzed", "spazzing", "spazzes", "fagged", "fagging"] {
            assert!(is_candidate(nickname), "{nickname} should be screened");
        }
    }

    #[test]
    fn still_screens_singular_stems() {
        for nickname in [
            "tranny",
            "troon",
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
            "jigaboo",
            "zipperhead",
            "spearchucker",
            "jungle bunny",
            "shitskin",
        ] {
            assert!(is_candidate(nickname), "{nickname} should be screened");
        }
    }

    /// Deleting punctuation destroyed the word boundary the bounded tier needs,
    /// so the most idiomatic username separators were an evasion: the spaced
    /// form was caught while the underscored form was not. Mapping punctuation
    /// to a space closes it. Every case here was a confirmed bypass.
    #[test]
    fn screens_slurs_separated_by_punctuation() {
        for nickname in [
            "kike_lover",
            "fag-killer",
            "coon.town",
            "paki_go_home",
            "kikes_must_die",
            "retard!alert",
            "cunt/face",
        ] {
            assert!(is_candidate(nickname), "{nickname} should be screened");
        }
    }

    /// Same root cause as the separator bypass: exact-equality impersonation
    /// checks were defeated by inserting a separator.
    #[test]
    fn screens_protected_identity_impersonation_through_separators() {
        let protected = vec!["Ian Clarke".to_string()];
        for nickname in ["Ian Clarke", "Ian_Clarke", "Ian-Clarke", "Ian.Clarke"] {
            assert!(
                matches!(inspect(nickname, &protected), NameGuardAction::Ban { .. }),
                "{nickname} should be screened"
            );
        }
    }

    /// These reach ONLY the embedded tier. Cases with digits or punctuation
    /// around the stem would also satisfy the bounded tier's `[^a-z]` boundary,
    /// so they would pass even with the embedded pattern deleted.
    #[test]
    fn screens_distinctive_stems_reachable_only_by_the_embedded_tier() {
        for nickname in ["xXtranniesXx", "aaafaggotaaa", "myniggersclub"] {
            assert!(is_candidate(nickname), "{nickname} should be screened");
        }
    }

    /// Short stems stay boundary-anchored and out of the embedded tier. Every
    /// entry here contains a stem as a substring and must still be rejected;
    /// "Viki Kelly" and "Disco Onyx" are the motivating shape, since stripping
    /// the space to defeat separator evasion joins two benign words into
    /// "kike" and "coon".
    #[test]
    fn does_not_screen_ordinary_words_containing_a_short_stem() {
        for nickname in [
            "Scunthorpe",
            "Disco Onyx",
            "Viki Kelly",
            "Pakistan",
            "suspicious",
            "Spice Trader",
            "Cocoon",
            "Loki Kernel",
        ] {
            assert!(!is_candidate(nickname), "{nickname} should not be screened");
        }
    }

    /// A representative slice of River's auto-generated two-word handles, which
    /// make up the bulk of real joins. None may be screened: they recur
    /// constantly, and in Enforce mode a screened name that both models get
    /// wrong is banned with no human in the path.
    #[test]
    fn does_not_screen_river_auto_generated_handles() {
        for nickname in [
            "Fractal Serpent",
            "Volt Matrix",
            "Silent Archive",
            "Crimson Bellows",
            "Plasma Modem",
            "Feral Terminal",
            "Zero Spike",
            "Mercury Anchor",
            "Null Harbor",
            "Vapor Cobra",
            "Phantom Worm",
            "Cyber Foundry",
            "Meteor Almanac",
            "Indigo Terminal",
            "Astral Vertex",
            "Onyx Console",
            "Cobalt Spike",
            "Lunar Bellows",
            "Twilight Gateway",
            "Xenon Foundry",
            "Silicon Runner",
            "Carbon Courier",
            "Glacier Havoc",
            "Nitro Rune",
            "Crash Furnace",
        ] {
            assert!(!is_candidate(nickname), "{nickname} should not be screened");
        }
    }

    /// `troon` is knowingly ambiguous: it is also a Scottish town and a
    /// surname, so it screens names that are very likely innocent. It is
    /// carried anyway because it is a high-volume anti-trans slur and sits
    /// directly beside the production miss this guard exists to catch. This
    /// pins the cost rather than hiding it: these reach the model gate, whose
    /// instructions tell it not to ban for an ambiguous name.
    #[test]
    fn screens_ambiguous_stems_and_leaves_the_call_to_the_model_gate() {
        assert!(is_candidate("Troon Golf Club"));
        assert!(is_candidate("snigger"));
    }

    /// The tail tier catches a slur glued to the end of a name. It also screens
    /// benign words ending in a short stem, which the original guard did too.
    #[test]
    fn screens_slurs_glued_to_the_end_of_a_name() {
        assert!(is_candidate("iamacunt"));
        assert!(is_candidate("killthefags"));
        assert!(is_candidate("Wild Raccoon"));
    }

    /// A match routes the join to the classifier and verifier. This asserts the
    /// trigger only; the "review, not ban" property lives in `runtime.rs` and
    /// is not observable from this module, so do not read this test as pinning
    /// it. Words merely containing a distinctive stem are screened on purpose.
    #[test]
    fn screens_words_containing_a_distinctive_stem() {
        assert!(is_candidate("snigger"));
        assert!(is_candidate("niggardly"));
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
        assert!(is_candidate("nigg\u{435}rs")); // Cyrillic \u{435}
    }

    /// Decomposed accents must keep matching: combining marks are not ASCII
    /// punctuation, so they are still dropped rather than turned into spaces.
    #[test]
    fn screens_slurs_written_with_decomposed_accents() {
        assert!(is_candidate("nigge\u{301}r"));
        assert!(is_candidate("tra\u{308}nnies"));
    }
}

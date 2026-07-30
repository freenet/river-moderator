//! Deterministic validation of reaction payloads.
//!
//! River stores a reaction as `ReactionPayload { emoji: String }` with no
//! validation anywhere on the apply path, and no cap on reaction count or size.
//! The UI's picker was the only thing making arbitrary payloads "impossible",
//! and `riverctl message react` accepts any string, so a reaction is in practice
//! an unbounded free-text field that replicates to every peer.
//!
//! This module answers one question: does a reaction payload look like a single
//! emoji? It is pure string inspection with no model call.

use unicode_segmentation::UnicodeSegmentation;

/// Generous upper bound on a legitimate emoji cluster.
///
/// The longest emoji in common use is a four-person family with skin tones,
/// around 35 bytes. 64 leaves room without allowing an unbounded ZWJ chain,
/// which would otherwise be a single grapheme cluster of arbitrary length and
/// so would slip past the cluster check.
const MAX_REACTION_BYTES: usize = 64;

/// Codepoints that may appear in an emoji cluster but are not emoji by
/// themselves: zero-width joiner, variation selector 16, skin-tone modifiers,
/// the keycap combining mark, and the ASCII bases that legitimately carry a
/// keycap (`0-9`, `#`, `*`).
fn is_emoji_component(c: char) -> bool {
    matches!(c,
        '\u{200D}'                      // ZWJ
        | '\u{FE0F}' | '\u{FE0E}'       // variation selectors
        | '\u{20E3}'                    // combining enclosing keycap
        | '\u{1F3FB}'..='\u{1F3FF}'     // skin tone modifiers
        | '0'..='9' | '#' | '*'         // keycap bases
    )
}

/// Codepoints that are emoji in their own right.
///
/// Deliberately range-based rather than a full Unicode property table: the goal
/// is to admit the standard emoji set and reject text, not to adjudicate every
/// edge of the emoji spec. Letters, CJK, and general punctuation fall outside
/// every range here, which is what actually matters.
fn is_emoji_base(c: char) -> bool {
    matches!(c,
        '\u{1F300}'..='\u{1FAFF}'       // pictographs, supplemental, extended-A
        | '\u{1F000}'..='\u{1F2FF}'     // mahjong/domino/cards, enclosed
        | '\u{1F1E6}'..='\u{1F1FF}'     // regional indicators (flags)
        | '\u{2600}'..='\u{27BF}'       // misc symbols + dingbats
        | '\u{2B00}'..='\u{2BFF}'       // misc symbols and arrows
        | '\u{2190}'..='\u{21FF}'       // arrows
        | '\u{2300}'..='\u{23FF}'       // technical (watch, hourglass, ...)
        | '\u{25A0}'..='\u{25FF}'       // geometric shapes
        | '\u{2900}'..='\u{297F}'       // supplemental arrows
        | '\u{00A9}' | '\u{00AE}'       // (c) (r)
        | '\u{2122}'                    // TM
        | '\u{203C}' | '\u{2049}'       // !! !?
        | '\u{3030}' | '\u{303D}'
        | '\u{3297}' | '\u{3299}'
    )
}

/// Why a reaction payload was refused. `None` means it is acceptable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReactionProblem {
    Empty,
    TooLarge,
    NotSingleCluster,
    NotEmoji,
}

/// Judge a reaction payload.
///
/// The rule is one extended GRAPHEME CLUSTER that is built entirely from emoji
/// codepoints, plus a byte cap.
///
/// Grapheme clusters rather than `char`s because most emoji are multi-codepoint
/// and a `chars().count() == 1` rule would reject things people use constantly:
/// `❤️` is a heart plus a variation selector, `👍🏽` is a base plus a skin tone,
/// `🇬🇧` is two regional indicators, `👨‍👩‍👧` is a ZWJ sequence. It would also
/// wrongly ACCEPT `A`, `7`, and `漢`, which is why emoji-ness is checked too.
pub fn reaction_problem(payload: &str) -> Option<ReactionProblem> {
    if payload.is_empty() {
        return Some(ReactionProblem::Empty);
    }
    if payload.len() > MAX_REACTION_BYTES {
        return Some(ReactionProblem::TooLarge);
    }
    if payload.graphemes(true).count() != 1 {
        return Some(ReactionProblem::NotSingleCluster);
    }
    // At least one real emoji, and nothing that is neither emoji nor a
    // legitimate component of one.
    //
    // A keycap (`1` + VS16 + U+20E3) is the exception that proves the rule: it
    // is built ENTIRELY from components and contains no emoji base at all, so
    // the presence of the keycap mark has to count as emoji-ness on its own.
    // Without this a plain `1️⃣` is refused while `7` is still correctly
    // refused, since a bare keycap base carries no U+20E3.
    let has_keycap = payload.contains('\u{20E3}');
    if (!has_keycap && !payload.chars().any(is_emoji_base))
        || !payload
            .chars()
            .all(|c| is_emoji_base(c) || is_emoji_component(c))
    {
        return Some(ReactionProblem::NotEmoji);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Everything here is in routine use. A `chars().count() == 1` rule would
    /// reject all but the simplest of them, including a plain red heart.
    #[test]
    fn ordinary_emoji_are_accepted() {
        for ok in [
            "👍", // single codepoint
            "❤️", // + variation selector
            "👍🏽", // + skin tone
            "🇬🇧", // two regional indicators
            "👨‍👩‍👧", // ZWJ sequence
            "🎉",
            "😂",
            "🔥",
            "✅",
            "⭐",
            "🤖",
            "🙈",
        ] {
            assert_eq!(reaction_problem(ok), None, "rejected valid emoji {ok:?}");
        }
    }

    /// The abuse this exists to stop: text, walls, and markup in a field the UI
    /// presents as a single glyph.
    #[test]
    fn text_and_walls_are_refused() {
        assert_eq!(reaction_problem("A"), Some(ReactionProblem::NotEmoji));
        assert_eq!(reaction_problem("漢"), Some(ReactionProblem::NotEmoji));
        assert_eq!(reaction_problem(""), Some(ReactionProblem::Empty));
        assert_eq!(
            reaction_problem("lgtm"),
            Some(ReactionProblem::NotSingleCluster)
        );
        assert_eq!(
            reaction_problem("👍👍"),
            Some(ReactionProblem::NotSingleCluster)
        );
        assert_eq!(
            reaction_problem(&"x".repeat(500)),
            Some(ReactionProblem::TooLarge)
        );
        // A single cluster can still be unbounded via ZWJ chaining, which is
        // exactly why the byte cap exists and is checked first.
        let zwj_chain = "👨".to_string() + &"\u{200D}👨".repeat(40);
        assert_eq!(
            reaction_problem(&zwj_chain),
            Some(ReactionProblem::TooLarge)
        );
    }

    /// Digits are keycap BASES, so they must not sneak through on their own.
    #[test]
    fn keycap_bases_alone_are_not_emoji() {
        assert_eq!(reaction_problem("7"), Some(ReactionProblem::NotEmoji));
        assert_eq!(reaction_problem("#"), Some(ReactionProblem::NotEmoji));
        assert_eq!(reaction_problem("1️⃣"), None, "a real keycap is fine");
    }
}

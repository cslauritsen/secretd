//! Sanitisation of untrusted, caller-controlled strings before they are shown
//! to the owner or written to notifications.

use unicode_general_category::{get_general_category, GeneralCategory as G};

/// Characters that are invisible, reorder or spoof text, or have no defined
/// meaning: everything in the general categories Cc, Cf, Cn, Co, Cs, Zl, Zp
/// and Zs (except the plain ASCII space), plus code points that render as
/// blanks or alter rendering although they are letters, marks or symbols
/// (Unicode tag characters, variation selectors, Mongolian free variation
/// selectors including U+180E, interlinear annotation controls, Braille
/// blank, Hangul fillers, the combining grapheme joiner, Khmer inherent
/// vowels).
fn is_bad(c: char) -> bool {
    if c == ' ' {
        return false;
    }
    if c.is_control() {
        return true;
    }
    if matches!(
        get_general_category(c),
        G::Control
            | G::Format
            | G::Unassigned
            | G::PrivateUse
            | G::Surrogate
            | G::LineSeparator
            | G::ParagraphSeparator
            | G::SpaceSeparator
    ) {
        return true;
    }
    matches!(
        u32::from(c),
        0x034F                      // combining grapheme joiner
        | 0x115F | 0x1160           // Hangul choseong/jungseong fillers
        | 0x17B4 | 0x17B5           // Khmer inherent vowels
        | 0x180B..=0x180F           // Mongolian free variation selectors, U+180E
        | 0x2800                    // Braille pattern blank
        | 0x3164 | 0xFFA0           // Hangul filler, halfwidth Hangul filler
        | 0xFE00..=0xFE0F           // variation selectors
        | 0xFFF9..=0xFFFB           // interlinear annotation
        | 0xE0000..=0xE007F         // tag characters
        | 0xE0100..=0xE01EF         // variation selectors supplement
    )
}

/// Replace control, bidi and invisible characters with `?` and truncate to at
/// most `max_chars` characters (adding an ellipsis when truncated).
pub fn clean(input: &str, max_chars: usize) -> String {
    let mut out = String::new();
    for (n, c) in input.chars().enumerate() {
        if n >= max_chars {
            out.push('\u{2026}');
            break;
        }
        out.push(if is_bad(c) { '?' } else { c });
    }
    out
}

/// Like [`clean`] but restricted to printable ASCII (for HTTP header values).
pub fn ascii(input: &str, max_chars: usize) -> String {
    let mut out = String::new();
    for (n, c) in input.chars().enumerate() {
        if n >= max_chars {
            out.push_str("...");
            break;
        }
        out.push(if c.is_ascii_graphic() || c == ' ' {
            c
        } else {
            '?'
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_control_and_bidi() {
        assert_eq!(clean("a\x1b[31mb\n", 50), "a?[31mb?");
        assert_eq!(clean("pay\u{202E}txt.exe", 50), "pay?txt.exe");
        assert_eq!(clean("a\u{200B}b", 50), "a?b");
    }

    #[test]
    fn strips_invisible_and_spoofing_characters() {
        for (c, name) in [
            ('\u{E0041}', "tag latin A"),
            ('\u{E0001}', "language tag"),
            ('\u{E007F}', "cancel tag"),
            ('\u{FE0F}', "variation selector-16"),
            ('\u{FE00}', "variation selector-1"),
            ('\u{E0100}', "variation selector-17"),
            ('\u{180E}', "mongolian vowel separator"),
            ('\u{FFF9}', "interlinear annotation anchor"),
            ('\u{FFFB}', "interlinear annotation terminator"),
            ('\u{2800}', "braille blank"),
            ('\u{3164}', "hangul filler"),
            ('\u{FFA0}', "halfwidth hangul filler"),
            ('\u{115F}', "hangul choseong filler"),
            ('\u{034F}', "combining grapheme joiner"),
            ('\u{2028}', "line separator"),
            ('\u{2029}', "paragraph separator"),
            ('\u{00A0}', "no-break space"),
            ('\u{2003}', "em space"),
            ('\u{3000}', "ideographic space"),
            ('\u{200D}', "zero width joiner"),
            ('\u{061C}', "arabic letter mark"),
            ('\u{0378}', "unassigned"),
            ('\u{E000}', "private use"),
            ('\u{F0000}', "supplementary private use"),
            ('\u{0600}', "arabic number sign (Cf)"),
            ('\u{13430}', "egyptian format control (Cf)"),
            ('\u{1D173}', "musical beam control (Cf)"),
            ('\u{7F}', "delete"),
            ('\u{85}', "next line"),
        ] {
            assert_eq!(
                clean(&format!("a{c}b"), 50),
                "a?b",
                "{name} U+{:04X}",
                c as u32
            );
        }
    }

    #[test]
    fn keeps_ordinary_text() {
        let t = "héllo wörld 日本語 Привет 🙂 psql -h db.example.com --opt=1";
        assert_eq!(clean(t, 200), t);
    }

    #[test]
    fn truncates() {
        assert_eq!(clean("abcdef", 3), "abc\u{2026}");
        assert_eq!(clean("abc", 3), "abc");
    }

    #[test]
    fn ascii_only() {
        assert_eq!(ascii("héllo\n", 50), "h?llo?");
        assert_eq!(ascii("abcdef", 3), "abc...");
    }
}

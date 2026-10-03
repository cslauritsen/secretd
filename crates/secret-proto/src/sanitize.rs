//! Sanitisation of untrusted, caller-controlled strings before they are shown
//! to the owner or written to notifications.

fn is_bad(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            // bidi controls, isolates and marks
            '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'
            // zero width and invisible formatting
            | '\u{200B}'..='\u{200D}' | '\u{2060}'..='\u{2064}' | '\u{FEFF}' | '\u{00AD}'
            | '\u{2028}' | '\u{2029}'
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

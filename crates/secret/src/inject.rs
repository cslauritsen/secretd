//! Template substitution for `secret inject`.
//!
//! Token syntax: `{{ secret:NAME }}` with optional spaces/tabs inside the
//! braces and `NAME` matching `[A-Za-z0-9._/-]+`.  `\{{ secret:NAME }}`
//! outputs the literal token (the backslash is consumed).  Anything that is
//! not a well-formed token is passed through untouched.  Parsing works on a
//! complete in-memory buffer, so tokens split across read chunks are handled.

use std::io::Read;

#[derive(Debug, PartialEq, Eq)]
pub enum Seg<'a> {
    /// Bytes copied to the output verbatim.
    Lit(&'a [u8]),
    /// A secret reference to substitute.
    Secret(&'a str),
}

fn is_name_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'/' | b'-')
}

fn skip_ws(input: &[u8], mut i: usize) -> usize {
    while i < input.len() && matches!(input[i], b' ' | b'\t') {
        i += 1;
    }
    i
}

/// If a well-formed token starts at `start` (which must point at `{{`),
/// return its name and the index just past the closing `}}`.
fn token_at(input: &[u8], start: usize) -> Option<(&str, usize)> {
    if !input[start..].starts_with(b"{{") {
        return None;
    }
    let mut i = skip_ws(input, start + 2);
    if !input[i..].starts_with(b"secret:") {
        return None;
    }
    i += b"secret:".len();
    let name_start = i;
    while i < input.len() && is_name_byte(input[i]) {
        i += 1;
    }
    if i == name_start {
        return None;
    }
    let name = std::str::from_utf8(&input[name_start..i]).ok()?;
    i = skip_ws(input, i);
    if !input[i..].starts_with(b"}}") {
        return None;
    }
    Some((name, i + 2))
}

/// Split `input` into literal runs and secret references.
pub fn parse(input: &[u8]) -> Vec<Seg<'_>> {
    let mut segs = Vec::new();
    let mut lit_start = 0;
    let mut i = 0;
    while i < input.len() {
        match input[i] {
            b'\\' if input[i + 1..].starts_with(b"{{") => {
                if let Some((_, end)) = token_at(input, i + 1) {
                    // Escaped token: drop the backslash, keep the token text.
                    if lit_start < i {
                        segs.push(Seg::Lit(&input[lit_start..i]));
                    }
                    segs.push(Seg::Lit(&input[i + 1..end]));
                    i = end;
                    lit_start = end;
                    continue;
                }
                i += 1;
            }
            b'{' => {
                if let Some((name, end)) = token_at(input, i) {
                    if lit_start < i {
                        segs.push(Seg::Lit(&input[lit_start..i]));
                    }
                    segs.push(Seg::Secret(name));
                    i = end;
                    lit_start = end;
                    continue;
                }
                i += 1;
            }
            _ => i += 1,
        }
    }
    if lit_start < input.len() {
        segs.push(Seg::Lit(&input[lit_start..]));
    }
    segs
}

/// Distinct secret names in order of first appearance.
pub fn names<'a>(segs: &[Seg<'a>]) -> Vec<&'a str> {
    let mut out: Vec<&str> = Vec::new();
    for s in segs {
        if let Seg::Secret(n) = s {
            if !out.contains(n) {
                out.push(n);
            }
        }
    }
    out
}

/// Produce the output, looking up each secret's bytes with `lookup`.
pub fn render<'a>(segs: &[Seg<'_>], lookup: impl Fn(&str) -> Option<&'a [u8]>) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    for s in segs {
        match s {
            Seg::Lit(b) => out.extend_from_slice(b),
            Seg::Secret(n) => out.extend_from_slice(lookup(n)?),
        }
    }
    Some(out)
}

/// Read everything from `r` (arbitrary chunking) up to `limit` bytes.
pub fn read_all(r: &mut impl Read, limit: usize) -> std::io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    r.take(limit as u64 + 1).read_to_end(&mut buf)?;
    if buf.len() > limit {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "template too large",
        ));
    }
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn run(input: &[u8], vals: &[(&str, &[u8])]) -> Vec<u8> {
        let m: HashMap<&str, &[u8]> = vals.iter().copied().collect();
        let segs = parse(input);
        render(&segs, |n| m.get(n).copied()).unwrap()
    }

    #[test]
    fn basic_and_whitespace_variants() {
        let v: &[(&str, &[u8])] = &[("a", b"AAA"), ("b/c.d_e-f", b"B")];
        assert_eq!(run(b"x={{ secret:a }};", v), b"x=AAA;");
        assert_eq!(run(b"{{secret:a}}", v), b"AAA");
        assert_eq!(run(b"{{   secret:a\t}}", v), b"AAA");
        assert_eq!(run(b"{{\tsecret:b/c.d_e-f  }}", v), b"B");
        assert_eq!(run(b"{{ secret:a }}{{ secret:a }}", v), b"AAAAAA");
        assert_eq!(run(b"no tokens here", v), b"no tokens here");
        assert_eq!(run(b"", v), b"");
    }

    #[test]
    fn escapes() {
        let v: &[(&str, &[u8])] = &[("a", b"AAA")];
        assert_eq!(run(br"\{{ secret:a }}", v), b"{{ secret:a }}");
        assert_eq!(
            run(br"x \{{ secret:a }} y {{ secret:a }}", v),
            b"x {{ secret:a }} y AAA"
        );
        // Escape applies only to a well-formed token; otherwise the backslash stays.
        assert_eq!(run(br"\{{ nothing }}", v), br"\{{ nothing }}");
        assert_eq!(run(br"\x{{ secret:a }}", v), br"\xAAA");
        // Only the immediately preceding backslash escapes.
        assert_eq!(run(br"\\{{ secret:a }}", v), br"\{{ secret:a }}");
    }

    #[test]
    fn malformed_tokens_are_literal() {
        let v: &[(&str, &[u8])] = &[("a", b"AAA")];
        for bad in [
            &b"{{ secret: }}"[..],
            b"{{ secret:a",
            b"{{ secret:a }",
            b"{{ secret:a b }}",
            b"{{ secret:a$ }}",
            b"{{ Secret:a }}",
            b"{{ other:a }}",
            b"{ secret:a }",
            b"{{secret :a}}",
            b"{{\nsecret:a}}",
            b"{{",
            b"{",
            b"{{ secret:",
        ] {
            assert_eq!(run(bad, v), bad, "{}", String::from_utf8_lossy(bad));
        }
    }

    #[test]
    fn adjacent_nested_and_surrounding_braces() {
        let v: &[(&str, &[u8])] = &[("a", b"1"), ("b", b"2")];
        assert_eq!(run(b"{{ secret:a }}{{ secret:b }}", v), b"12");
        assert_eq!(run(b"{{{ secret:a }}}", v), b"{1}");
        assert_eq!(run(b"{{ {{ secret:a }} }}", v), b"{{ 1 }}");
        assert_eq!(run(b"${{ secret:a }}", v), b"$1");
    }

    #[test]
    fn binary_safe() {
        let v: &[(&str, &[u8])] = &[("a", &[0, 255, 1])];
        let input = [0xffu8, 0x00, b'{', 0xc3, b'{', b'{', b' ', b's'];
        assert_eq!(run(&input, v), input);
        let mut with_token = vec![0xff, 0xfe, 0x00];
        with_token.extend_from_slice(b"{{ secret:a }}");
        with_token.push(0x80);
        assert_eq!(run(&with_token, v), [0xff, 0xfe, 0x00, 0, 255, 1, 0x80]);
    }

    #[test]
    fn names_are_distinct_in_order() {
        let segs = parse(b"{{ secret:b }} {{ secret:a }} {{ secret:b }} \\{{ secret:z }}");
        assert_eq!(names(&segs), vec!["b", "a"]);
    }

    /// Reader that returns at most `n` bytes per read, like a slow pipe.
    struct Drip<'a>(&'a [u8], usize);
    impl Read for Drip<'_> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = self.1.min(buf.len()).min(self.0.len());
            buf[..n].copy_from_slice(&self.0[..n]);
            self.0 = &self.0[n..];
            Ok(n)
        }
    }

    #[test]
    fn tokens_split_across_read_chunks() {
        let v: &[(&str, &[u8])] = &[("db", b"S3CRET")];
        let input = b"a={{ secret:db }}\nb=\\{{ secret:db }}\nc={{secret:db}}";
        let want = run(input, v);
        for chunk in [1, 2, 3, 5, 7, 64] {
            let got_in = read_all(&mut Drip(input, chunk), 1 << 20).unwrap();
            assert_eq!(got_in, input);
            assert_eq!(run(&got_in, v), want, "chunk size {chunk}");
        }
        assert_eq!(want, b"a=S3CRET\nb={{ secret:db }}\nc=S3CRET");
    }

    #[test]
    fn read_all_enforces_limit() {
        assert!(read_all(&mut Drip(&[0u8; 100], 10), 99).is_err());
        assert!(read_all(&mut Drip(&[0u8; 100], 10), 100).is_ok());
    }

    #[test]
    fn missing_lookup_yields_none() {
        let segs = parse(b"{{ secret:a }}");
        assert!(render(&segs, |_| None).is_none());
    }
}

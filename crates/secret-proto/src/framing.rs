//! Newline-delimited JSON framing (one message per line, max 64 KiB).

use crate::MAX_LINE_LEN;
use std::io::{self, BufRead, Write};

/// Serialise a message as one line (including the trailing `\n`).
pub fn encode_line<T: serde::Serialize>(msg: &T) -> io::Result<Vec<u8>> {
    let mut v = serde_json::to_vec(msg).map_err(io::Error::other)?;
    if v.len() > MAX_LINE_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "message exceeds maximum line length",
        ));
    }
    v.push(b'\n');
    Ok(v)
}

pub fn write_line<W: Write, T: serde::Serialize>(w: &mut W, msg: &T) -> io::Result<()> {
    let line = encode_line(msg)?;
    w.write_all(&line)?;
    w.flush()
}

/// Result of reading one frame.
#[derive(Debug, PartialEq, Eq)]
pub enum Frame {
    /// A complete line (without the newline) was placed in the buffer.
    Line,
    /// Clean end of stream with no pending bytes.
    Eof,
    /// The line exceeded the maximum length; the stream should be closed.
    TooLong,
}

/// Read one newline-terminated frame into `buf` (cleared first), enforcing
/// `max_len`.  Reads are bounded so an oversized line never buffers more than
/// `max_len + 1` bytes.  A final unterminated line before EOF is an error.
pub fn read_frame<R: BufRead>(r: &mut R, buf: &mut Vec<u8>, max_len: usize) -> io::Result<Frame> {
    buf.clear();
    loop {
        let chunk = r.fill_buf()?;
        if chunk.is_empty() {
            return if buf.is_empty() {
                Ok(Frame::Eof)
            } else {
                Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "unterminated line",
                ))
            };
        }
        match chunk.iter().position(|&b| b == b'\n') {
            Some(pos) => {
                if buf.len() + pos > max_len {
                    return Ok(Frame::TooLong);
                }
                buf.extend_from_slice(&chunk[..pos]);
                r.consume(pos + 1);
                return Ok(Frame::Line);
            }
            None => {
                let n = chunk.len();
                if buf.len() + n > max_len {
                    return Ok(Frame::TooLong);
                }
                buf.extend_from_slice(chunk);
                r.consume(n);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufReader, Cursor};

    #[test]
    fn reads_lines_across_tiny_chunks() {
        // BufReader with capacity 1 forces every fill_buf to return one byte.
        let data = b"{\"a\":1}\n{\"b\":2}\n";
        let mut r = BufReader::with_capacity(1, Cursor::new(&data[..]));
        let mut buf = Vec::new();
        assert_eq!(read_frame(&mut r, &mut buf, 100).unwrap(), Frame::Line);
        assert_eq!(buf, b"{\"a\":1}");
        assert_eq!(read_frame(&mut r, &mut buf, 100).unwrap(), Frame::Line);
        assert_eq!(buf, b"{\"b\":2}");
        assert_eq!(read_frame(&mut r, &mut buf, 100).unwrap(), Frame::Eof);
    }

    #[test]
    fn rejects_oversized() {
        let mut data = vec![b'a'; 200];
        data.push(b'\n');
        let mut r = BufReader::with_capacity(16, Cursor::new(data));
        let mut buf = Vec::new();
        assert_eq!(read_frame(&mut r, &mut buf, 100).unwrap(), Frame::TooLong);
        assert!(buf.len() <= 101);
    }

    #[test]
    fn exact_limit_is_accepted() {
        let mut data = vec![b'a'; 100];
        data.push(b'\n');
        let mut r = Cursor::new(data);
        let mut buf = Vec::new();
        assert_eq!(read_frame(&mut r, &mut buf, 100).unwrap(), Frame::Line);
        assert_eq!(buf.len(), 100);
    }

    #[test]
    fn unterminated_is_error() {
        let mut r = Cursor::new(b"abc".to_vec());
        let mut buf = Vec::new();
        assert!(read_frame(&mut r, &mut buf, 100).is_err());
    }

    #[test]
    fn encode_appends_newline() {
        let l = encode_line(&serde_json::json!({"x": 1})).unwrap();
        assert_eq!(l, b"{\"x\":1}\n");
    }
}

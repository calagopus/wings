pub struct LineBuffer {
    buffer: Vec<u8>,
    line_start: usize,
}

impl LineBuffer {
    const INITIAL_CAPACITY: usize = 10240; // 10 KiB
    const MAX_LINE_LENGTH: usize = 5120; // 5 KiB
    const COMPACT_THRESHOLD: usize = 10240; // 10 KiB

    pub fn new() -> Self {
        Self {
            buffer: Vec::with_capacity(Self::INITIAL_CAPACITY),
            line_start: 0,
        }
    }

    pub fn extend(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }

    pub fn next_line(&mut self) -> Option<&[u8]> {
        let newline = self
            .buffer
            .get(self.line_start..)?
            .iter()
            .position(|&b| b == b'\n');
        let available = self.buffer.len() - self.line_start;

        let (len, advance) = match newline {
            Some(pos) if pos <= Self::MAX_LINE_LENGTH => (pos, pos + 1),
            Some(_) => (Self::MAX_LINE_LENGTH, Self::MAX_LINE_LENGTH),
            None if available > Self::MAX_LINE_LENGTH => {
                (Self::MAX_LINE_LENGTH, Self::MAX_LINE_LENGTH)
            }
            None => return None,
        };

        let start = self.line_start;
        self.line_start += advance;

        self.buffer
            .get(start..start + len)
            .map(|slice| slice.trim_ascii_end())
    }

    pub fn compact(&mut self) {
        if self.line_start > Self::COMPACT_THRESHOLD && self.line_start > self.buffer.len() / 2 {
            self.buffer.drain(..self.line_start);
            self.line_start = 0;
        }
    }

    pub fn flush(&self) -> Option<&[u8]> {
        let rest = self.buffer.get(self.line_start..)?;
        (!rest.is_empty()).then(|| rest.trim_ascii_end())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAX: usize = LineBuffer::MAX_LINE_LENGTH;

    // LineBuffer

    #[test]
    fn new_buffer_yields_nothing() {
        let mut lb = LineBuffer::new();
        assert_eq!(lb.next_line(), None);
        assert_eq!(lb.flush(), None);
    }

    #[test]
    fn single_line() {
        let mut lb = LineBuffer::new();
        lb.extend(b"hello\n");
        assert_eq!(lb.next_line(), Some(&b"hello"[..]));
        assert_eq!(lb.next_line(), None);
    }

    #[test]
    fn multiple_lines_in_order() {
        let mut lb = LineBuffer::new();
        lb.extend(b"a\nb\nc\n");
        assert_eq!(lb.next_line(), Some(&b"a"[..]));
        assert_eq!(lb.next_line(), Some(&b"b"[..]));
        assert_eq!(lb.next_line(), Some(&b"c"[..]));
        assert_eq!(lb.next_line(), None);
    }

    #[test]
    fn pending_line_without_newline_returns_none() {
        let mut lb = LineBuffer::new();
        lb.extend(b"partial");
        assert_eq!(lb.next_line(), None);
        // still recoverable via flush
        assert_eq!(lb.flush(), Some(&b"partial"[..]));
    }

    #[test]
    fn partial_line_completed_by_later_extend() {
        let mut lb = LineBuffer::new();
        lb.extend(b"par");
        assert_eq!(lb.next_line(), None);
        lb.extend(b"tial\n");
        assert_eq!(lb.next_line(), Some(&b"partial"[..]));
        assert_eq!(lb.next_line(), None);
    }

    #[test]
    fn streaming_in_arbitrary_chunks() {
        let mut lb = LineBuffer::new();
        lb.extend(b"hel");
        assert_eq!(lb.next_line(), None);
        lb.extend(b"lo\nwor");
        assert_eq!(lb.next_line(), Some(&b"hello"[..]));
        assert_eq!(lb.next_line(), None);
        lb.extend(b"ld\n");
        assert_eq!(lb.next_line(), Some(&b"world"[..]));
        assert_eq!(lb.next_line(), None);
    }

    #[test]
    fn trims_only_trailing_ascii_whitespace() {
        let mut lb = LineBuffer::new();
        lb.extend(b"  hello  \n");
        assert_eq!(lb.next_line(), Some(&b"  hello"[..]));
    }

    #[test]
    fn trims_carriage_return_from_crlf() {
        let mut lb = LineBuffer::new();
        lb.extend(b"\thi\r\n");
        assert_eq!(lb.next_line(), Some(&b"\thi"[..]));
    }

    #[test]
    fn empty_line_returns_empty_slice() {
        let mut lb = LineBuffer::new();
        lb.extend(b"a\n\nb\n");
        assert_eq!(lb.next_line(), Some(&b"a"[..]));
        assert_eq!(lb.next_line(), Some(&b""[..]));
        assert_eq!(lb.next_line(), Some(&b"b"[..]));
        assert_eq!(lb.next_line(), None);
    }

    #[test]
    fn whitespace_only_line_trims_to_empty() {
        let mut lb = LineBuffer::new();
        lb.extend(b"   \n");
        assert_eq!(lb.next_line(), Some(&b""[..]));
    }

    #[test]
    fn flush_returns_end_trimmed_remainder() {
        let mut lb = LineBuffer::new();
        lb.extend(b"done\n  leftover  ");
        assert_eq!(lb.next_line(), Some(&b"done"[..]));
        assert_eq!(lb.flush(), Some(&b"  leftover"[..]));
        assert_eq!(lb.flush(), Some(&b"  leftover"[..]));
    }

    #[test]
    fn flush_is_none_when_fully_consumed() {
        let mut lb = LineBuffer::new();
        lb.extend(b"a\n");
        assert_eq!(lb.next_line(), Some(&b"a"[..]));
        assert_eq!(lb.flush(), None);
    }

    #[test]
    fn flush_of_whitespace_only_remainder_is_some_empty() {
        let mut lb = LineBuffer::new();
        lb.extend(b"x\n   ");
        assert_eq!(lb.next_line(), Some(&b"x"[..]));
        assert_eq!(lb.flush(), Some(&b""[..]));
    }

    #[test]
    fn line_exactly_max_is_kept_whole() {
        let mut lb = LineBuffer::new();
        let mut data = vec![b'x'; MAX];
        data.push(b'\n');
        lb.extend(&data);
        assert_eq!(lb.next_line().map(<[_]>::len), Some(MAX));
        assert_eq!(lb.next_line(), None);
    }

    #[test]
    fn over_length_line_with_newline_is_split_into_chunks() {
        let mut lb = LineBuffer::new();
        let extra = 880;
        let mut data = vec![b'x'; MAX + extra];
        data.push(b'\n');
        lb.extend(&data);

        // first the forced max-length chunk (no newline consumed)
        assert_eq!(lb.next_line().map(<[_]>::len), Some(MAX));
        // then the remainder up to the newline
        assert_eq!(lb.next_line().map(<[_]>::len), Some(extra));
        assert_eq!(lb.next_line(), None);
    }

    #[test]
    fn over_length_line_without_newline_is_force_emitted() {
        let mut lb = LineBuffer::new();
        let extra = 880;
        lb.extend(&vec![b'x'; MAX + extra]);

        // available > MAX with no newline forces a max-length chunk
        assert_eq!(lb.next_line().map(<[_]>::len), Some(MAX));
        // the leftover is below MAX and has no newline, so it waits
        assert_eq!(lb.next_line(), None);
        assert_eq!(lb.flush().map(<[_]>::len), Some(extra));
    }

    #[test]
    fn exactly_max_without_newline_waits_then_forces() {
        let mut lb = LineBuffer::new();
        lb.extend(&vec![b'x'; MAX]);
        // available == MAX is not strictly greater than MAX, so it waits
        assert_eq!(lb.next_line(), None);

        // one more byte tips it over and forces the chunk
        lb.extend(b"x");
        assert_eq!(lb.next_line().map(<[_]>::len), Some(MAX));
        assert_eq!(lb.next_line(), None);
        assert_eq!(lb.flush().map(<[_]>::len), Some(1));
    }

    #[test]
    fn forced_chunk_remainder_completes_when_newline_arrives() {
        let mut lb = LineBuffer::new();
        let extra = 880;
        lb.extend(&vec![b'x'; MAX + extra]);
        assert_eq!(lb.next_line().map(<[_]>::len), Some(MAX));
        assert_eq!(lb.next_line(), None);

        lb.extend(b"\n");
        assert_eq!(lb.next_line().map(<[_]>::len), Some(extra));
        assert_eq!(lb.next_line(), None);
    }

    #[test]
    fn compact_noop_when_below_threshold() {
        let mut lb = LineBuffer::new();
        lb.extend(b"a\nbc");
        assert_eq!(lb.next_line(), Some(&b"a"[..]));
        let before = lb.line_start;

        lb.compact();
        // nothing drained, cursor untouched, data intact
        assert_eq!(lb.line_start, before);
        assert_eq!(lb.flush(), Some(&b"bc"[..]));
    }

    #[test]
    fn compact_drains_consumed_prefix_and_preserves_rest() {
        let mut lb = LineBuffer::new();

        let line_len = 100; // 99 payload bytes + '\n'
        let mut line = vec![b'x'; line_len - 1];
        line.push(b'\n');

        // enough lines that the consumed prefix clears COMPACT_THRESHOLD
        let total = LineBuffer::COMPACT_THRESHOLD / line_len + 30;
        let keep = 20;
        let consume = total - keep;

        for _ in 0..total {
            lb.extend(&line);
        }
        for _ in 0..consume {
            assert!(lb.next_line().is_some());
        }

        assert!(lb.line_start > LineBuffer::COMPACT_THRESHOLD);
        assert!(lb.line_start > lb.buffer.len() / 2);

        lb.compact();
        assert_eq!(lb.line_start, 0);
        assert_eq!(lb.buffer.len(), keep * line_len);

        let mut remaining = 0;
        while let Some(l) = lb.next_line() {
            assert_eq!(l.len(), line_len - 1);
            remaining += 1;
        }
        assert_eq!(remaining, keep);
        assert_eq!(lb.flush(), None);
    }
}

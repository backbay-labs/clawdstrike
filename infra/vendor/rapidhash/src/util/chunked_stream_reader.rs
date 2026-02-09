use std::io::Read;

/// Internal reader that reads data in chunks from a stream, and caches a certain number of
/// last-read bytes. This facilitates streamed hashing for rapidhash V3.
pub(crate) struct ChunkedStreamReader<R: Read> {
    reader: R,
    start: usize,
    end: usize,
    total_read: usize,
    buffer: Vec<u8>,
    last: Vec<u8>,
}

impl<R: Read> ChunkedStreamReader<R> {
    #[inline]
    pub fn new(reader: R, keep_last: usize) -> Self {
        Self {
            reader,
            start: 0,
            end: 0,
            total_read: 0,
            buffer: vec![0; 8 * 1024],
            last: vec![0; keep_last],
        }
    }

    #[inline(always)]
    pub fn debug_invariants(&self) {
        debug_assert!(self.start <= self.end);
        debug_assert!(self.end <= self.buffer.len());
    }

    /// Returns the buffer size.
    pub fn fill_buffer(&mut self, chunk_size: usize) -> std::io::Result<usize> {
        self.debug_invariants();
        if chunk_size > self.buffer.len() {
            self.buffer.resize(chunk_size, 0);
        }

        let mut read_in_round = 0;

        while self.end - self.start < chunk_size {
            if self.buffer.len() - self.start < chunk_size {
                self.buffer.copy_within(self.start..self.end, 0);
                self.end -= self.start;
                self.start = 0;
            }

            let read = self.reader.read(&mut self.buffer[self.end..])?;
            if read == 0 {
                break;
            }
            read_in_round += read;
            self.end += read;
        }

        self.total_read += read_in_round;
        self.debug_invariants();
        Ok(read_in_round)
    }

    #[inline]
    pub fn consume(&mut self, consume: usize) {
        self.debug_invariants();
        self.start += consume;
        self.debug_invariants();
        if self.start > self.end {
            self.start = self.end;
        }
    }

    /// Read a chunk of data, guaranteeing to return at least `chunk_size` unless the reader has
    /// reached the end. May return larger than `chunk_size` if available.
    pub fn read_chunk(&mut self, chunk_size: usize) -> std::io::Result<&[u8]> {
        let read = self.fill_buffer(chunk_size)?;

        if read > 0 {
            if read < self.last.len() {
                self.last.copy_within(read.., 0);
            }

            let read = read.min(self.last.len());
            let offset = self.last.len() - read;

            self.last[offset..].copy_from_slice(&self.buffer[self.end - read..self.end]);
        }

        Ok(&self.buffer[self.start..self.end])
    }

    #[inline]
    pub fn last_read(&self) -> &[u8] {
        &self.last
    }
}

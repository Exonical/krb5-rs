//! Sequence/replay tracking, mirroring MIT generic/util_seqstate.c:65-117.
//!
//! MIT reports GSS_S_GAP_TOKEN / GSS_S_UNSEQ_TOKEN / GSS_S_OLD_TOKEN /
//! GSS_S_DUPLICATE_TOKEN as supplementary-info major-status bits — the
//! message is still returned to the caller.  We model that with the
//! [`SeqStatus`] return value rather than an error.

/// Per-message sequence outcome (MIT GSS_S_* supplementary statuses).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeqStatus {
    /// Accepted in order (GSS_S_COMPLETE).
    Complete,
    /// Earlier sequence numbers were skipped (GSS_S_GAP_TOKEN).
    Gap,
    /// In-window out-of-order arrival under sequence checking
    /// (GSS_S_UNSEQ_TOKEN).
    Unseq,
    /// Too old for the replay window (GSS_S_OLD_TOKEN).
    Old,
    /// Already seen under replay checking (GSS_S_DUPLICATE_TOKEN).
    Duplicate,
}

/// Sequence-number state for received per-message tokens.
#[derive(Debug)]
pub struct SeqState {
    do_replay: bool,
    do_sequence: bool,
    seqmask: u64,
    base: u64,
    next: u64,
    recvmap: u64,
}

impl SeqState {
    /// `base` is the initial sequence number; `wide` selects 64-bit sequence
    /// numbers (CFX/proto 1) vs 32-bit (proto 0).
    pub fn new(base: u64, do_replay: bool, do_sequence: bool, wide: bool) -> Self {
        SeqState {
            do_replay,
            do_sequence,
            seqmask: if wide { u64::MAX } else { u32::MAX as u64 },
            base,
            next: 0,
            recvmap: 0,
        }
    }

    /// Record receipt of `seq` and report the MIT supplementary status.
    pub fn check(&mut self, seq: u64) -> SeqStatus {
        if !self.do_replay && !self.do_sequence {
            return SeqStatus::Complete;
        }
        let rel = seq.wrapping_sub(self.base) & self.seqmask;
        if rel >= self.next {
            let offset = rel - self.next;
            if offset >= 64 {
                self.recvmap = 1;
            } else {
                self.recvmap = (self.recvmap << (offset + 1)) | 1;
            }
            self.next = (rel + 1) & self.seqmask;
            return if offset > 0 && self.do_sequence {
                SeqStatus::Gap
            } else {
                SeqStatus::Complete
            };
        }
        let offset = self.next - rel;
        if offset > 64 {
            return if self.do_sequence {
                SeqStatus::Unseq
            } else {
                SeqStatus::Old
            };
        }
        let bit = 1u64 << (offset - 1);
        if self.do_replay && (self.recvmap & bit) != 0 {
            return SeqStatus::Duplicate;
        }
        self.recvmap |= bit;
        if self.do_sequence {
            SeqStatus::Unseq
        } else {
            SeqStatus::Complete
        }
    }
}

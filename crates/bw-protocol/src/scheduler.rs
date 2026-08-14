//! Deficit Round Robin (DRR) priority scheduler for QUIC stream multiplexing.
//!
//! Implements the stream priority weights from the BLACKWING transport spec:
//!
//! | Stream | Content                 | Priority weight       |
//! |--------|-------------------------|-----------------------|
//! | 0      | Control / migration     | Strict (always first) |
//! | 1      | Keyboard input          | 6                     |
//! | 2      | Mouse / pointer         | 5                     |
//! | 3      | Audio                   | 3                     |
//! | 4      | *(not listed in spec)*  | 4 (interpolated)      |
//! | 5      | Clipboard               | 2                     |
//! | 6      | Video frames            | 1                     |
//!
//! Stream 0 is a strict-priority queue: it always drains before any DRR
//! stream. Streams 1–6 are served with Deficit Round Robin: each stream is
//! credited `weight × quantum` bytes once per round and may send while its
//! front packet fits in its remaining deficit; unused credit carries over into
//! the next round, so a stream that cannot fill its quantum is not penalized.

use std::collections::VecDeque;
use thiserror::Error;

/// Number of logical streams the scheduler multiplexes (0–6).
pub const NUM_STREAMS: usize = 7;

/// Number of DRR-weighted streams (1–6); stream 0 is strict priority.
const NUM_DRR_STREAMS: usize = NUM_STREAMS - 1;

/// Default DRR quantum in bytes.
pub const DEFAULT_QUANTUM: u64 = 1500;

/// Default per-stream priority weights, indexed by stream ID.
///
/// Stream 0 is strict priority (its weight is unused by DRR). Stream 4 is not
/// listed in the transport spec and is assigned an interpolated weight of 4.
pub const DEFAULT_WEIGHTS: [u64; NUM_STREAMS] = [0, 6, 5, 3, 4, 2, 1];

/// Errors produced by the [`DrrScheduler`].
#[derive(Debug, Error, PartialEq, Eq)]
pub enum SchedulerError {
    /// The stream ID is outside the valid 0–6 range.
    #[error("Invalid stream ID: {0}")]
    InvalidStreamId(u8),
}

/// Deficit Round Robin scheduler for QUIC stream multiplexing.
#[derive(Debug, Clone)]
pub struct DrrScheduler {
    queues: [VecDeque<Vec<u8>>; NUM_STREAMS],
    deficits: [u64; NUM_STREAMS],
    weights: [u64; NUM_STREAMS],
    quantum: u64,
    /// Position of the stream currently taking its DRR turn (0–5 → stream 1–6).
    cursor: usize,
    /// Cursor position at the start of the current round.
    round_start: usize,
    /// Number of completed scheduling rounds.
    round: u64,
    /// Round in which each stream last received its credit.
    credited_round: [u64; NUM_STREAMS],
}

impl DrrScheduler {
    /// Creates a scheduler with the spec's default weights and quantum.
    pub fn new() -> Self {
        Self::with_quantum(DEFAULT_QUANTUM)
    }

    /// Creates a scheduler with the spec's default weights and a custom quantum.
    pub fn with_quantum(quantum: u64) -> Self {
        Self {
            queues: std::array::from_fn(|_| VecDeque::new()),
            deficits: [0; NUM_STREAMS],
            weights: DEFAULT_WEIGHTS,
            quantum,
            cursor: 0,
            round_start: 0,
            round: 0,
            credited_round: [u64::MAX; NUM_STREAMS],
        }
    }

    /// Enqueues a payload on the given logical stream.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError::InvalidStreamId`] if `stream_id` is outside
    /// the valid 0–6 range.
    pub fn enqueue(&mut self, stream_id: u8, data: Vec<u8>) -> Result<(), SchedulerError> {
        let idx = self.stream_index(stream_id)?;
        self.queues[idx].push_back(data);
        Ok(())
    }

    /// Dequeues the next payload according to the priority schedule.
    ///
    /// Stream 0 (control) is always served first. Otherwise streams 1–6 are
    /// served with Deficit Round Robin: a stream keeps its turn while its
    /// front packet fits in its deficit, then the cursor advances to the next
    /// stream; when the cursor completes a circuit the round advances and each
    /// non-empty stream is credited `weight × quantum` bytes on its next turn.
    /// Returns `None` when all queues are empty.
    pub fn dequeue_next(&mut self) -> Option<(u8, Vec<u8>)> {
        // Strict priority: the control stream always drains first.
        if let Some(data) = self.queues[0].pop_front() {
            return Some((0, data));
        }

        loop {
            let s = self.cursor + 1;

            if !self.queues[s].is_empty() {
                // Credit this stream once per round.
                if self.credited_round[s] != self.round {
                    self.deficits[s] += self.weights[s] * self.quantum;
                    self.credited_round[s] = self.round;
                }
                let front_len = self.queues[s].front().map_or(0, Vec::len) as u64;
                if front_len <= self.deficits[s] {
                    let data = self.queues[s].pop_front()?;
                    self.deficits[s] -= front_len;
                    return Some((s as u8, data));
                }
                // Front packet too large for the remaining deficit: the deficit
                // carries over and the turn moves to the next stream.
            } else {
                // Inactive streams hold no deficit.
                self.deficits[s] = 0;
            }

            // This stream's turn is over: advance to the next DRR stream.
            self.cursor = (self.cursor + 1) % NUM_DRR_STREAMS;

            // A full circuit closes the round; streams are re-credited when
            // their turn next comes up.
            if self.cursor == self.round_start {
                self.round += 1;
                self.round_start = self.cursor;
            }

            if self.queues[1..].iter().all(VecDeque::is_empty) {
                return None;
            }
        }
    }

    /// Returns whether every stream queue is empty.
    pub fn is_empty(&self) -> bool {
        self.queues.iter().all(VecDeque::is_empty)
    }

    /// Returns the number of queued payloads on the given stream.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError::InvalidStreamId`] if `stream_id` is outside
    /// the valid 0–6 range.
    pub fn queue_depth(&self, stream_id: u8) -> Result<usize, SchedulerError> {
        Ok(self.queues[self.stream_index(stream_id)?].len())
    }

    /// Returns the current deficit of the given stream.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError::InvalidStreamId`] if `stream_id` is outside
    /// the valid 0–6 range.
    pub fn deficit(&self, stream_id: u8) -> Result<u64, SchedulerError> {
        Ok(self.deficits[self.stream_index(stream_id)?])
    }

    /// Returns the number of completed scheduling rounds.
    pub fn round(&self) -> u64 {
        self.round
    }

    fn stream_index(&self, stream_id: u8) -> Result<usize, SchedulerError> {
        let idx = stream_id as usize;
        if idx >= NUM_STREAMS {
            return Err(SchedulerError::InvalidStreamId(stream_id));
        }
        Ok(idx)
    }
}

impl Default for DrrScheduler {
    fn default() -> Self {
        Self::new()
    }
}

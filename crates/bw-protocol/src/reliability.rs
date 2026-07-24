//! Reliable delivery subsystem.
//!
//! Provides sequence tracking, sliding window flow control, retransmissions,
//! duplicate filtering, and ordered assembly.

use crate::error::ProtocolError;
use serde::{Deserialize, Serialize};

/// Represents a monotonic sequence identifier for reliable delivery tracking.
#[derive(
    Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize,
)]
pub struct SequenceNumber(pub u64);

impl SequenceNumber {
    /// Returns the next sequence number in wrapped sequence space.
    pub fn next(&self) -> Self {
        Self(self.0.wrapping_add(1))
    }
}

/// An acknowledgment frame indicating received sequences.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AckFrame {
    /// The base sequence number being acknowledged.
    pub acked_seq: SequenceNumber,
    /// A selective acknowledgment bitmask representing previously received offsets.
    pub ack_bits: u64,
}

/// A reliability envelope wrapping user payload data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReliableFrame {
    /// The unique sequence number of the frame.
    pub seq: SequenceNumber,
    /// The payload bytes.
    pub payload: Vec<u8>,
}

/// The state of an active frame delivery attempt.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum DeliveryState {
    /// The frame has been sent and is awaiting an ACK.
    Pending,
    /// The frame has been acknowledged.
    Acked,
    /// The frame delivery attempt timed out.
    TimedOut,
}

/// Configuration policy managing RTO timeouts and retry limits.
#[derive(Debug, Clone, Copy)]
pub struct TimeoutPolicy {
    /// The Retransmission Timeout duration.
    pub rto: std::time::Duration,
    /// The maximum number of retry attempts before giving up.
    pub max_retransmissions: u32,
}

/// Tracking entry inside the sender's retransmission queue.
#[derive(Debug, Clone)]
pub struct RetransmissionEntry {
    /// The wrapped reliable frame.
    pub frame: ReliableFrame,
    /// The timestamp when the frame was sent or retransmitted.
    pub sent_at: std::time::Instant,
    /// The number of times this frame has been retransmitted.
    pub retransmissions: u32,
    /// The current delivery state.
    pub state: DeliveryState,
}

/// A sliding window managing outgoing sequence space.
#[derive(Debug, Clone)]
pub struct SlidingWindow {
    base: SequenceNumber,
    next_seq: SequenceNumber,
    window_size: u32,
}

impl SlidingWindow {
    /// Creates a new `SlidingWindow` with the specified size.
    pub fn new(window_size: u32) -> Self {
        Self {
            base: SequenceNumber(0),
            next_seq: SequenceNumber(0),
            window_size,
        }
    }

    /// Returns the number of slots available in the sending window.
    pub fn window_available(&self) -> u32 {
        let unacked = self.next_seq.0.saturating_sub(self.base.0);
        (self.window_size as u64).saturating_sub(unacked) as u32
    }
}

/// Sliding window filter mapping recently received sequences to filter duplicates.
#[derive(Debug, Default, Clone)]
pub struct DuplicateFilter {
    max_received: u64,
    received_mask: u64,
}

impl DuplicateFilter {
    /// Creates a new empty `DuplicateFilter`.
    pub fn new() -> Self {
        Self {
            max_received: 0,
            received_mask: 0,
        }
    }

    /// Checks if a sequence is a duplicate and tracks it.
    ///
    /// # Returns
    ///
    /// `true` if the sequence is a duplicate or too old, otherwise `false`.
    pub fn check_and_track(&mut self, seq: SequenceNumber) -> bool {
        let val = seq.0;
        if val <= self.max_received {
            let diff = self.max_received - val;
            if diff >= 64 {
                return true;
            }
            let bit = 1 << diff;
            if (self.received_mask & bit) != 0 {
                true
            } else {
                self.received_mask |= bit;
                false
            }
        } else {
            let diff = val - self.max_received;
            if diff >= 64 {
                self.received_mask = 1;
            } else {
                self.received_mask = (self.received_mask << diff) | 1;
            }
            self.max_received = val;
            false
        }
    }
}

/// Buffers out-of-order received frames and reassembles them sequentially.
#[derive(Debug, Default, Clone)]
pub struct OrderedAssembler {
    next_expected: SequenceNumber,
    buffer: std::collections::BTreeMap<SequenceNumber, ReliableFrame>,
}

impl OrderedAssembler {
    /// Creates a new empty `OrderedAssembler`.
    pub fn new() -> Self {
        Self {
            next_expected: SequenceNumber(0),
            buffer: std::collections::BTreeMap::new(),
        }
    }

    /// Inserts a frame into the reassembly buffer if it is relevant.
    pub fn insert(&mut self, frame: ReliableFrame) {
        if frame.seq >= self.next_expected {
            self.buffer.insert(frame.seq, frame);
        }
    }

    /// Returns the next expected sequence number.
    pub fn next_expected(&self) -> SequenceNumber {
        self.next_expected
    }

    /// Assembles and drains all contiguous ready payloads.
    pub fn assemble(&mut self) -> Vec<Vec<u8>> {
        let mut ready = Vec::new();
        while let Some(frame) = self.buffer.remove(&self.next_expected) {
            ready.push(frame.payload);
            self.next_expected = self.next_expected.next();
        }
        ready
    }
}

/// Coordinates reliable frame transmission, sliding window, and timeouts.
#[derive(Debug, Clone)]
pub struct ReliableSender {
    window: SlidingWindow,
    queue: Vec<RetransmissionEntry>,
    policy: TimeoutPolicy,
}

impl ReliableSender {
    /// Creates a new `ReliableSender` governed by the timeout policy.
    pub fn new(window_size: u32, policy: TimeoutPolicy) -> Self {
        Self {
            window: SlidingWindow::new(window_size),
            queue: Vec::new(),
            policy,
        }
    }

    /// Prepares and enqueues a new payload for sending.
    pub fn send(&mut self, payload: Vec<u8>) -> Result<ReliableFrame, ProtocolError> {
        if self.window.window_available() == 0 {
            return Err(ProtocolError::WindowFull);
        }

        let seq = self.window.next_seq;
        self.window.next_seq = seq.next();

        let frame = ReliableFrame { seq, payload };
        let entry = RetransmissionEntry {
            frame: frame.clone(),
            sent_at: std::time::Instant::now(),
            retransmissions: 0,
            state: DeliveryState::Pending,
        };
        self.queue.push(entry);

        Ok(frame)
    }

    /// Processes an incoming acknowledgment frame.
    pub fn ack(&mut self, ack: &AckFrame) -> Result<(), ProtocolError> {
        self.mark_delivered(ack.acked_seq);

        for i in 0..64 {
            if (ack.ack_bits & (1 << i)) != 0 {
                let bit_seq = SequenceNumber(ack.acked_seq.0.wrapping_sub(i + 1));
                self.mark_delivered(bit_seq);
            }
        }

        // Slide window base
        while !self.queue.is_empty() {
            if self.queue[0].state == DeliveryState::Acked {
                self.window.base = self.queue[0].frame.seq.next();
                self.queue.remove(0);
            } else {
                break;
            }
        }

        Ok(())
    }

    /// Marks a specific sequence number as successfully delivered.
    pub fn mark_delivered(&mut self, seq: SequenceNumber) {
        if let Some(entry) = self.queue.iter_mut().find(|e| e.frame.seq == seq) {
            entry.state = DeliveryState::Acked;
        }
    }

    /// Evaluates outstanding attempts against the timeout policy, returning timed out sequences.
    pub fn mark_timeout(&mut self, now: std::time::Instant) -> Vec<SequenceNumber> {
        let mut timed_out = Vec::new();
        for entry in self.queue.iter_mut() {
            if entry.state == DeliveryState::Pending
                && now.saturating_duration_since(entry.sent_at) >= self.policy.rto
            {
                entry.state = DeliveryState::TimedOut;
                timed_out.push(entry.frame.seq);
            }
        }
        timed_out
    }

    /// Reschedules timed-out frames for retransmission.
    pub fn retransmit(&mut self, now: std::time::Instant) -> Vec<ReliableFrame> {
        let mut frames_to_send = Vec::new();
        for entry in self.queue.iter_mut() {
            if entry.state == DeliveryState::TimedOut {
                if entry.retransmissions < self.policy.max_retransmissions {
                    entry.retransmissions += 1;
                    entry.sent_at = now;
                    entry.state = DeliveryState::Pending;
                    frames_to_send.push(entry.frame.clone());
                } else {
                    // Permanently timed out (retry budget exhausted)
                }
            }
        }
        frames_to_send
    }

    /// Returns the number of slots available in the sending window base.
    pub fn window_available(&self) -> u32 {
        self.window.window_available()
    }

    /// Returns the count of pending active frame entries.
    pub fn queue_depth(&self) -> usize {
        self.queue
            .iter()
            .filter(|e| e.state == DeliveryState::Pending || e.state == DeliveryState::TimedOut)
            .count()
    }

    /// Exposes a copy list of all unacknowledged pending frames.
    pub fn pending_frames(&self) -> Vec<ReliableFrame> {
        self.queue
            .iter()
            .filter(|e| e.state == DeliveryState::Pending || e.state == DeliveryState::TimedOut)
            .map(|e| e.frame.clone())
            .collect()
    }
}

/// Receives, filters, and sequentially assembles incoming reliable frames.
#[derive(Debug, Default, Clone)]
pub struct ReliableReceiver {
    assembler: OrderedAssembler,
    filter: DuplicateFilter,
}

impl ReliableReceiver {
    /// Creates a new `ReliableReceiver`.
    pub fn new() -> Self {
        Self {
            assembler: OrderedAssembler::new(),
            filter: DuplicateFilter::new(),
        }
    }

    /// Processes an incoming reliable frame.
    ///
    /// Returns contiguous ordered payloads that are ready to be consumed,
    /// filtering duplicates and buffering out-of-order sequences.
    pub fn receive(&mut self, frame: ReliableFrame) -> Result<Vec<Vec<u8>>, ProtocolError> {
        if self.filter.check_and_track(frame.seq) {
            return Ok(Vec::new());
        }

        self.assembler.insert(frame);
        Ok(self.assembler.assemble())
    }

    /// Returns the next expected sequence number.
    pub fn next_expected(&self) -> SequenceNumber {
        self.assembler.next_expected()
    }
}

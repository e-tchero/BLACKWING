#![allow(missing_docs)] // Integration-test crate (repo convention)
#![allow(clippy::unwrap_used, clippy::expect_used)] // Test code may panic on failure (repo convention)
use bw_protocol::error::ProtocolError;
use bw_protocol::reliability::{
    AckFrame, DuplicateFilter, ReliableFrame, ReliableReceiver, ReliableSender, SequenceNumber,
    TimeoutPolicy,
};
use std::time::{Duration, Instant};

#[test]
fn test_sequence_increment() {
    let s0 = SequenceNumber(0);
    let s1 = s0.next();
    assert_eq!(s1, SequenceNumber(1));
    assert_eq!(s1.next(), SequenceNumber(2));
}

#[test]
fn test_sliding_window_limits_and_availability() {
    let policy = TimeoutPolicy {
        rto: Duration::from_millis(100),
        max_retransmissions: 3,
    };
    let mut sender = ReliableSender::new(4, policy);

    assert_eq!(sender.window_available(), 4);

    let f0 = sender.send(b"payload0".to_vec()).unwrap();
    let f1 = sender.send(b"payload1".to_vec()).unwrap();
    let f2 = sender.send(b"payload2".to_vec()).unwrap();
    let f3 = sender.send(b"payload3".to_vec()).unwrap();

    assert_eq!(f0.seq, SequenceNumber(0));
    assert_eq!(f1.seq, SequenceNumber(1));
    assert_eq!(f2.seq, SequenceNumber(2));
    assert_eq!(f3.seq, SequenceNumber(3));

    assert_eq!(sender.window_available(), 0);

    // Limit hit
    let res = sender.send(b"blocked".to_vec());
    assert_eq!(res.err(), Some(ProtocolError::WindowFull));
}

#[test]
fn test_ack_processing_and_window_sliding() {
    let policy = TimeoutPolicy {
        rto: Duration::from_millis(100),
        max_retransmissions: 3,
    };
    let mut sender = ReliableSender::new(4, policy);

    let _f0 = sender.send(b"p0".to_vec()).unwrap();
    let _f1 = sender.send(b"p1".to_vec()).unwrap();
    let _f2 = sender.send(b"p2".to_vec()).unwrap();

    assert_eq!(sender.window_available(), 1);
    assert_eq!(sender.queue_depth(), 3);

    // ACK f0
    let ack = AckFrame {
        acked_seq: SequenceNumber(0),
        ack_bits: 0,
    };
    sender.ack(&ack).unwrap();

    assert_eq!(sender.window_available(), 2);
    assert_eq!(sender.queue_depth(), 2);

    // ACK f2 selectively (f1 is not acked yet, window shouldn't slide past f1)
    let ack_selective = AckFrame {
        acked_seq: SequenceNumber(2),
        ack_bits: 0, // Not setting bit for f1 yet
    };
    sender.ack(&ack_selective).unwrap();

    assert_eq!(sender.window_available(), 2); // Still 2 because f1 blocks base sliding
    assert_eq!(sender.queue_depth(), 1); // Only f1 remains unacknowledged

    // Now ACK f1
    let ack_f1 = AckFrame {
        acked_seq: SequenceNumber(1),
        ack_bits: 0,
    };
    sender.ack(&ack_f1).unwrap();

    assert_eq!(sender.window_available(), 4); // Slides completely
    assert_eq!(sender.queue_depth(), 0);
}

#[test]
fn test_duplicate_rejection() {
    let mut filter = DuplicateFilter::new();

    // First receive -> valid
    assert!(!filter.check_and_track(SequenceNumber(0)));
    // Second receive -> duplicate
    assert!(filter.check_and_track(SequenceNumber(0)));

    assert!(!filter.check_and_track(SequenceNumber(10)));
    assert!(filter.check_and_track(SequenceNumber(10)));
    assert!(!filter.check_and_track(SequenceNumber(5)));
    assert!(filter.check_and_track(SequenceNumber(5)));

    // Duplicate detection window boundaries (too old sequence)
    assert!(filter.check_and_track(SequenceNumber(0)));
}

#[test]
fn test_ordered_delivery_and_out_of_order_buffering() {
    let mut receiver = ReliableReceiver::new();

    // Out of order frame f1 received first
    let f1 = ReliableFrame {
        seq: SequenceNumber(1),
        payload: b"p1".to_vec(),
    };
    let ready1 = receiver.receive(f1).unwrap();
    assert!(ready1.is_empty()); // Buffered, waiting for f0
    assert_eq!(receiver.next_expected(), SequenceNumber(0));

    // Frame f3 received out of order
    let f3 = ReliableFrame {
        seq: SequenceNumber(3),
        payload: b"p3".to_vec(),
    };
    let ready3 = receiver.receive(f3).unwrap();
    assert!(ready3.is_empty());

    // In-order frame f0 received
    let f0 = ReliableFrame {
        seq: SequenceNumber(0),
        payload: b"p0".to_vec(),
    };
    let ready0 = receiver.receive(f0).unwrap();
    // f0 and f1 are contiguous and should be released
    assert_eq!(ready0.len(), 2);
    assert_eq!(ready0[0], b"p0");
    assert_eq!(ready0[1], b"p1");
    assert_eq!(receiver.next_expected(), SequenceNumber(2));

    // Frame f2 received
    let f2 = ReliableFrame {
        seq: SequenceNumber(2),
        payload: b"p2".to_vec(),
    };
    let ready2 = receiver.receive(f2).unwrap();
    // f2 and f3 are now contiguous and should be released
    assert_eq!(ready2.len(), 2);
    assert_eq!(ready2[0], b"p2");
    assert_eq!(ready2[1], b"p3");
    assert_eq!(receiver.next_expected(), SequenceNumber(4));
}

#[test]
fn test_retransmission_scheduling_and_timeouts() {
    let policy = TimeoutPolicy {
        rto: Duration::from_millis(50),
        max_retransmissions: 2,
    };
    let mut sender = ReliableSender::new(4, policy);

    let start = Instant::now();
    let f0 = sender.send(b"p0".to_vec()).unwrap();

    assert_eq!(sender.queue_depth(), 1);
    assert_eq!(sender.pending_frames().len(), 1);

    // No timeout immediately
    let timed_out = sender.mark_timeout(start);
    assert!(timed_out.is_empty());

    // Trigger timeout after RTO
    let timeout_time = start + Duration::from_millis(60);
    let timed_out = sender.mark_timeout(timeout_time);
    assert_eq!(timed_out.len(), 1);
    assert_eq!(timed_out[0], f0.seq);

    // Retransmit
    let retransmitted = sender.retransmit(timeout_time);
    assert_eq!(retransmitted.len(), 1);
    assert_eq!(retransmitted[0].seq, f0.seq);

    // Re-trigger timeout
    let second_timeout = timeout_time + Duration::from_millis(60);
    let timed_out = sender.mark_timeout(second_timeout);
    assert_eq!(timed_out.len(), 1);

    // Retransmit (hits max retry budget of 2)
    let retransmitted = sender.retransmit(second_timeout);
    assert_eq!(retransmitted.len(), 1);

    // Re-trigger third timeout
    let third_timeout = second_timeout + Duration::from_millis(60);
    let timed_out = sender.mark_timeout(third_timeout);
    assert_eq!(timed_out.len(), 1);

    // Try to retransmit again, should be empty because retry budget is exhausted
    let retransmitted = sender.retransmit(third_timeout);
    assert!(retransmitted.is_empty());
}

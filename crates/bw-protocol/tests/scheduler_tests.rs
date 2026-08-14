//! Integration tests for the Deficit Round Robin priority scheduler.

#![allow(clippy::unwrap_used, clippy::expect_used)]
#![allow(missing_docs)]

use bw_protocol::scheduler::{DrrScheduler, SchedulerError, DEFAULT_QUANTUM};

#[test]
fn test_stream_0_always_dequeues_first() {
    let mut sched = DrrScheduler::new();

    // Control data on stream 0 must come out before any DRR stream, even
    // though it was enqueued after stream 1 data.
    sched.enqueue(1, vec![1u8; 64]).unwrap();
    sched.enqueue(0, vec![0u8; 64]).unwrap();

    let (id, data) = sched.dequeue_next().unwrap();
    assert_eq!(id, 0);
    assert_eq!(data, vec![0u8; 64]);

    let (id, _) = sched.dequeue_next().unwrap();
    assert_eq!(id, 1);
}

#[test]
fn test_drr_higher_weight_gets_more_bytes() {
    let quantum = DEFAULT_QUANTUM;
    let mut sched = DrrScheduler::with_quantum(quantum);

    // Equal-size packets on stream 1 (weight 6) and stream 6 (weight 1).
    // Stream 1 is credited 6×1500 = 9000 bytes per round, stream 6 gets 1500.
    // Use packets smaller than the quantum so the ratio is exact.
    let packet = [0xABu8; 100];
    for _ in 0..100 {
        sched.enqueue(1, packet.to_vec()).unwrap();
        sched.enqueue(6, packet.to_vec()).unwrap();
    }

    // Drain the first complete round: each stream serves exactly its credit.
    let mut bytes = [0u64; 7];
    let round_before = sched.round();
    while let Some((id, data)) = sched.dequeue_next() {
        if sched.round() != round_before {
            // Belongs to the next round; stop counting.
            break;
        }
        bytes[id as usize] += data.len() as u64;
    }

    // Stream 1 (weight 6) got 6× the bytes of stream 6 (weight 1).
    assert_eq!(bytes[1], 6 * quantum);
    assert_eq!(bytes[6], quantum);
    assert_eq!(bytes[1], 6 * bytes[6]);
}

#[test]
fn test_deficit_carries_over() {
    let quantum = DEFAULT_QUANTUM;
    let mut sched = DrrScheduler::with_quantum(quantum);

    // A single packet larger than one round's credit for stream 1 (9000).
    // Stream 1 cannot serve it in the first round, so the deficit must carry
    // over and the packet is served once accumulated credit is sufficient.
    let big_packet = vec![0xEEu8; (2 * 9000 - 500) as usize];
    sched.enqueue(1, big_packet.clone()).unwrap();

    let round_before = sched.round();
    let (id, data) = sched.dequeue_next().unwrap();
    assert_eq!(id, 1);
    assert_eq!(data, big_packet);
    // Serving required crossing at least one round boundary: the deficit was
    // carried over rather than dropped.
    assert!(sched.round() > round_before);
    assert!(sched.is_empty());
}

#[test]
fn test_empty_streams_are_skipped() {
    let mut sched = DrrScheduler::new();

    // Only stream 3 and stream 5 have data; streams 1, 2, 4, 6 are empty and
    // must be skipped without blocking service.
    sched.enqueue(3, vec![3u8; 32]).unwrap();
    sched.enqueue(5, vec![5u8; 32]).unwrap();

    let mut got = Vec::new();
    while let Some((id, data)) = sched.dequeue_next() {
        got.push((id, data));
    }

    assert_eq!(got.len(), 2);
    assert!(got.iter().any(|(id, _)| *id == 3));
    assert!(got.iter().any(|(id, _)| *id == 5));
    assert!(sched.is_empty());
}

#[test]
fn test_all_streams_eventually_dequeue() {
    let mut sched = DrrScheduler::new();

    // Seed every DRR stream with data; every stream must eventually be served.
    for stream in 1..=6u8 {
        sched.enqueue(stream, vec![stream; 64]).unwrap();
    }

    let mut served = [false; 7];
    while let Some((id, _)) = sched.dequeue_next() {
        served[id as usize] = true;
    }

    for stream in 1..=6 {
        assert!(served[stream as usize], "stream {stream} was never served");
    }
    assert!(sched.is_empty());
}

#[test]
fn test_invalid_stream_id_rejected() {
    let mut sched = DrrScheduler::new();
    assert_eq!(
        sched.enqueue(7, vec![0u8; 1]),
        Err(SchedulerError::InvalidStreamId(7))
    );
    assert_eq!(
        sched.queue_depth(200),
        Err(SchedulerError::InvalidStreamId(200))
    );
    assert_eq!(
        sched.deficit(255),
        Err(SchedulerError::InvalidStreamId(255))
    );
}

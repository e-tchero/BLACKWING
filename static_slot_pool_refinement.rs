#![deny(clippy::unwrap_used, clippy::expect_used)]

use std::cell::UnsafeCell;
use std::sync::atomic::{AtomicUsize, AtomicU64, Ordering};
use zeroize::Zeroize;
use crate::BwError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZeroizePolicy { Never, OnRelease }

/// ABA protection via 64-bit tagged indices.
#[repr(transparent)]
struct TaggedIndex(u64);

impl TaggedIndex {
    const GEN_MASK: u64 = 0xFFFF_0000_0000_0000;
    const IDX_MASK: u64 = 0x0000_FFFF_FFFF_FFFF;

    fn new(gen: u16, idx: usize) -> Self {
        Self(((gen as u64) << 48) | (idx as u64 & Self::IDX_MASK))
    }
    fn generation(&self) -> u16 { (self.0 >> 48) as u16 }
    fn index(&self) -> usize { (self.0 & Self::IDX_MASK) as usize }
}

/// A production-grade memory pool with const-generic slot sizing.
pub struct StaticSlotPool<const SLOT_SIZE: usize, const POOL_SIZE: usize> {
    memory: Box<[UnsafeCell<[u8; SLOT_SIZE]>]>,
    nodes: Box<[UnsafeCell<AtomicUsize>]>,
    head: AtomicU64,
    policy: ZeroizePolicy,
    // Metrics
    pub successful_checkouts: AtomicUsize,
    pub pool_exhaustion: AtomicUsize,
}

#[must_use]
pub struct PoolGuard<'a, const SLOT_SIZE: usize, const POOL_SIZE: usize> {
    pool: &'a StaticSlotPool<SLOT_SIZE, POOL_SIZE>,
    index: usize,
}

impl<'a, const SLOT_SIZE: usize, const POOL_SIZE: usize> PoolGuard<'a, SLOT_SIZE, POOL_SIZE> {
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        debug_assert!(self.index < POOL_SIZE);
        unsafe { &mut *self.pool.memory[self.index].get() }
    }
}

impl<'a, const SLOT_SIZE: usize, const POOL_SIZE: usize> Drop for PoolGuard<'a, SLOT_SIZE, POOL_SIZE> {
    fn drop(&mut self) {
        if matches!(self.pool.policy, ZeroizePolicy::OnRelease) {
            self.as_mut_slice().zeroize();
        }
        self.pool.release(self.index);
    }
}

impl<const SLOT_SIZE: usize, const POOL_SIZE: usize> StaticSlotPool<SLOT_SIZE, POOL_SIZE> {
    fn release(&self, index: usize) {
        let mut current_head = TaggedIndex(self.head.load(Ordering::Acquire));
        loop {
            // Update node links: Acquire synchronizes with Release in checkout()
            unsafe { (*self.nodes[index].get()).store(current_head.index(), Ordering::Relaxed); }
            
            let new_head = TaggedIndex::new(current_head.generation().wrapping_add(1), index);
            
            // Release: Publishes the node back to the stack head
            match self.head.compare_exchange_weak(
                current_head.0, new_head.0,
                Ordering::AcqRel, Ordering::Acquire
            ) {
                Ok(_) => break,
                Err(actual) => current_head = TaggedIndex(actual),
            }
        }
    }
}
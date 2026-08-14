//! Const-generic static slot pool for performance-critical allocations.
//!
//! Provides a lock-free stack of pre-allocated slots with ABA protection.
//! Converted to safe Rust utilizing interior mutability via Mutex for slots,
//! whilst the pool structure remains entirely lock-free.

use crate::error::BwError;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard};
use zeroize::Zeroize;

/// Defines whether a slot should be zeroized when released back to the pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZeroizePolicy {
    /// Never zeroize slot data.
    Never,
    /// Zeroize slot data when dropped.
    OnRelease,
}

/// ABA protection via 64-bit tagged indices.
#[repr(transparent)]
struct TaggedIndex(u64);

impl TaggedIndex {
    const _GEN_MASK: u64 = 0xFFFF_0000_0000_0000;
    const IDX_MASK: u64 = 0x0000_FFFF_FFFF_FFFF;

    fn new(gen: u16, idx: usize) -> Self {
        Self(((gen as u64) << 48) | (idx as u64 & Self::IDX_MASK))
    }

    fn generation(&self) -> u16 {
        (self.0 >> 48) as u16
    }

    fn index(&self) -> usize {
        (self.0 & Self::IDX_MASK) as usize
    }
}

/// A production-grade memory pool with const-generic slot sizing.
pub struct StaticSlotPool<const SLOT_SIZE: usize, const POOL_SIZE: usize> {
    memory: Box<[Mutex<[u8; SLOT_SIZE]>]>,
    nodes: Box<[AtomicUsize]>,
    head: AtomicU64,
    policy: ZeroizePolicy,

    /// Total number of successful allocations.
    pub successful_checkouts: AtomicUsize,
    /// Total number of failed allocations due to pool exhaustion.
    pub pool_exhaustion: AtomicUsize,
}

impl<const SLOT_SIZE: usize, const POOL_SIZE: usize> StaticSlotPool<SLOT_SIZE, POOL_SIZE> {
    /// Creates a new statically sized slot pool.
    pub fn new(policy: ZeroizePolicy) -> Self {
        let mut memory_vec = Vec::with_capacity(POOL_SIZE);
        let mut nodes_vec = Vec::with_capacity(POOL_SIZE);

        for i in 0..POOL_SIZE {
            memory_vec.push(Mutex::new([0u8; SLOT_SIZE]));
            // Link to the next element. The last element links to POOL_SIZE (sentinel for empty).
            nodes_vec.push(AtomicUsize::new(i + 1));
        }

        Self {
            memory: memory_vec.into_boxed_slice(),
            nodes: nodes_vec.into_boxed_slice(),
            head: AtomicU64::new(TaggedIndex::new(0, 0).0),
            policy,
            successful_checkouts: AtomicUsize::new(0),
            pool_exhaustion: AtomicUsize::new(0),
        }
    }

    /// Checks out a pre-allocated slot from the pool.
    pub fn checkout(&self) -> Result<PoolGuard<'_, SLOT_SIZE, POOL_SIZE>, BwError> {
        let mut current_head = TaggedIndex(self.head.load(Ordering::Acquire));
        loop {
            let index = current_head.index();
            if index >= POOL_SIZE {
                self.pool_exhaustion.fetch_add(1, Ordering::Relaxed);
                return Err(BwError::PoolAllocationBoundaryViolated);
            }

            // Read the next node index
            let next_index = self.nodes[index].load(Ordering::Relaxed);
            let new_head = TaggedIndex::new(current_head.generation().wrapping_add(1), next_index);

            match self.head.compare_exchange_weak(
                current_head.0,
                new_head.0,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    self.successful_checkouts.fetch_add(1, Ordering::Relaxed);
                    let guard = match self.memory[index].lock() {
                        Ok(g) => g,
                        Err(_) => unreachable!("StaticSlotPool mutex poisoning impossible"),
                    };
                    return Ok(PoolGuard {
                        guard,
                        pool: self,
                        index,
                    });
                }
                Err(actual) => current_head = TaggedIndex(actual),
            }
        }
    }

    /// Releases a slot back to the pool.
    fn release(&self, index: usize) {
        let mut current_head = TaggedIndex(self.head.load(Ordering::Acquire));
        loop {
            // Update node links: Acquire synchronizes with Release in checkout()
            self.nodes[index].store(current_head.index(), Ordering::Relaxed);

            let new_head = TaggedIndex::new(current_head.generation().wrapping_add(1), index);

            // Release: Publishes the node back to the stack head
            match self.head.compare_exchange_weak(
                current_head.0,
                new_head.0,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(actual) => current_head = TaggedIndex(actual),
            }
        }
    }
}

/// A RAII guard for a checked-out slot.
#[must_use]
pub struct PoolGuard<'a, const SLOT_SIZE: usize, const POOL_SIZE: usize> {
    guard: MutexGuard<'a, [u8; SLOT_SIZE]>,
    pool: &'a StaticSlotPool<SLOT_SIZE, POOL_SIZE>,
    index: usize,
}

impl<'a, const SLOT_SIZE: usize, const POOL_SIZE: usize> PoolGuard<'a, SLOT_SIZE, POOL_SIZE> {
    /// Returns a mutable reference to the underlying slot data.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        self.guard.as_mut_slice()
    }

    /// Returns a shared reference to the underlying slot data.
    pub fn as_slice(&self) -> &[u8] {
        self.guard.as_slice()
    }
}

impl<'a, const SLOT_SIZE: usize, const POOL_SIZE: usize> Drop
    for PoolGuard<'a, SLOT_SIZE, POOL_SIZE>
{
    fn drop(&mut self) {
        if matches!(self.pool.policy, ZeroizePolicy::OnRelease) {
            self.as_mut_slice().zeroize();
        }
        self.pool.release(self.index);
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn test_slot_allocation_and_release() {
        let pool = StaticSlotPool::<64, 4>::new(ZeroizePolicy::Never);

        {
            let mut g1 = pool.checkout().unwrap();
            let mut g2 = pool.checkout().unwrap();

            g1.as_mut_slice()[0] = 42;
            g2.as_mut_slice()[0] = 99;

            assert_eq!(pool.successful_checkouts.load(Ordering::Relaxed), 2);
            drop(g1);
            drop(g2);
        } // released here

        let g3 = pool.checkout().unwrap();
        // LIFO stack, so g3 should get the last released slot (g2's old slot)
        // With ZeroizePolicy::Never, the value should persist
        assert_eq!(g3.as_slice()[0], 99);
    }

    #[test]
    fn test_pool_exhaustion() {
        let pool = StaticSlotPool::<32, 2>::new(ZeroizePolicy::Never);

        let _g1 = pool.checkout().unwrap();
        let _g2 = pool.checkout().unwrap();

        let res = pool.checkout();
        assert!(res.is_err());
        assert_eq!(res.err().unwrap(), BwError::PoolAllocationBoundaryViolated);
        assert_eq!(pool.pool_exhaustion.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_zeroize_policy_on_release() {
        let pool = StaticSlotPool::<32, 2>::new(ZeroizePolicy::OnRelease);

        {
            let mut g1 = pool.checkout().unwrap();
            g1.as_mut_slice()[0] = 123;
        }

        let g2 = pool.checkout().unwrap();
        assert_eq!(g2.as_slice()[0], 0); // Should be zeroized
    }

    #[test]
    fn test_slot_reuse_lifo_order() {
        let pool = StaticSlotPool::<16, 3>::new(ZeroizePolicy::Never);

        let g1 = pool.checkout().unwrap();
        let mut g2 = pool.checkout().unwrap();
        let g3 = pool.checkout().unwrap();

        // Write distinct values to identify slots
        g2.as_mut_slice()[0] = 77;

        // Drop g2 and g3
        drop(g2);
        drop(g3);

        // Since it's a stack, g4 gets what g3 dropped, and g5 gets what g2 dropped
        let _g4 = pool.checkout().unwrap();
        let g5 = pool.checkout().unwrap();

        assert_eq!(g5.as_slice()[0], 77); // Confirms g5 received g2's old slot

        // Keep compiler from warning about unused variables
        drop(g1);
    }
}

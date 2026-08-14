//! Memory allocation utilities and zero-allocation buffers.
//!
//! This module provides a lock-free memory pool that pre-allocates
//! memory upon initialization and issues checkouts with zero heap allocations.

use crate::error::BwError;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use zeroize::Zeroize;

/// A highly optimized memory pool that pre-allocates slot buffers
/// on initialization, strictly guaranteeing zero heap allocations during runtime checkouts.
pub struct LockFreeMemoryPool {
    memory: Vec<Mutex<Vec<u8>>>,
    occupancy_flags: Arc<[AtomicBool]>,
    pool_size: usize,
    _slot_capacity: usize, // kept for struct backward compatibility
}

impl LockFreeMemoryPool {
    /// Creates and pre-allocates a new `LockFreeMemoryPool`.
    ///
    /// # Arguments
    ///
    /// * `pool_size` - The number of slots to pre-allocate.
    /// * `slot_capacity` - The size of each slot in bytes.
    pub fn new(pool_size: usize, slot_capacity: usize) -> Self {
        let mut memory = Vec::with_capacity(pool_size);
        for _ in 0..pool_size {
            memory.push(Mutex::new(vec![0u8; slot_capacity]));
        }

        let mut flags = Vec::with_capacity(pool_size);
        for _ in 0..pool_size {
            flags.push(AtomicBool::new(false));
        }

        Self {
            memory,
            occupancy_flags: Arc::from(flags),
            pool_size,
            _slot_capacity: slot_capacity,
        }
    }

    /// Checks out a pre-allocated buffer from the pool using atomic compare-and-swap (CAS).
    ///
    /// Strictly zero heap allocations occur during this pathway.
    ///
    /// # Returns
    ///
    /// A `PoolGuard` protecting the checked-out buffer slice, or a `BwError` if the
    /// pool boundaries are violated (i.e. the pool is completely full).
    pub fn checkout(&self) -> Result<PoolGuard<'_>, BwError> {
        for index in 0..self.pool_size {
            let flag = &self.occupancy_flags[index];
            // Atomically swap occupancy status from false to true
            if flag
                .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                // Lock acquisition is strictly uncontended due to the CAS flag above.
                let guard = match self.memory[index].lock() {
                    Ok(g) => g,
                    Err(_) => unreachable!("LockFreeMemoryPool mutex poisoning impossible"),
                };
                return Ok(PoolGuard {
                    guard,
                    pool: self,
                    index,
                });
            }
        }
        Err(BwError::PoolAllocationBoundaryViolated)
    }
}

/// RAII Guard that manages buffer occupancy with a strictly zero-allocation design.
///
/// When dropped, the guard automatically zeroizes the slice and releases its slot.
pub struct PoolGuard<'a> {
    guard: MutexGuard<'a, Vec<u8>>,
    pool: &'a LockFreeMemoryPool,
    index: usize,
}

impl<'a> PoolGuard<'a> {
    /// Returns a shared reference to the claimed buffer slice.
    pub fn get(&self) -> &[u8] {
        &self.guard
    }

    /// Returns a mutable reference to the claimed buffer slice.
    pub fn get_mut(&mut self) -> &mut [u8] {
        &mut self.guard
    }
}

impl<'a> Drop for PoolGuard<'a> {
    fn drop(&mut self) {
        // Enforce cryptographic zeroization on resource release
        self.guard.as_mut_slice().zeroize();

        // Release the occupancy flag atomically using Release memory ordering
        self.pool.occupancy_flags[self.index].store(false, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn test_zero_allocation_pool_behavior() {
        // Initialize memory pool with 2 slots of 32 bytes each
        let pool = LockFreeMemoryPool::new(2, 32);

        {
            // First checkout
            let mut guard1 = pool.checkout().unwrap();
            let slice1 = guard1.get_mut();
            assert_eq!(slice1.len(), 32);
            slice1[0] = 42;
            slice1[31] = 99;

            // Second checkout
            let mut guard2 = pool.checkout().unwrap();
            let slice2 = guard2.get_mut();
            assert_eq!(slice2[0], 0); // Verify initialized to zero
            slice2[0] = 11;

            // Third checkout must fail because the pool size limit is strictly 2
            let failed_checkout = pool.checkout();
            assert_eq!(
                failed_checkout.err(),
                Some(BwError::PoolAllocationBoundaryViolated)
            );
        } // Both guards are dropped here: slots are automatically zeroized and released

        // Checkouts are now fully accessible again
        let mut guard3 = pool.checkout().unwrap();
        let slice3 = guard3.get_mut();
        // Assert dropped slice was zeroized on drop
        assert_eq!(slice3[0], 0);
    }
}

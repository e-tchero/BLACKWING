//! Encryption pipeline for protocol frames.
//!
//! Integrates `bw-crypto` into the protocol layer to secure frames
//! before transmission.

use crate::codec::{decode_frame, encode_frame};
use crate::error::ProtocolError;
use crate::frame::OwnedProtocolFrame;
use bw_crypto::{decrypt_aead, encrypt_aead, hkdf_derive, SymmetricKey};
use serde::{Deserialize, Serialize};

/// Represents a deterministic, monotonic 96-bit initialization vector.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Nonce(pub [u8; 12]);

impl Nonce {
    /// Generates a new nonce from an epoch and a sequence counter.
    pub fn new(epoch: u32, counter: u64) -> Self {
        let mut bytes = [0u8; 12];
        bytes[0..4].copy_from_slice(&epoch.to_be_bytes());
        bytes[4..12].copy_from_slice(&counter.to_be_bytes());
        Self(bytes)
    }

    /// Extracts the epoch from the nonce.
    pub fn epoch(&self) -> u32 {
        u32::from_be_bytes([self.0[0], self.0[1], self.0[2], self.0[3]])
    }

    /// Extracts the sequence counter from the nonce.
    pub fn counter(&self) -> u64 {
        let mut counter_bytes = [0u8; 8];
        counter_bytes.copy_from_slice(&self.0[4..12]);
        u64::from_be_bytes(counter_bytes)
    }
}

/// Represents a 128-bit authentication tag.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthenticationTag(pub [u8; 16]);

/// Represents an encrypted protocol frame wrapper.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedFrame {
    /// The cryptographic epoch of the keys used.
    pub epoch: u32,
    /// The unique monotonic nonce.
    pub nonce: Nonce,
    /// The encrypted frame data.
    pub ciphertext: Vec<u8>,
    /// The authentication tag verifying integrity.
    pub tag: AuthenticationTag,
}

impl EncryptedFrame {
    /// Serializes the encrypted frame to CBOR format.
    pub fn serialize(&self) -> Result<Vec<u8>, ProtocolError> {
        let mut buffer = Vec::new();
        ciborium::into_writer(self, &mut buffer).map_err(|_| ProtocolError::SerializationError)?;
        Ok(buffer)
    }

    /// Maximum serialized size of an EncryptedFrame (4 MiB).
    pub const MAX_DESER_SIZE: usize = 4 * 1024 * 1024;

    /// Deserializes an encrypted frame from CBOR bytes.
    pub fn deserialize(bytes: &[u8]) -> Result<Self, ProtocolError> {
        // C3 FIX: reject oversized payloads before CBOR allocation.
        if bytes.len() > Self::MAX_DESER_SIZE {
            return Err(ProtocolError::OversizedPayload(
                bytes.len(),
                Self::MAX_DESER_SIZE,
            ));
        }
        ciborium::from_reader(bytes).map_err(|_| ProtocolError::DeserializationError)
    }
}

use zeroize::{Zeroize, ZeroizeOnDrop};

/// Active session keys for frame transmission and reception.
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct SessionKeys {
    /// Key used for encryption.
    pub send_key: SymmetricKey,
    /// Key used for decryption.
    pub recv_key: SymmetricKey,
    /// Current cryptographic key epoch.
    pub epoch: u32,
}

/// Replay protection using a sliding window for sequence numbers.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ReplayProtection {
    max_counter: u64,
    received_mask: u64,
}

impl ReplayProtection {
    /// Creates a new `ReplayProtection` filter.
    pub fn new() -> Self {
        Self {
            max_counter: 0,
            received_mask: 0,
        }
    }

    /// Tracks a received nonce and rejects replay attempts.
    pub fn protect_replay(&mut self, nonce: &Nonce) -> Result<(), ProtocolError> {
        let val = nonce.counter();
        if val <= self.max_counter {
            let diff = self.max_counter - val;
            if diff >= 64 {
                return Err(ProtocolError::ReplayDetected);
            }
            let bit = 1 << diff;
            if (self.received_mask & bit) != 0 {
                Err(ProtocolError::ReplayDetected)
            } else {
                self.received_mask |= bit;
                Ok(())
            }
        } else {
            let diff = val - self.max_counter;
            if diff >= 64 {
                self.received_mask = 1;
            } else {
                self.received_mask = (self.received_mask << diff) | 1;
            }
            self.max_counter = val;
            Ok(())
        }
    }
}

/// The policy defining key rotation triggers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyRotationPolicy {
    /// Key rotation triggered manually.
    Manual,
    /// Key rotation triggered every N frames.
    Counter(u64),
}

/// Encryptor responsible for securing outbound frames.
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct FrameEncryptor {
    send_key: SymmetricKey,
    epoch: u32,
    counter: u64,
}

impl FrameEncryptor {
    /// Creates a new `FrameEncryptor`.
    pub fn new(send_key: SymmetricKey, epoch: u32) -> Self {
        Self {
            send_key,
            epoch,
            counter: 0,
        }
    }

    /// Encrypts an owned protocol frame.
    pub fn encrypt_frame(
        &mut self,
        frame: &OwnedProtocolFrame,
    ) -> Result<EncryptedFrame, ProtocolError> {
        let plaintext = encode_frame(&frame.borrow());
        let nonce = self.generate_nonce();
        let (ciphertext, tag_bytes) = encrypt_aead(&self.send_key, &nonce.0, &plaintext, &[])
            .map_err(|_| ProtocolError::EncryptionError)?;

        self.counter += 1;

        Ok(EncryptedFrame {
            epoch: self.epoch,
            nonce,
            ciphertext,
            tag: AuthenticationTag(tag_bytes),
        })
    }

    /// Generates the next monotonic nonce.
    pub fn generate_nonce(&self) -> Nonce {
        Nonce::new(self.epoch, self.counter)
    }

    /// Rotates the send key using HKDF.
    pub fn rotate_keys(&mut self) -> Result<(), ProtocolError> {
        self.epoch += 1;
        let info = format!("epoch-{}", self.epoch);
        let new_key = hkdf_derive(None, &self.send_key.0, Some(info.as_bytes()))
            .map_err(|_| ProtocolError::EncryptionError)?;
        self.send_key = new_key;
        self.counter = 0;
        Ok(())
    }

    /// Returns the current key epoch.
    pub fn current_key_epoch(&self) -> u32 {
        self.epoch
    }
}

/// Decryptor responsible for verifying and restoring inbound frames.
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct FrameDecryptor {
    recv_key: SymmetricKey,
    epoch: u32,
    #[zeroize(skip)]
    replay_protection: ReplayProtection,
}

impl FrameDecryptor {
    /// Creates a new `FrameDecryptor`.
    pub fn new(recv_key: SymmetricKey, epoch: u32) -> Self {
        Self {
            recv_key,
            epoch,
            replay_protection: ReplayProtection::new(),
        }
    }

    /// Decrypts an encrypted frame.
    ///
    /// If the frame's epoch is exactly one ahead of the current epoch,
    /// the decryptor automatically rotates its key before decryption.
    /// This keeps the receiver synchronized with a sender that rotates
    /// at the configured Counter threshold.
    pub fn decrypt_frame(
        &mut self,
        encrypted: &EncryptedFrame,
    ) -> Result<OwnedProtocolFrame, ProtocolError> {
        if encrypted.epoch == self.epoch {
            // ── Same epoch: normal path ──────────────────────────────
            self.replay_protection.protect_replay(&encrypted.nonce)?;

            let plaintext = decrypt_aead(
                &self.recv_key,
                &encrypted.nonce.0,
                &encrypted.ciphertext,
                &encrypted.tag.0,
                &[],
            )
            .map_err(|_| ProtocolError::EncryptionError)?;

            let borrowed_frame = decode_frame(&plaintext)?;
            Ok(OwnedProtocolFrame {
                header: borrowed_frame.header,
                payload: borrowed_frame.payload.to_vec(),
            })
        } else if encrypted.epoch == self.epoch + 1 {
            // ── Next epoch: derive candidate key, authenticate FIRST ──
            //
            // Compute the key we WOULD have after rotation, but do NOT
            // mutate self yet.  Only commit the epoch/key/replay-window
            // transition after AEAD authentication succeeds, so a forged
            // frame can never advance receiver state.
            let candidate_epoch = self.epoch + 1;
            let info = format!("epoch-{}", candidate_epoch);
            let candidate_key = hkdf_derive(None, &self.recv_key.0, Some(info.as_bytes()))
                .map_err(|_| ProtocolError::EncryptionError)?;

            // Attempt AEAD with the candidate key (fresh replay window).
            let mut candidate_replay = ReplayProtection::new();
            candidate_replay.protect_replay(&encrypted.nonce)?;

            let plaintext = decrypt_aead(
                &candidate_key,
                &encrypted.nonce.0,
                &encrypted.ciphertext,
                &encrypted.tag.0,
                &[],
            )
            .map_err(|_| ProtocolError::EncryptionError)?;

            // ── Authentication succeeded: commit state transition ─────
            self.epoch = candidate_epoch;
            self.recv_key = candidate_key;
            self.replay_protection = candidate_replay;

            let borrowed_frame = decode_frame(&plaintext)?;
            Ok(OwnedProtocolFrame {
                header: borrowed_frame.header,
                payload: borrowed_frame.payload.to_vec(),
            })
        } else {
            // ── Wrong epoch: reject immediately, no state change ──────
            Err(ProtocolError::EncryptionError)
        }
    }

    /// Verifies the authentication tag of an encrypted frame without full decryption.
    pub fn verify_tag(&self, encrypted: &EncryptedFrame) -> Result<(), ProtocolError> {
        // NOTE: verify_tag is read-only (no &mut self), so it cannot auto-rotate.
        // It checks only the current epoch. Callers that need to verify across
        // epoch boundaries should rotate first, then verify.
        if encrypted.epoch != self.epoch {
            return Err(ProtocolError::EncryptionError);
        }

        let _ = decrypt_aead(
            &self.recv_key,
            &encrypted.nonce.0,
            &encrypted.ciphertext,
            &encrypted.tag.0,
            &[],
        )
        .map_err(|_| ProtocolError::EncryptionError)?;

        Ok(())
    }

    /// Rotates the receive key using HKDF.
    pub fn rotate_keys(&mut self) -> Result<(), ProtocolError> {
        self.epoch += 1;
        let info = format!("epoch-{}", self.epoch);
        let new_key = hkdf_derive(None, &self.recv_key.0, Some(info.as_bytes()))
            .map_err(|_| ProtocolError::EncryptionError)?;
        self.recv_key = new_key;
        self.replay_protection = ReplayProtection::new();
        Ok(())
    }

    /// Protects against replay attacks using the internal replay protection sliding window.
    pub fn protect_replay(&mut self, nonce: &Nonce) -> Result<(), ProtocolError> {
        self.replay_protection.protect_replay(nonce)
    }

    /// Returns the current key epoch.
    pub fn current_key_epoch(&self) -> u32 {
        self.epoch
    }
}

/// Pipeline context coordinating frame encryption, decryption, and key lifetime policies.
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct EncryptionContext {
    /// Active encryptor.
    pub encryptor: FrameEncryptor,
    /// Active decryptor.
    pub decryptor: FrameDecryptor,
    /// Active key rotation policy.
    #[zeroize(skip)]
    pub rotation_policy: KeyRotationPolicy,
}

impl EncryptionContext {
    /// Creates a new `EncryptionContext` with the specified policy.
    pub fn new(keys: SessionKeys, rotation_policy: KeyRotationPolicy) -> Self {
        Self {
            encryptor: FrameEncryptor::new(keys.send_key.clone(), keys.epoch),
            decryptor: FrameDecryptor::new(keys.recv_key.clone(), keys.epoch),
            rotation_policy,
        }
    }

    /// Encrypts an outbound frame, triggering automatic key rotation if scheduled by the policy.
    pub fn encrypt_frame(
        &mut self,
        frame: &OwnedProtocolFrame,
    ) -> Result<EncryptedFrame, ProtocolError> {
        let encrypted = self.encryptor.encrypt_frame(frame)?;

        if let KeyRotationPolicy::Counter(limit) = self.rotation_policy {
            if self.encryptor.counter >= limit {
                self.rotate_keys()?;
            }
        }

        Ok(encrypted)
    }

    /// Decrypts and validates an inbound encrypted frame.
    pub fn decrypt_frame(
        &mut self,
        encrypted: &EncryptedFrame,
    ) -> Result<OwnedProtocolFrame, ProtocolError> {
        self.decryptor.decrypt_frame(encrypted)
    }

    /// Rotates both transmission and reception session keys.
    pub fn rotate_keys(&mut self) -> Result<(), ProtocolError> {
        self.encryptor.rotate_keys()?;
        self.decryptor.rotate_keys()?;
        Ok(())
    }

    /// Returns the current key epoch.
    pub fn current_key_epoch(&self) -> u32 {
        self.encryptor.current_key_epoch()
    }
}

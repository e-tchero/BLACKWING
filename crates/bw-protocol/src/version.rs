//! Protocol versioning schemas.

use serde::{Deserialize, Serialize};

/// Represents a protocol version in PROJECT BLACKWING.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ProtocolVersion {
    /// Major version number.
    pub major: u8,
    /// Minor version number.
    pub minor: u8,
}

/// The current protocol version of this library.
pub const CURRENT_VERSION: ProtocolVersion = ProtocolVersion { major: 1, minor: 0 };

impl ProtocolVersion {
    /// Creates a new `ProtocolVersion`.
    pub const fn new(major: u8, minor: u8) -> Self {
        Self { major, minor }
    }

    /// Checks if this version is compatible with another version.
    ///
    /// Compatibility rule: major versions must be equal.
    pub fn is_compatible_with(&self, other: &Self) -> bool {
        self.major == other.major
    }
}

impl From<ProtocolVersion> for u16 {
    fn from(v: ProtocolVersion) -> Self {
        ((v.major as u16) << 8) | (v.minor as u16)
    }
}

impl From<u16> for ProtocolVersion {
    fn from(val: u16) -> Self {
        Self {
            major: (val >> 8) as u8,
            minor: (val & 0xFF) as u8,
        }
    }
}

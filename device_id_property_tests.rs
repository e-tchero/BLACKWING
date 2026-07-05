#![deny(clippy::unwrap_used, clippy::expect_used)]

use proptest::prelude::*;
use proptest::test_runner::TestCaseError;
use std::str::FromStr;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

// Assuming these types are exposed from our target library
use bw_crypto::identity::{
    DeviceId, DeviceIdParseError, DEVICE_ID_BYTES, DEVICE_ID_PREFIX, DEVICE_ID_STR_LEN
};

prop_compose! {
    /// Generates an arbitrary 32-byte array representing a SHA-256 digest.
    fn any_digest()(bytes in any::<[u8; 32]>()) -> [u8; 32] {
        bytes
    }
}

// =========================================================================
// Property-Based Test Definitions
// =========================================================================

proptest! {
    // ---------------------------------------------------------------------
    // Group 1: Round-Trip Invariants
    // ---------------------------------------------------------------------
    #[test]
    fn prop_roundtrip_display_to_from_str(digest in any_digest()) -> Result<(), TestCaseError> {
        let original_id = DeviceId::from_digest(digest);
        let serialized = original_id.to_string();

        // Round-trip parse: Display -> FromStr == Original
        let parsed_id = DeviceId::from_str(&serialized)
            .map_err(|e| TestCaseError::fail(format!("{e:?}")))?;
        prop_assert_eq!(parsed_id, original_id);
        Ok(())
    }

    #[test]
    fn prop_roundtrip_from_str_to_display(digest in any_digest()) -> Result<(), TestCaseError> {
        let canonical_id = DeviceId::from_digest(digest);
        let text_repr = canonical_id.to_string();

        // Round-trip serialization: FromStr -> Display == Canonical Text Representation
        let parsed_id = DeviceId::from_str(&text_repr)
            .map_err(|e| TestCaseError::fail(format!("{e:?}")))?;
        prop_assert_eq!(parsed_id.to_string(), text_repr);
        Ok(())
    }

    // ---------------------------------------------------------------------
    // Group 2: Formatting Invariants
    // ---------------------------------------------------------------------
    #[test]
    fn prop_formatting_invariants(digest in any_digest()) -> Result<(), TestCaseError> {
        let id = DeviceId::from_digest(digest);
        let s = id.to_string();

        // Invariant: Prefix is exactly "bw-id-"
        prop_assert!(s.starts_with(DEVICE_ID_PREFIX));

        // Invariant: Total length is exactly 70 characters
        prop_assert_eq!(s.len(), DEVICE_ID_STR_LEN);

        // Invariant: Text contains only lowercase hexadecimal characters (0-9, a-f) and the prefix
        let body = &s[DEVICE_ID_PREFIX.len()..];
        prop_assert!(body.chars().all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)));

        // Invariant: No whitespace is allowed
        prop_assert!(!s.contains(char::is_whitespace));
        Ok(())
    }

    // ---------------------------------------------------------------------
    // Group 3: Parser Rejection of Malformed Inputs
    // ---------------------------------------------------------------------
    #[test]
    fn prop_reject_invalid_prefixes(s in r"[a-z]{5}-[0-9a-f]{64}") -> Result<(), TestCaseError> {
        // Guard: Prevent accidentally matching the valid "bw-id-" prefix
        if !s.starts_with(DEVICE_ID_PREFIX) {
            let result = DeviceId::from_str(&s);
            prop_assert_eq!(result.err(), Some(DeviceIdParseError::InvalidPrefix));
        }
        Ok(())
    }

    #[test]
    fn prop_reject_invalid_lengths(digest in any_digest(), len_delta in -10i32..10i32) -> Result<(), TestCaseError> {
        if len_delta != 0 {
            let id = DeviceId::from_digest(digest);
            let s = id.to_string();
            let mut modified_s = s.clone();

            if len_delta > 0 {
                modified_s.push_str(&"a".repeat(len_delta as usize));
            } else {
                let target_len = (DEVICE_ID_STR_LEN as i32).saturating_add(len_delta);
                if target_len > 0 && (target_len as usize) < modified_s.len() {
                    modified_s.truncate(target_len as usize);
                } else {
                    modified_s.clear();
                }
            }

            let result = DeviceId::from_str(&modified_s);
            prop_assert_eq!(result.err(), Some(DeviceIdParseError::InvalidLength));
        }
        Ok(())
    }

    #[test]
    fn prop_reject_uppercase_hexadecimal(digest in any_digest(), char_idx in 0..64usize) -> Result<(), TestCaseError> {
        let id = DeviceId::from_digest(digest);
        let s = id.to_string();
        let mut modified_bytes = s.into_bytes();
        let target_idx = DEVICE_ID_PREFIX.len() + char_idx;

        let c = modified_bytes[target_idx];
        // Mutate only if the target is an alphabetic hex character ('a' through 'f')
        prop_assume!((b'a'..=b'f').contains(&c));

        modified_bytes[target_idx] = c.to_ascii_uppercase();

        let modified_str = String::from_utf8(modified_bytes)
            .map_err(|e| TestCaseError::fail(format!("{e:?}")))?;
        let result = DeviceId::from_str(&modified_str);
        prop_assert_eq!(result.err(), Some(DeviceIdParseError::UppercaseNotAllowed));
        Ok(())
    }

    #[test]
    fn prop_reject_invalid_hex_digits(digest in any_digest(), char_idx in 0..64usize) -> Result<(), TestCaseError> {
        let id = DeviceId::from_digest(digest);
        let s = id.to_string();
        let mut modified_bytes = s.into_bytes();
        let target_idx = DEVICE_ID_PREFIX.len() + char_idx;

        // Force-insert a non-hexadecimal character
        modified_bytes[target_idx] = b'g';

        let modified_str = String::from_utf8(modified_bytes)
            .map_err(|e| TestCaseError::fail(format!("{e:?}")))?;
        let result = DeviceId::from_str(&modified_str);
        prop_assert_eq!(result.err(), Some(DeviceIdParseError::InvalidHex));
    }

    // ---------------------------------------------------------------------
    // Group 4: Strict Equality Invariants
    // ---------------------------------------------------------------------
    #[test]
    fn prop_equality_by_binary_value(a in any_digest(), b in any_digest()) {
        let id_a = DeviceId::from_digest(a);
        let id_b = DeviceId::from_digest(b);

        if a == b {
            prop_assert_eq!(id_a, id_b);
        } else {
            prop_assert_ne!(id_a, id_b);
        }
    }

    // ---------------------------------------------------------------------
    // Group 5: Hash & Determinism Consistency
    // ---------------------------------------------------------------------
    #[test]
    fn prop_hash_consistency(a in any_digest(), b in any_digest()) {
        let id_a = DeviceId::from_digest(a);
        let id_b = DeviceId::from_digest(b);

        if id_a == id_b {
            let mut hasher_a = DefaultHasher::new();
            let mut hasher_b = DefaultHasher::new();
            id_a.hash(&mut hasher_a);
            id_b.hash(&mut hasher_b);
            
            let hash_a = hasher_a.finish();
            let hash_b = hasher_b.finish();
            prop_assert_eq!(hash_a, hash_b);

            // Clone / Copy invariant check (Copying must never alter the hash)
            let id_clone = id_a;
            let mut hasher_clone = DefaultHasher::new();
            id_clone.hash(&mut hasher_clone);
            let hash_clone = hasher_clone.finish();
            prop_assert_eq!(hash_a, hash_clone);
        }
    }

    #[test]
    fn prop_display_determinism_and_idempotence(digest in any_digest()) -> Result<(), TestCaseError> {
        let id = DeviceId::from_digest(digest);
        let s1 = id.to_string();
        let s2 = id.to_string();
        prop_assert_eq!(s1, s2);

        // Parser Idempotency: parse(display(parse(display(x)))) == parse(display(x))
        let parsed1 = DeviceId::from_str(&s1)
            .map_err(|e| TestCaseError::fail(format!("{e:?}")))?;
        
        let s3 = parsed1.to_string();
        let parsed2 = DeviceId::from_str(&s3)
            .map_err(|e| TestCaseError::fail(format!("{e:?}")))?;
        prop_assert_eq!(parsed1, parsed2);
        Ok(())
    }

    // ---------------------------------------------------------------------
    // Group 6: Byte API Invariants
    // ---------------------------------------------------------------------
    #[test]
    fn prop_byte_api_invariants(digest in any_digest()) {
        let id = DeviceId::from_digest(digest);

        // Invariant: as_bytes() length matches static schema rules
        prop_assert_eq!(id.as_bytes().len(), DEVICE_ID_BYTES);

        // Invariant: from_digest(x).as_bytes() == x
        prop_assert_eq!(id.as_bytes(), &digest);

        // Invariant: AsRef<[u8]> matches source bytes
        let as_ref_bytes: &[u8] = id.as_ref();
        prop_assert_eq!(as_ref_bytes, &digest[..]);

        // Invariant: AsRef<[u8; 32]> matches source bytes
        let as_ref_array: &[u8; 32] = id.as_ref();
        prop_assert_eq!(as_ref_array, &digest);
    }

    // ---------------------------------------------------------------------
    // Group 7: Parser Fuzzing
    // ---------------------------------------------------------------------
    #[test]
    fn prop_fuzz_parser_garbage(bytes in prop::collection::vec(any::<u8>(), 0..200)) -> Result<(), TestCaseError> {
        if let Ok(s) = String::from_utf8(bytes) {
            // Parser must never panic, overflow, or trigger memory leaks on un-trusted inputs
            if let Ok(id) = DeviceId::from_str(&s) {
                prop_assert_eq!(id.to_string(), s);
            }
        }
        Ok(())
    }

    // ---------------------------------------------------------------------
    // Group 8: Serialization Invariants (JSON Encodings)
    // ---------------------------------------------------------------------
    #[test]
    fn prop_serde_json_roundtrip(digest in any_digest()) -> Result<(), TestCaseError> {
        let id = DeviceId::from_digest(digest);

        // Serialize to JSON (Must yield textual representation "bw-id-...")
        let serialized = serde_json::to_string(&id)
            .map_err(|e| TestCaseError::fail(format!("{e:?}")))?;

        // Enforce the layout is serialized as a strict JSON string with proper quotes
        let expected_json = format!("\"{}\"", id);
        prop_assert_eq!(serialized, expected_json);

        // Deserialize back and assert matching equality
        let deserialized: DeviceId = serde_json::from_str(&serialized)
            .map_err(|e| TestCaseError::fail(format!("{e:?}")))?;
        prop_assert_eq!(deserialized, id);

        // Verify JSON string-to-type parsing mirrors FromStr exactly
        let json_from_raw_string = format!("\"{}\"", id.to_string());
        let decoded_json: DeviceId = serde_json::from_str(&json_from_raw_string)
            .map_err(|e| TestCaseError::fail(format!("{e:?}")))?;
        prop_assert_eq!(decoded_json, id);
        Ok(())
    }
}
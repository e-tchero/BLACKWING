#![allow(missing_docs)]

use bw_core::error::BwError;

#[test]
fn test_error_formatting() {
    let err = BwError::AntiDebugViolation;
    assert_eq!(
        format!("{}", err),
        "[BW-5002] Anti-Debugging Violation: Debugger attached, process terminated"
    );
}

// ... (imports)

impl Signature {
    /// Constant-time equality check for Signature.
    pub fn ct_eq(&self, other: &Self) -> bool {
        subtle::ConstantTimeEq::ct_eq(&self.0, &other.0).into()
    }
}

// Any future secret-bearing types (e.g., SharedSecret) will follow 
// this exact pattern, keeping the logic local and the trait count at zero.
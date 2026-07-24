/// Internal trait to ensure secret-bearing types handle their own comparison.
pub(crate) trait ConstantTimeHelper {
    fn ct_eq(&self, other: &Self) -> bool;
}
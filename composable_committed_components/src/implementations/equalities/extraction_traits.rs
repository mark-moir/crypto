/// Traits for deriving a commitment key (or other helper) from a component's common setup.
pub trait ExtractCommitmentKey<T> {
    fn extract_commitment_key(&self) -> T;
}

pub trait ExtractCommitment<T> {
    fn extract_commitment(&self) -> T;
}

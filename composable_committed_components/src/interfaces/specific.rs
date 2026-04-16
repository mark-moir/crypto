//! Core traits and data structures that describe a composable committed
//! component (CCC).  Each backend implements the `ComposableCommittedComponent`
//! trait to provide the concrete cryptographic primitive (setup, commitment,
//! proof, verification).  Higher-level layers can then orchestrate those
//! implementations without depending on the concrete types.
//!
//! The interfaces here are intentionally immutable and clone-friendly so that
//! backends can be stored in dynamic registries (e.g., `DynamicComposableCommittedComponent`).

use crate::{error::CCCResult, types::*};
use ark_ec::AffineRepr;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use dock_crypto_utils::{
    commitment::PedersenCommitmentKey,
    transcript::{new_merlin_transcript, Transcript},
};
use std::clone::Clone;

/// Contract implemented by every committed component backend.  The associated
/// types describe the concrete objects produced/consumed by the
/// backend (e.g., setup arguments, commitment outputs, proof arguments).
pub trait SpecificComposableCommittedComponent {
    type ValueType: Clone + CanonicalDeserialize + CanonicalSerialize;
    type RandomnessType: Clone + CanonicalDeserialize + CanonicalSerialize;
    type CommitmentType: CanonicalDeserialize + CanonicalSerialize;
    type CommonSetupArgs;
    type CommonSetup;
    type CommitArgs;
    type CommitmentHandle;
    type ProveArgs;
    type Proof;
    type VerifyArgs;
    type VerifyReturn;
    fn common_setup(args: &Self::CommonSetupArgs) -> CCCResult<Self::CommonSetup>;
    fn commit(
        args: &Self::CommonSetup,
        setup: &Self::CommitArgs,
    ) -> CCCResult<(
        std::collections::HashMap<
            Self::CommitmentHandle,
            ValueAndRandomness<Self::ValueType, Self::RandomnessType>,
        >,
        std::collections::HashMap<Self::CommitmentHandle, Self::CommitmentType>,
    )>;
    fn prove(
        setup: &Self::CommonSetup,
        values: &std::collections::HashMap<
            Self::CommitmentHandle,
            ValueAndRandomness<Self::ValueType, Self::RandomnessType>,
        >,
        commitments: &std::collections::HashMap<Self::CommitmentHandle, Self::CommitmentType>,
        args: &Self::ProveArgs,
    ) -> CCCResult<Self::Proof>;

    fn verify(
        setup: &Self::CommonSetup,
        commitments: &std::collections::HashMap<Self::CommitmentHandle, Self::CommitmentType>,
        args: &Self::VerifyArgs,
        proof: &Self::Proof,
    ) -> CCCResult<()>;
}

pub trait SpecificEqualityOfCommittedValues<
    Component1: SpecificComposableCommittedComponent,
    Component2: SpecificComposableCommittedComponent,
> {
    type Proof: Clone;
    fn prove(
        setup_1: &Component1::CommonSetup,
        setup_2: &Component2::CommonSetup,
        vr_1: &ValueAndRandomness<Component1::ValueType, Component1::RandomnessType>,
        vr_2: &ValueAndRandomness<Component2::ValueType, Component2::RandomnessType>,
        comm_1: &Component1::CommitmentType,
        comm_2: &Component2::CommitmentType,
    ) -> CCCResult<Self::Proof>;
    fn verify(
        setup_1: &Component1::CommonSetup,
        setup_2: &Component2::CommonSetup,
        comm_1: &Component1::CommitmentType,
        comm_2: &Component2::CommitmentType,
        proof: &Self::Proof,
    ) -> CCCResult<()>;
}

/// This function provides a general way of complying with the requirement stated in the
/// documentation for ProofLargeWitness.new and ProofLargeWitness.verify (in eq_across_groups).
// That documentation says says: "This does not include the commitments, commitment key or any
// public parameters into the transcript.  The caller should ensure that they have been added
// before."
pub fn init_eq_prover<
    C1: Clone + CanonicalSerialize + AffineRepr,
    C2: Clone + CanonicalSerialize + AffineRepr,
    AdditionalPublicSetup: Clone + CanonicalSerialize,
>(
    commitment_key_group_1: &PedersenCommitmentKey<C1>,
    commitment_key_group_2: &PedersenCommitmentKey<C2>,
    additional_public_setup: &AdditionalPublicSetup,
    comm_group_1: &C1,
    comm_group_2: &C2,
) -> impl Transcript + Clone {
    let mut transcript = new_merlin_transcript(b"eq_transcript");
    transcript.append(b"commitment_key_group_1", commitment_key_group_1);
    transcript.append(b"commitment_key_group_2", commitment_key_group_2);
    transcript.append(b"additional_public_setup", additional_public_setup);
    transcript.append(b"commitment_group_1", comm_group_1);
    transcript.append(b"commitment_group_2", comm_group_2);

    transcript
}

use ark_secp256r1::{Affine, Fr};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use blake2::Blake2b512;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};

use bulletproofs_plus_plus::prelude::SetupParams as BppSetupParams;
use dock_crypto_utils::{
    commitment::PedersenCommitmentKey,
    randomized_mult_checker::RandomizedMultChecker,
    transcript::{new_merlin_transcript, Transcript},
};
use equality_across_groups::{
    ec::commitments::{PointCommitment, PointCommitmentWithOpening},
    pok_ecdsa_pubkey::{
        PoKEcdsaSigCommittedPublicKey, PoKEcdsaSigCommittedPublicKeyProtocol, TransformedEcdsaSig,
    },
    tom256::{Affine as Tom256Affine, Fr as Tom256Fr},
};
use kvac::bbs_sharp::ecdsa;

use crate::{
    impl_api_roundtrip_ark, impl_api_roundtrip_json,
    interfaces::SpecificComposableCommittedComponent,
    types::{api_types::*, ValueAndRandomness},
    CCCError, CCCResult, ComposableCommittedComponent,
};
use std::collections::HashMap;

#[derive(Clone, CanonicalDeserialize, CanonicalSerialize)]
pub struct ESVCPKCommonSetupArgs {
    pub tom_seed: Vec<u8>,
    pub secp_seed: Vec<u8>,
    pub bpp_seed: Vec<u8>,
}
impl_api_roundtrip_ark!(ESVCPKCommonSetupArgs => ApiCommonSetupArgs);

#[derive(Clone, CanonicalDeserialize, CanonicalSerialize)]
pub struct ESVCPKCommonSetup {
    pub comm_key_secp: PedersenCommitmentKey<Affine>,
    pub comm_key_tom: PedersenCommitmentKey<Tom256Affine>,
    pub base_for_bpp_proofs: u16,
    pub bpp_setup_params: BppSetupParams<Tom256Affine>,
}
impl_api_roundtrip_ark!(ESVCPKCommonSetup => ApiCommonSetup);

#[derive(CanonicalDeserialize, CanonicalSerialize)]
pub struct ESVCPKProverArgs {
    pub sig: ecdsa::Signature,
    pub ecdsa_challenge: Fr,
    // kept for convenience; we could reconstruct it from the commitment opening
    pub pk: Affine,
}
impl_api_roundtrip_ark!(ESVCPKProverArgs => ApiProveArgs);

#[derive(Clone, CanonicalDeserialize, CanonicalSerialize)]
pub struct ESVCPKProof {
    pub challenge_prover: Tom256Fr,
    // Included only for debugging: enables asserting that prover and verifier get same challenge
    pub ptom_proof: PoKEcdsaSigCommittedPublicKey,
}
impl_api_roundtrip_ark!(ESVCPKProof => ApiComponentProof);

#[derive(Clone, CanonicalDeserialize, CanonicalSerialize)]
pub struct ESVCPKVerifyArgs {
    pub ecdsa_challenge: Fr,
}
impl_api_roundtrip_ark!(ESVCPKVerifyArgs => ApiVerifyArgs);

#[derive(Clone, Deserialize, Serialize, Debug, PartialEq, Eq, Hash)]
pub enum ESVCPKCommitmentHandle {
    PkX,
    PkY,
}
impl_api_roundtrip_json!(ESVCPKCommitmentHandle => ApiCommitmentHandle);

#[derive(Clone, CanonicalDeserialize, CanonicalSerialize)]
pub struct ESVCPKCommitment(pub Tom256Affine);
impl_api_roundtrip_ark!(ESVCPKCommitment => ApiCommitment);

// This SpecificComposableCommittedComponent is built based on the pok_ecdsa_sig_comm_pubkey test in
// equality_across_groups.  It could probably be refined into two
// SpecificComposableCommittedComponent implementations (nodes), one for the secp256r1 curve and one
// for the Tom256 curve, and some SpecificEqualityOfCommittedValues implementations (edges) for
// proving equalities of various values committed on the two curves.  This would be significant work
// for the mostly-intellectual benefit of demonstrating the generality of the framework, which we do
// not consider worthwhile unless and until there is a need to use any of the finer grained nodes or
// edges for another purpose.
#[derive(Clone, CanonicalDeserialize, CanonicalSerialize)]
pub struct EcdsaSignCommittedPublicKey;

impl SpecificComposableCommittedComponent for EcdsaSignCommittedPublicKey {
    type ValueType = Tom256Fr;
    type RandomnessType = Tom256Fr;
    type CommitmentType = ESVCPKCommitment;
    type CommonSetupArgs = ESVCPKCommonSetupArgs;
    type CommonSetup = ESVCPKCommonSetup;
    type CommitArgs = Affine;
    type CommitmentHandle = ESVCPKCommitmentHandle;
    type ProveArgs = ESVCPKProverArgs;
    type Proof = ESVCPKProof;
    type VerifyArgs = ESVCPKVerifyArgs;
    type VerifyReturn = ();

    fn common_setup(args: &ESVCPKCommonSetupArgs) -> CCCResult<ESVCPKCommonSetup> {
        Ok(ecdsa_common_setup(args))
    }
    fn commit(
        setup_info: &ESVCPKCommonSetup,
        pk: &Affine,
    ) -> CCCResult<(
        HashMap<ESVCPKCommitmentHandle, ValueAndRandomness<Tom256Fr, Tom256Fr>>,
        HashMap<ESVCPKCommitmentHandle, ESVCPKCommitment>,
    )> {
        let mut rng = OsRng;
        let for_prover = PointCommitmentWithOpening::new(&mut rng, pk, &setup_info.comm_key_tom)
            .map_err(|e| CCCError::General(format!("failed to commit ECDSA key: {e:?}")))?;
        let for_verifier = for_prover.comm;

        let mut values = HashMap::new();
        values.insert(
            ESVCPKCommitmentHandle::PkX,
            ValueAndRandomness {
                value: for_prover.x,
                randomness: for_prover.r_x,
            },
        );
        values.insert(
            ESVCPKCommitmentHandle::PkY,
            ValueAndRandomness {
                value: for_prover.y,
                randomness: for_prover.r_y,
            },
        );

        let mut commitments = HashMap::new();
        commitments.insert(
            ESVCPKCommitmentHandle::PkX,
            ESVCPKCommitment(for_verifier.x),
        );
        commitments.insert(
            ESVCPKCommitmentHandle::PkY,
            ESVCPKCommitment(for_verifier.y),
        );

        Ok((values, commitments))
    }
    fn prove(
        setup: &ESVCPKCommonSetup,
        values_map: &HashMap<ESVCPKCommitmentHandle, ValueAndRandomness<Tom256Fr, Tom256Fr>>,
        commitments_map: &HashMap<ESVCPKCommitmentHandle, ESVCPKCommitment>,
        args: &ESVCPKProverArgs,
    ) -> CCCResult<ESVCPKProof> {
        // Transform signature
        let transformed_sig = TransformedEcdsaSig::new(&args.sig, args.ecdsa_challenge, args.pk)
            .map_err(|e| CCCError::General(format!("failed to transform signature: {e:?}")))?;
        transformed_sig
            .verify_prehashed(args.ecdsa_challenge, args.pk)
            .map_err(|e| CCCError::General(format!("invalid transformed signature: {e:?}")))?;

        let val_x = values_map
            .get(&ESVCPKCommitmentHandle::PkX)
            .ok_or_else(|| {
                CCCError::General("missing value/randomness for PkX commitment".to_string())
            })?;
        let val_y = values_map
            .get(&ESVCPKCommitmentHandle::PkY)
            .ok_or_else(|| {
                CCCError::General("missing value/randomness for PkY commitment".to_string())
            })?;

        let comm_x = commitments_map
            .get(&ESVCPKCommitmentHandle::PkX)
            .ok_or_else(|| CCCError::General("missing commitment for PkX".to_string()))?;
        let comm_y = commitments_map
            .get(&ESVCPKCommitmentHandle::PkY)
            .ok_or_else(|| CCCError::General("missing commitment for PkY".to_string()))?;

        let commitment_with_opening = PointCommitmentWithOpening::new_given_randomness_and_coords(
            val_x.value,
            val_y.value,
            val_x.randomness,
            val_y.randomness,
            &setup.comm_key_tom,
        );
        let commitment = PointCommitment {
            x: comm_x.0,
            y: comm_y.0,
        };

        let mut prover_transcript = new_merlin_transcript(b"test");
        prover_transcript.append(b"comm_key_secp", &setup.comm_key_secp);
        prover_transcript.append(b"comm_key_tom", &setup.comm_key_tom);
        prover_transcript.append(b"bpp_setup_params", &setup.bpp_setup_params);
        prover_transcript.append(b"comm_pk", &commitment);
        prover_transcript.append(b"message", &args.ecdsa_challenge);

        let mut rng = OsRng;

        let protocol = PoKEcdsaSigCommittedPublicKeyProtocol::<128>::init(
            &mut rng,
            transformed_sig,
            args.ecdsa_challenge,
            args.pk,
            commitment_with_opening.clone(),
            &setup.comm_key_secp,
            &setup.comm_key_tom,
        )
        .map_err(|e| CCCError::General(format!("failed to init PoK protocol: {e:?}")))?;
        protocol
            .challenge_contribution(&mut prover_transcript)
            .map_err(|e| {
                CCCError::General(format!(
                    "challenge contribution failed for prover transcript: {e:?}"
                ))
            })?;
        let challenge_prover = prover_transcript.challenge_scalar(b"challenge");
        let ptom_proof = protocol.gen_proof(&challenge_prover);
        Ok(ESVCPKProof {
            challenge_prover,
            ptom_proof,
        })
    }
    fn verify(
        setup: &ESVCPKCommonSetup,
        commitments_map: &HashMap<ESVCPKCommitmentHandle, ESVCPKCommitment>,
        args: &ESVCPKVerifyArgs,
        proof: &ESVCPKProof,
    ) -> CCCResult<()> {
        let commitment = PointCommitment {
            x: commitments_map
                .get(&ESVCPKCommitmentHandle::PkX)
                .ok_or_else(|| CCCError::General("missing commitment for PkX".to_string()))?
                .0,
            y: commitments_map
                .get(&ESVCPKCommitmentHandle::PkY)
                .ok_or_else(|| CCCError::General("missing commitment for PkY".to_string()))?
                .0,
        };
        let mut verifier_transcript = new_merlin_transcript(b"test");
        verifier_transcript.append(b"comm_key_secp", &setup.comm_key_secp);
        verifier_transcript.append(b"comm_key_tom", &setup.comm_key_tom);
        verifier_transcript.append(b"bpp_setup_params", &setup.bpp_setup_params);
        verifier_transcript.append(b"comm_pk", &commitment);
        verifier_transcript.append(b"message", &args.ecdsa_challenge);
        proof
            .ptom_proof
            .challenge_contribution(&mut verifier_transcript)
            .map_err(|e| {
                CCCError::General(format!(
                    "challenge contribution failed for verifier transcript: {e:?}"
                ))
            })?;

        let challenge_verifier = verifier_transcript.challenge_scalar(b"challenge");
        assert_eq!(proof.challenge_prover, challenge_verifier);

        let mut rng = OsRng;
        let mut checker_1 = RandomizedMultChecker::<Affine>::new_using_rng(&mut rng);
        let mut checker_2 = RandomizedMultChecker::<Tom256Affine>::new_using_rng(&mut rng);
        proof
            .ptom_proof
            .verify_using_randomized_mult_checker(
                args.ecdsa_challenge,
                commitment,
                &challenge_verifier,
                setup.comm_key_secp,
                setup.comm_key_tom,
                &mut checker_1,
                &mut checker_2,
            )
            .map_err(|e| {
                CCCError::General(format!("ECDSA commitment proof verification failed: {e:?}"))
            })?;
        Ok(())
    }
}
impl_api_roundtrip_ark!(Affine => ApiCommitArgs);

pub(in crate::implementations) const WITNESS_BIT_SIZE: usize = 64;
pub(in crate::implementations) const NUM_CHUNKS: usize = 4;
const BPP_BASE: u16 = 2;

pub fn ecdsa_common_setup(args: &ESVCPKCommonSetupArgs) -> ESVCPKCommonSetup {
    let comm_key_secp = PedersenCommitmentKey::<Affine>::new::<Blake2b512>(&args.secp_seed);
    let comm_key_tom = PedersenCommitmentKey::<Tom256Affine>::new::<Blake2b512>(&args.tom_seed);

    let mut bpp_setup_params =
        BppSetupParams::<Tom256Affine>::new_for_perfect_range_proof::<Blake2b512>(
            &args.bpp_seed,
            BPP_BASE,
            WITNESS_BIT_SIZE as u16,
            NUM_CHUNKS as u32,
        );
    bpp_setup_params.G = comm_key_tom.g;
    bpp_setup_params.H_vec[0] = comm_key_tom.h;
    ESVCPKCommonSetup {
        comm_key_secp,
        comm_key_tom,
        base_for_bpp_proofs: BPP_BASE,
        bpp_setup_params,
    }
}

pub fn esvcpk_component() -> ComposableCommittedComponent {
    ComposableCommittedComponent::from_specific_component::<EcdsaSignCommittedPublicKey>(
        "Proof of knowledge of an ECDSA signature on a known challenge that verifies against a committed public key",
        &["PkX", "PkY"],
    )
}

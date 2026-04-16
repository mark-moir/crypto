use ark_bls12_381::{Fr as BlsFr, G1Affine as BlsG1Affine};
use ark_ff::fields::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{vec::Vec, UniformRand};
use blake2::Blake2b512;
use rand_core::OsRng;
use std::collections::HashMap;

use bulletproofs_plus_plus::{
    range_proof_arbitrary_range::ProofArbitraryRange, setup::SetupParams,
};
use dock_crypto_utils::transcript::{new_merlin_transcript, Transcript};

use crate::{
    error::{CCCError, CCCResult},
    impl_api_roundtrip_ark,
    implementations::equalities::extraction_traits::ExtractCommitmentKey,
    interfaces::SpecificComposableCommittedComponent,
    types::{api_types::*, ValueAndRandomness},
    ComposableCommittedComponent,
};

/// Common setup arguments: number of bits and a transcript label. Base is fixed to 2.
#[derive(Clone, CanonicalDeserialize, CanonicalSerialize)]
pub struct RangeCheckBppCommonSetupArgs {
    pub num_bits: u16,
    pub label: Vec<u8>,
}
impl_api_roundtrip_ark!(RangeCheckBppCommonSetupArgs => ApiCommonSetupArgs);

/// Common setup stores the generated Bulletproofs++ parameters and the label.
#[derive(Clone, CanonicalDeserialize, CanonicalSerialize)]
pub struct RangeCheckBppCommonSetup {
    pub params: SetupParams<BlsG1Affine>,
    pub num_bits: u16,
    pub label: Vec<u8>,
}
impl_api_roundtrip_ark!(RangeCheckBppCommonSetup => ApiCommonSetup);

impl ExtractCommitmentKey<dock_crypto_utils::commitment::PedersenCommitmentKey<BlsG1Affine>>
    for RangeCheckBppCommonSetup
{
    fn extract_commitment_key(
        &self,
    ) -> dock_crypto_utils::commitment::PedersenCommitmentKey<BlsG1Affine> {
        dock_crypto_utils::commitment::PedersenCommitmentKey {
            g: self.params.G,
            h: self.params.H_vec[0],
        }
    }
}

#[derive(Clone, CanonicalDeserialize, CanonicalSerialize)]
pub struct RangeCheckBppCommitArgs {
    pub value: BlsFr,
}
impl_api_roundtrip_ark!(RangeCheckBppCommitArgs => ApiCommitArgs);

pub type ValueAndRandomnessBls = ValueAndRandomness<BlsFr, BlsFr>;

#[derive(Clone, CanonicalDeserialize, CanonicalSerialize)]
pub struct RangeCheckBppProveArgs {
    pub min: u64,
    pub max: u64,
    pub transcript_label: Option<Vec<u8>>,
}
impl_api_roundtrip_ark!(RangeCheckBppProveArgs => ApiProveArgs);

#[derive(Clone, CanonicalDeserialize, CanonicalSerialize)]
pub struct RangeCheckBppVerifyArgs {
    pub min: u64,
    pub max: u64,
    pub transcript_label: Option<Vec<u8>>,
}
impl_api_roundtrip_ark!(RangeCheckBppVerifyArgs => ApiVerifyArgs);

#[derive(Clone, CanonicalDeserialize, CanonicalSerialize)]
pub struct RangeCheckBppProof {
    pub proof: ProofArbitraryRange<BlsG1Affine>,
}
impl_api_roundtrip_ark!(RangeCheckBppProof => ApiComponentProof);

#[derive(Clone, Debug, CanonicalDeserialize, CanonicalSerialize, PartialEq, Eq, Hash)]
pub struct RangeCheckBppCommitmentHandle;
impl_api_roundtrip_ark!(RangeCheckBppCommitmentHandle => ApiCommitmentHandle);

#[derive(Clone, Debug, CanonicalDeserialize, CanonicalSerialize, PartialEq, Eq)]
pub struct RangeCheckBppCommitment(pub BlsG1Affine);
impl_api_roundtrip_ark!(RangeCheckBppCommitment => ApiCommitment);

pub struct RangeCheckBpp;

fn blsfr_to_u64(v: &BlsFr) -> CCCResult<u64> {
    let bigint = v.into_bigint();
    let limbs = bigint.as_ref();
    if limbs.is_empty() {
        return Err(CCCError::General("unexpected zero limbs".into()));
    }
    if limbs.len() > 1 && limbs[1..].iter().any(|&l| l != 0) {
        return Err(CCCError::General(
            "value does not fit into u64 for range proof".into(),
        ));
    }
    Ok(limbs[0])
}

fn build_transcript(label: &[u8], params: &SetupParams<BlsG1Affine>) -> impl Transcript + Clone {
    let mut t = new_merlin_transcript(b"range-check-bpp");
    t.append_message_without_static_label(b"label", label);
    t.append(b"setup", params);
    t
}

impl RangeCheckBpp {
    fn validate_bounds(min: u64, max: u64, num_bits: u16) -> CCCResult<()> {
        if min >= max {
            return Err(CCCError::General("min must be < max".into()));
        }
        let max_allowed: u128 = 1u128 << num_bits;
        if (max as u128) > max_allowed {
            return Err(CCCError::General("max exceeds num_bits bound".into()));
        }
        Ok(())
    }
}

impl SpecificComposableCommittedComponent for RangeCheckBpp {
    type ValueType = BlsFr;
    type RandomnessType = BlsFr;
    type CommitmentType = RangeCheckBppCommitment;
    type CommonSetupArgs = RangeCheckBppCommonSetupArgs;
    type CommonSetup = RangeCheckBppCommonSetup;
    type CommitArgs = RangeCheckBppCommitArgs;
    type CommitmentHandle = RangeCheckBppCommitmentHandle;
    type ProveArgs = RangeCheckBppProveArgs;
    type Proof = RangeCheckBppProof;
    type VerifyArgs = RangeCheckBppVerifyArgs;
    type VerifyReturn = ();

    fn common_setup(args: &RangeCheckBppCommonSetupArgs) -> CCCResult<RangeCheckBppCommonSetup> {
        if args.num_bits == 0 {
            return Err(CCCError::General("num_bits must be > 0".into()));
        }
        let params = SetupParams::<BlsG1Affine>::new_for_arbitrary_range_proof::<Blake2b512>(
            &args.label,
            2,
            args.num_bits,
            1,
        );
        Ok(RangeCheckBppCommonSetup {
            params,
            num_bits: args.num_bits,
            label: args.label.clone(),
        })
    }

    fn commit(
        setup: &RangeCheckBppCommonSetup,
        args: &RangeCheckBppCommitArgs,
    ) -> CCCResult<(
        HashMap<RangeCheckBppCommitmentHandle, ValueAndRandomnessBls>,
        HashMap<RangeCheckBppCommitmentHandle, RangeCheckBppCommitment>,
    )> {
        let value_u64 = blsfr_to_u64(&args.value)?;
        let r0 = BlsFr::rand(&mut OsRng);
        let commitment = setup.params.compute_pedersen_commitment(value_u64, &r0);
        let mut values = HashMap::new();
        values.insert(
            RangeCheckBppCommitmentHandle,
            ValueAndRandomness {
                value: args.value,
                randomness: r0,
            },
        );
        let mut commitments = HashMap::new();
        commitments.insert(
            RangeCheckBppCommitmentHandle,
            RangeCheckBppCommitment(commitment),
        );
        Ok((values, commitments))
    }

    fn prove(
        setup: &RangeCheckBppCommonSetup,
        values_map: &HashMap<RangeCheckBppCommitmentHandle, ValueAndRandomnessBls>,
        _commitments_map: &HashMap<RangeCheckBppCommitmentHandle, RangeCheckBppCommitment>,
        args: &RangeCheckBppProveArgs,
    ) -> CCCResult<RangeCheckBppProof> {
        RangeCheckBpp::validate_bounds(args.min, args.max, setup.num_bits)?;
        let vr = values_map
            .get(&RangeCheckBppCommitmentHandle)
            .ok_or_else(|| {
                CCCError::General("missing value/randomness for RangeCheckBpp commitment".into())
            })?;
        let value_u64 = blsfr_to_u64(&vr.value)?;
        if value_u64 < args.min || value_u64 >= args.max {
            return Err(CCCError::General("value is outside supplied bounds".into()));
        }

        let randomness = vec![vr.randomness, BlsFr::rand(&mut OsRng)];

        let label_owned = args
            .transcript_label
            .clone()
            .unwrap_or_else(|| setup.label.clone());
        let mut transcript = build_transcript(&label_owned, &setup.params);

        let proof = ProofArbitraryRange::new(
            &mut OsRng,
            setup.num_bits,
            vec![(value_u64, args.min, args.max)],
            randomness,
            setup.params.clone(),
            &mut transcript,
        )
        .map_err(|e| CCCError::General(format!("range proof creation failed: {:?}", e)))?;

        Ok(RangeCheckBppProof { proof })
    }

    fn verify(
        setup: &RangeCheckBppCommonSetup,
        commitments_map: &HashMap<RangeCheckBppCommitmentHandle, RangeCheckBppCommitment>,
        args: &RangeCheckBppVerifyArgs,
        proof: &RangeCheckBppProof,
    ) -> CCCResult<()> {
        RangeCheckBpp::validate_bounds(args.min, args.max, setup.num_bits)?;

        let comm = commitments_map
            .get(&RangeCheckBppCommitmentHandle)
            .ok_or_else(|| {
                CCCError::General("missing commitment for RangeCheckBpp verification".into())
            })?;

        // Check that the proof's derived commitment matches the supplied one.
        let c_and_c_alt = proof
            .proof
            .get_commitments_to_values_given_g(vec![(args.min, args.max)], &setup.params.G)
            .map_err(|e| CCCError::General(format!("commitment derivation failed: {:?}", e)))?;
        // Use the first commitment (constructed with randomness supplied as first entry) to match the provided commitment.
        if c_and_c_alt[0].0 != comm.0 {
            return Err(CCCError::General(
                "commitment mismatch between proof and provided commitment".into(),
            ));
        }

        let label_owned = args
            .transcript_label
            .clone()
            .unwrap_or_else(|| setup.label.clone());
        let mut transcript = build_transcript(&label_owned, &setup.params);
        proof
            .proof
            .verify(setup.num_bits, &setup.params, &mut transcript)
            .map_err(|e| CCCError::General(format!("range proof verification failed: {:?}", e)))
    }
}

pub fn range_check_bpp_component() -> ComposableCommittedComponent {
    ComposableCommittedComponent::from_specific_component::<RangeCheckBpp>(
        "Range check over a committed value using Bulletproofs++",
        &["RangeCheckBppCommitmentHandle"],
    )
}

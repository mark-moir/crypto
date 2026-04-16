use ark_bls12_381::{Fr as BlsFr, G1Affine as BlsG1Affine};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::{rngs::StdRng, SeedableRng};
use bulletproofs_plus_plus::prelude::SetupParams as BppSetupParams;
use equality_across_groups::{
    eq_across_groups::ProofLargeWitness,
    tom256::{Affine as Tom256Affine, Fr as Tom256Fr},
};
use std::collections::HashMap;

use crate::{
    impl_api_roundtrip_ark,
    implementations::components::{
        bbs_sd_dncps::{
            BbsSdDncps, BbsSdDncpsCommitment, BbsSdDncpsCommitmentHandle, BbsSdDncpsCommonSetup,
        },
        pok_ecdsa_sig_verifies_against_committed_pk::{
            ESVCPKCommitment, ESVCPKCommitmentHandle, ESVCPKCommonSetup,
            EcdsaSignCommittedPublicKey,
        },
    },
    init_eq_prover,
    interfaces::SpecificEqualityOfCommittedValues,
    types::api_types::*,
    CCCError, CCCResult, EqualityOfCommittedValues, ValueAndRandomness,
};

// Same values used by Prover and Verifier
use crate::implementations::components::pok_ecdsa_sig_verifies_against_committed_pk::{
    NUM_CHUNKS, WITNESS_BIT_SIZE,
};

const CHALLENGE_BIT_SIZE: usize = 180;
const ABORT_PARAM: usize = 8;
const RESPONSE_BYTE_SIZE: usize = 32;
const NUM_REPS: usize = 1;

pub type EqualityTomBlsProofType = ProofLargeWitness<
    Tom256Affine,
    BlsG1Affine,
    NUM_CHUNKS,
    WITNESS_BIT_SIZE,
    CHALLENGE_BIT_SIZE,
    ABORT_PARAM,
    RESPONSE_BYTE_SIZE,
    NUM_REPS,
>;

pub struct EqualityTomBls();
impl_api_roundtrip_ark!(EqualityTomBlsProofType => ApiEqualityProof);

impl SpecificEqualityOfCommittedValues<EcdsaSignCommittedPublicKey, BbsSdDncps> for EqualityTomBls {
    type Proof = EqualityTomBlsProofType;
    fn prove(
        ecdcpk_common_setup: &ESVCPKCommonSetup,
        bbs_sd_dncps_common_setup: &BbsSdDncpsCommonSetup,
        value_and_randomness_1: &ValueAndRandomness<Tom256Fr, Tom256Fr>,
        value_and_randomness_2: &ValueAndRandomness<BlsFr, BlsFr>,
        commitment_1: &ESVCPKCommitment,
        commitment_2: &BbsSdDncpsCommitment,
    ) -> CCCResult<EqualityTomBlsProofType> {
        let mut transcript = init_eq_prover(
            &ecdcpk_common_setup.comm_key_tom,
            &bbs_sd_dncps_common_setup.comm_key,
            // The example test pok_ecdsa_pubkey_committed_in_bls12_381_commitment on
            // which this is based does not include the base_for_bpp_proofs.  We do, to
            // be on the safe side.
            &BppSetup {
                bpp_setup_params: ecdcpk_common_setup.bpp_setup_params.clone(),
                base_for_bpp_proofs: ecdcpk_common_setup.base_for_bpp_proofs,
            },
            &commitment_1.0,
            &commitment_2.0,
        );
        let mut rng = StdRng::from_entropy();

        let proof = EqualityTomBlsProofType::new(
            &mut rng,
            &value_and_randomness_1.value,
            value_and_randomness_1.randomness,
            value_and_randomness_2.randomness,
            &ecdcpk_common_setup.comm_key_tom,
            &bbs_sd_dncps_common_setup.comm_key,
            ecdcpk_common_setup.base_for_bpp_proofs,
            ecdcpk_common_setup.bpp_setup_params.clone(),
            &mut transcript,
        )
        .map_err(|e| CCCError::General(format!("failed to build equality proof: {e:?}")))?;
        Ok(proof)
    }
    fn verify(
        ecdcpk_common_setup: &ESVCPKCommonSetup,
        bbs_sd_dncps_common_setup: &BbsSdDncpsCommonSetup,
        commitment_1: &ESVCPKCommitment,
        commitment_2: &BbsSdDncpsCommitment,
        eq_proof: &EqualityTomBlsProofType,
    ) -> CCCResult<()> {
        let mut eq_verifier_transcript = init_eq_prover(
            &ecdcpk_common_setup.comm_key_tom,
            &bbs_sd_dncps_common_setup.comm_key,
            &BppSetup {
                bpp_setup_params: ecdcpk_common_setup.bpp_setup_params.clone(),
                base_for_bpp_proofs: ecdcpk_common_setup.base_for_bpp_proofs,
            },
            &commitment_1.0,
            &commitment_2.0,
        );

        eq_proof
            .verify(
                &commitment_1.0,
                &commitment_2.0,
                &ecdcpk_common_setup.comm_key_tom,
                &bbs_sd_dncps_common_setup.comm_key,
                &ecdcpk_common_setup.bpp_setup_params.clone(),
                &mut eq_verifier_transcript,
            )
            .map_err(|e| CCCError::General(format!("failed to verify equality proof: {e:?}`")))?;
        Ok(())
    }
}

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct BppSetup {
    pub base_for_bpp_proofs: u16,
    pub bpp_setup_params: BppSetupParams<Tom256Affine>,
}

pub fn prove_key_component_equals_attribute(
    esvcpk_common_setup: &ESVCPKCommonSetup,
    bbs_sd_dncps_common_setup: &BbsSdDncpsCommonSetup,
    key_component: &ESVCPKCommitmentHandle,
    attribute_index: usize,
    tom_values: &HashMap<ESVCPKCommitmentHandle, ValueAndRandomness<Tom256Fr, Tom256Fr>>,
    tom_commitments: &HashMap<ESVCPKCommitmentHandle, ESVCPKCommitment>,
    bls_values: &HashMap<BbsSdDncpsCommitmentHandle, ValueAndRandomness<BlsFr, BlsFr>>,
    bls_commitments: &HashMap<BbsSdDncpsCommitmentHandle, BbsSdDncpsCommitment>,
) -> CCCResult<EqualityTomBlsProofType> {
    let var_tom = tom_values.get(key_component).ok_or_else(|| {
        CCCError::General(format!(
            "missing value/randomness for key component {:?}",
            key_component
        ))
    })?;

    let var_bls = bls_values
        .get(&BbsSdDncpsCommitmentHandle(attribute_index))
        .ok_or_else(|| {
            CCCError::General(format!(
                "missing value/randomness for attribute index {}",
                attribute_index
            ))
        })?;

    let comm_group_1 = tom_commitments.get(key_component).ok_or_else(|| {
        CCCError::General(format!(
            "missing commitment for key component {:?}",
            key_component
        ))
    })?;

    let comm_group_2 = bls_commitments
        .get(&BbsSdDncpsCommitmentHandle(attribute_index))
        .ok_or_else(|| {
            CCCError::General(format!(
                "missing commitment for attribute index {}",
                attribute_index
            ))
        })?;

    let proof = EqualityTomBls::prove(
        esvcpk_common_setup,
        bbs_sd_dncps_common_setup,
        var_tom,
        var_bls,
        comm_group_1,
        comm_group_2,
    )?;
    Ok(proof)
}

pub fn verify_key_component_equals_attribute(
    esvcpk_common_setup: &ESVCPKCommonSetup,
    bbs_sd_dncps_common_setup: &BbsSdDncpsCommonSetup,
    key_component: &ESVCPKCommitmentHandle,
    attribute_index: usize,
    tom_commitments: &HashMap<ESVCPKCommitmentHandle, ESVCPKCommitment>,
    bls_commitments: &HashMap<BbsSdDncpsCommitmentHandle, BbsSdDncpsCommitment>,
    proof: &EqualityTomBlsProofType,
) -> CCCResult<()> {
    let comm_group_1 = tom_commitments.get(key_component).ok_or_else(|| {
        CCCError::General(format!(
            "missing commitment for key component {:?}",
            key_component
        ))
    })?;

    let comm_group_2 = bls_commitments
        .get(&BbsSdDncpsCommitmentHandle(attribute_index))
        .ok_or_else(|| {
            CCCError::General(format!(
                "missing commitment for attribute index {}",
                attribute_index
            ))
        })?;

    EqualityTomBls::verify(
        esvcpk_common_setup,
        bbs_sd_dncps_common_setup,
        comm_group_1,
        comm_group_2,
        proof,
    )?;
    Ok(())
}

pub fn equality_by_equal_committed_values_ecdsa_pub_key_bbs_sd_dncps() -> EqualityOfCommittedValues {
    EqualityOfCommittedValues::from_components_and_equality::<
        EcdsaSignCommittedPublicKey,
        BbsSdDncps,
        EqualityTomBls,
    >("Equality of committed values between ESVCPK (TOM256) and BBS_SD_DNCPS (BLS12-381)")
}

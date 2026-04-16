use ark_bls12_381::{Fr as BlsFr, G1Affine as BlsG1Affine};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::UniformRand;
use rand_core::OsRng;

use crate::{
    error::CCCError,
    impl_api_roundtrip_ark,
    implementations::{
        components::{
            bbs_sd_dncps::{BbsSdDncps, BbsSdDncpsCommitment},
            range_check_bpp::{RangeCheckBpp, RangeCheckBppCommitment},
        },
        equalities::extraction_traits::{ExtractCommitment, ExtractCommitmentKey},
    },
    interfaces::{SpecificComposableCommittedComponent, SpecificEqualityOfCommittedValues},
    types::{api_types::*, ValueAndRandomness},
    EqualityOfCommittedValues,
};
use dock_crypto_utils::{
    commitment::PedersenCommitmentKey,
    transcript::{new_merlin_transcript, Transcript},
};

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct EqualCommittedValuesProof {
    pub t1: BlsG1Affine,
    pub t2: BlsG1Affine,
    pub respv: BlsFr,
    pub resp1: BlsFr,
    pub resp2: BlsFr,
}
impl_api_roundtrip_ark!(EqualCommittedValuesProof => ApiEqualityProof);

pub struct EqualityByEqualCommittedValuesBlsBls;

fn random_scalar(rng: &mut OsRng) -> BlsFr {
    BlsFr::rand(rng)
}

fn commit_with_key(key: &PedersenCommitmentKey<BlsG1Affine>, m: &BlsFr, r: &BlsFr) -> BlsG1Affine {
    key.commit(m, r)
}

impl ExtractCommitment<BlsG1Affine> for BbsSdDncpsCommitment {
    fn extract_commitment(&self) -> BlsG1Affine {
        self.0
    }
}

impl ExtractCommitment<BlsG1Affine> for RangeCheckBppCommitment {
    fn extract_commitment(&self) -> BlsG1Affine {
        self.0
    }
}

fn build_transcript_and_get_challenge(
    key_1: &PedersenCommitmentKey<BlsG1Affine>,
    key_2: &PedersenCommitmentKey<BlsG1Affine>,
    commitment_1: &BlsG1Affine,
    commitment_2: &BlsG1Affine,
    t1: &BlsG1Affine,
    t2: &BlsG1Affine,
) -> BlsFr {
    let mut transcript = new_merlin_transcript(b"eq_committed_values");
    transcript.append(b"comm_key_1_g", &key_1.g);
    transcript.append(b"comm_key_1_h", &key_1.h);
    transcript.append(b"comm_key_2_g", &key_2.g);
    transcript.append(b"comm_key_2_h", &key_2.h);
    transcript.append(b"C1", commitment_1);
    transcript.append(b"C2", commitment_2);
    transcript.append(b"T1", t1);
    transcript.append(b"T2", t2);
    transcript.challenge_scalar(b"challenge")
}

fn prove_internal(
    setup_1: &impl ExtractCommitmentKey<PedersenCommitmentKey<BlsG1Affine>>,
    setup_2: &impl ExtractCommitmentKey<PedersenCommitmentKey<BlsG1Affine>>,
    vr_1: &ValueAndRandomness<BlsFr, BlsFr>,
    vr_2: &ValueAndRandomness<BlsFr, BlsFr>,
    commitment_1: &impl ExtractCommitment<BlsG1Affine>,
    commitment_2: &impl ExtractCommitment<BlsG1Affine>,
) -> crate::CCCResult<EqualCommittedValuesProof> {
    // key_1 = (g1,h1), key_2 = (g2,h2)
    let key_1 = setup_1.extract_commitment_key();
    let key_2 = setup_2.extract_commitment_key();

    let value = vr_1.value;

    // Get the random values used to create the provided commitments (i.e., their openings)
    let open1 = vr_1.randomness;
    let open2 = vr_2.randomness;

    // NOTE: we could assert that vr_1.value == vr_2.value and that the commitments are correctly
    // generated from the values and randomness, i.e., that the following equations hold.
    //
    // comm1 = g1^value . h1^open1
    // comm2 = g2^value . h2^open2
    //
    // However, this would make tests involving dishonest provers pass without
    // testing that verification correctly rejects the proof.

    let comm1 = commitment_1.extract_commitment();
    let comm2 = commitment_2.extract_commitment();

    let mut rng = OsRng;
    // Choose random scalar to prove knowledge of value
    let rv = random_scalar(&mut rng);

    // Choose random scalars to prove knowledge of randomness used for each provided commitment
    let r1 = random_scalar(&mut rng);
    let r2 = random_scalar(&mut rng);

    // Commit to same random witness using each commitment key
    // t1 = g1^rv.h1^r1
    // t2 = g2^rv.h2^r2
    let t1 = commit_with_key(&key_1, &rv, &r1);
    let t2 = commit_with_key(&key_2, &rv, &r2);

    let c = build_transcript_and_get_challenge(&key_1, &key_2, &comm1, &comm2, &t1, &t2);

    // Prove knowledge of value
    let respv = rv + c * value;
    // Prove knowledge of randomness used for each commitment
    let resp1 = r1 + c * open1;
    let resp2 = r2 + c * open2;

    Ok(EqualCommittedValuesProof {
        t1,
        t2,
        respv,
        resp1,
        resp2,
    })
}

fn verify_internal(
    setup_1: &impl ExtractCommitmentKey<PedersenCommitmentKey<BlsG1Affine>>,
    setup_2: &impl ExtractCommitmentKey<PedersenCommitmentKey<BlsG1Affine>>,
    commitment_1: &impl ExtractCommitment<BlsG1Affine>,
    commitment_2: &impl ExtractCommitment<BlsG1Affine>,
    proof: &EqualCommittedValuesProof,
) -> crate::CCCResult<()> {
    let key_1 = setup_1.extract_commitment_key();
    let key_2 = setup_2.extract_commitment_key();

    let c = build_transcript_and_get_challenge(
        &key_1,
        &key_2,
        &commitment_1.extract_commitment(),
        &commitment_2.extract_commitment(),
        &proof.t1,
        &proof.t2,
    );

    let comm1 = commitment_1.extract_commitment();
    let comm2 = commitment_2.extract_commitment();

    // lhs = g1^rv.h1^r1
    let lhs1 = proof.t1;

    // rhs = g1^respv . h1^resp1 / comm1 ^ c
    //     = g1^respv . h1^resp1 / (g1^(value*c) . h1^(open1*c))
    //     = g1^(respv-(value*c)) . h1^(resp1-(open1*c))
    //     = g1^(rv + (c*value) - (value*c)) . h1^(r1 + (c*open1) - (open1*c))
    //     = g1^rv . h1^r1
    //     = lhs
    let rhs1 = key_1.commit_as_projective(&proof.respv, &proof.resp1) - comm1 * c;
    if lhs1 != rhs1 {
        return Err(CCCError::General(
            "equal commitment proof failed for first commitment".to_string(),
        ));
    }

    // Similar reasoning to above holds for t2.  Note that both use the same value of respv, so if
    // both checks pass, the two committed values must be equal.
    let lhs2 = proof.t2;
    let rhs2 = key_2.commit_as_projective(&proof.respv, &proof.resp2) - comm2 * c;
    if lhs2 != rhs2 {
        return Err(CCCError::General(
            "equal commitment proof failed for second commitment".to_string(),
        ));
    }
    Ok(())
}

impl<CK1, CK2> SpecificEqualityOfCommittedValues<CK1, CK2>
    for EqualityByEqualCommittedValuesBlsBls
where
    CK1: SpecificComposableCommittedComponent<ValueType = BlsFr, RandomnessType = BlsFr>,
    CK2: SpecificComposableCommittedComponent<ValueType = BlsFr, RandomnessType = BlsFr>,
    CK1::CommonSetup: ExtractCommitmentKey<PedersenCommitmentKey<BlsG1Affine>>,
    CK2::CommonSetup: ExtractCommitmentKey<PedersenCommitmentKey<BlsG1Affine>>,
    CK1::CommitmentType: ExtractCommitment<BlsG1Affine> + CanonicalDeserialize + CanonicalSerialize,
    CK2::CommitmentType: ExtractCommitment<BlsG1Affine> + CanonicalDeserialize + CanonicalSerialize,
{
    type Proof = EqualCommittedValuesProof;
    fn prove(
        setup_1: &CK1::CommonSetup,
        setup_2: &CK2::CommonSetup,
        vr_1: &ValueAndRandomness<BlsFr, BlsFr>,
        vr_2: &ValueAndRandomness<BlsFr, BlsFr>,
        commitment_1: &CK1::CommitmentType,
        commitment_2: &CK2::CommitmentType,
    ) -> crate::CCCResult<EqualCommittedValuesProof> {
        prove_internal(setup_1, setup_2, vr_1, vr_2, commitment_1, commitment_2)
    }

    fn verify(
        setup_1: &CK1::CommonSetup,
        setup_2: &CK2::CommonSetup,
        commitment_1: &CK1::CommitmentType,
        commitment_2: &CK2::CommitmentType,
        proof: &EqualCommittedValuesProof,
    ) -> crate::CCCResult<()> {
        verify_internal(setup_1, setup_2, commitment_1, commitment_2, proof)
    }
}

pub fn equality_by_equal_committed_values_bbs_sd_dncps_bbs_sd_dncps() -> EqualityOfCommittedValues {
    EqualityOfCommittedValues::from_components_and_equality::<
        BbsSdDncps,
        BbsSdDncps,
        EqualityByEqualCommittedValuesBlsBls,
    >("Equality of committed values between two BBS_SD_DNCPS commitments (BLS12-381)")
}

pub fn equality_by_equal_committed_values_bbs_sd_dncps_range() -> EqualityOfCommittedValues {
    EqualityOfCommittedValues::from_components_and_equality::<
        BbsSdDncps,
        RangeCheckBpp,
        EqualityByEqualCommittedValuesBlsBls,
    >("Equality of a BBS_SD_DNCPS commitment and a RangeCheckBpp commitment")
}

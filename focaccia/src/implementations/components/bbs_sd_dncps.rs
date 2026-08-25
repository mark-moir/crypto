use ark_bls12_381::{Bls12_381, Fr as BlsFr, G1Affine as BlsG1Affine};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Debug,
    rand::{rngs::StdRng, SeedableRng},
    vec::Vec,
    UniformRand,
};
use bbs_plus::{
    prelude::SignatureG1,
    setup::{PublicKeyG2, SignatureParamsG1},
};
use blake2::Blake2b512;
use dock_crypto_utils::commitment::PedersenCommitmentKey;
use proof_system::{
    prelude::{EqualWitnesses, MetaStatements, Proof, Witness, WitnessRef, Witnesses},
    proof_spec::ProofSpec,
    statement::{
        bbs_plus::{
            PoKBBSSignatureG1Prover as PoKSignatureBBSG1ProverStmt,
            PoKBBSSignatureG1Verifier as PoKSignatureBBSG1VerifierStmt,
        },
        ped_comm::PedersenCommitment as PedersenCommitmentStmt,
        Statements,
    },
    witness::PoKBBSSignatureG1 as PoKSignatureBBSG1Wit,
};
use rand_chacha::ChaChaRng;
use rand_core::OsRng;
use std::collections::HashMap;

use crate::{
    impl_api_roundtrip_ark, implementations::equalities::extraction_traits::ExtractCommitmentKey,
    interfaces::SpecificComposableCommittedComponent,
    types::api_types::*,
    CCCError, CCCResult, ComposableCommittedComponent, ValueAndRandomness,
};

#[derive(Clone, CanonicalDeserialize, CanonicalSerialize)]
pub struct BbsSdDncpsCommonSetupArgs {
    pub message_count: u32,
    pub seed: [u8; 32],
}
impl_api_roundtrip_ark!(BbsSdDncpsCommonSetupArgs => ApiCommonSetupArgs);

#[derive(Clone, CanonicalDeserialize, CanonicalSerialize)]
pub struct BbsSdDncpsCommonSetup {
    pub bls_sig_params: SignatureParamsG1<Bls12_381>,
    pub comm_key: PedersenCommitmentKey<BlsG1Affine>,
}
impl_api_roundtrip_ark!(BbsSdDncpsCommonSetup => ApiCommonSetup);

impl ExtractCommitmentKey<PedersenCommitmentKey<BlsG1Affine>> for BbsSdDncpsCommonSetup {
    fn extract_commitment_key(&self) -> PedersenCommitmentKey<BlsG1Affine> {
        self.comm_key
    }
}

#[derive(Clone, CanonicalDeserialize, CanonicalSerialize)]
pub struct BbsSdDncpsCommitArgs {
    pub messages: Vec<BlsFr>,
    pub idxs_to_commit: Vec<usize>,
}
impl_api_roundtrip_ark!(BbsSdDncpsCommitArgs => ApiCommitArgs);

impl BbsSdDncpsCommitArgs {
    pub fn validate(&self) -> CCCResult<()> {
        let message_count = self.messages.len();
        let mut seen = BTreeSet::new();
        for &idx in &self.idxs_to_commit {
            if idx >= message_count {
                return Err(CCCError::General(format!(
                    "commit index {idx} out of bounds for {message_count} messages"
                )));
            }
            if !seen.insert(idx) {
                return Err(CCCError::General(format!(
                    "duplicate commit index {idx} supplied to BBS_SD_DNCPS"
                )));
            }
        }
        Ok(())
    }
}

pub type ValueAndRandomnessBls = ValueAndRandomness<BlsFr, BlsFr>;

#[derive(Clone, CanonicalDeserialize, CanonicalSerialize)]
pub struct BbsSdDncpsProveArgs {
    pub sig_bls: SignatureG1<Bls12_381>,
    pub messages: Vec<BlsFr>,
    /// Map of message indexes and values to disclose
    pub disclosed_messages: BTreeMap<usize, BlsFr>,
    pub context: Option<Vec<u8>>,
    pub nonce: Option<Vec<u8>>,
}
impl_api_roundtrip_ark!(BbsSdDncpsProveArgs => ApiProveArgs);

#[derive(Clone, CanonicalDeserialize, CanonicalSerialize)]
pub struct BbsSdDncpsVerifyArgs {
    pub bls_public_key: PublicKeyG2<Bls12_381>,
    /// Map of message indexes and values the prover disclosed
    pub disclosed_messages: BTreeMap<usize, BlsFr>,
    pub context: Option<Vec<u8>>,
    pub nonce: Option<Vec<u8>>,
}
impl_api_roundtrip_ark!(BbsSdDncpsVerifyArgs => ApiVerifyArgs);

pub type BbsSdDncpsProof = Proof<Bls12_381>;
impl_api_roundtrip_ark!(BbsSdDncpsProof => ApiComponentProof);

pub fn commit_to_value_on_bls(
    comm_key_bls: &PedersenCommitmentKey<BlsG1Affine>,
    m: &BlsFr,
) -> (BlsFr, BlsG1Affine) {
    let mut rng = OsRng;
    let r = BlsFr::rand(&mut rng);
    let c = comm_key_bls.commit(m, &r);
    (r, c)
}

impl BbsSdDncps {
    fn cmtmt_key_bases_from_pedersen_commitment_key(
        pck: &PedersenCommitmentKey<BlsG1Affine>,
    ) -> Vec<BlsG1Affine> {
        vec![pck.g, pck.h]
    }
}

#[derive(Clone, Debug, CanonicalDeserialize, CanonicalSerialize, PartialEq, Eq, Hash)]
pub struct BbsSdDncpsCommitmentHandle(pub usize);
impl_api_roundtrip_ark!(BbsSdDncpsCommitmentHandle => ApiCommitmentHandle);

#[derive(Clone, Debug, CanonicalDeserialize, CanonicalSerialize, PartialEq, Eq)]
pub struct BbsSdDncpsCommitment(pub BlsG1Affine);
impl_api_roundtrip_ark!(BbsSdDncpsCommitment => ApiCommitment);

pub struct BbsSdDncps;

fn build_statements_and_equalities_for_committed_attrs<I>(
    bls_sig_params: &SignatureParamsG1<Bls12_381>,
    bls_public_key: Option<&PublicKeyG2<Bls12_381>>, // Needed only if called by Verifier
    commitment_bases: &[BlsG1Affine],
    committed_attrs: I,
    disclosed: &BTreeMap<usize, BlsFr>,
) -> CCCResult<(Statements<Bls12_381>, MetaStatements)>
where
    I: IntoIterator<Item = (usize, BlsG1Affine)>,
{
    let mut statements = Statements::new();
    let mut meta_statements = MetaStatements::new();

    // PoKSignature statement is added first, so it is statement 0
    match bls_public_key {
        Some(pk) => statements.add(PoKSignatureBBSG1VerifierStmt::new_statement_from_params(
            bls_sig_params.clone(),
            pk.clone(),
            disclosed.clone(),
        )),
        None => statements.add(PoKSignatureBBSG1ProverStmt::new_statement_from_params(
            bls_sig_params.clone(),
            disclosed.clone(),
        )),
    };

    let mut pedersen_stmt_idx = 0;
    for (attr_idx, cmtmt) in committed_attrs.into_iter() {
        if disclosed.contains_key(&attr_idx) {
            continue;
        }
        statements.add(PedersenCommitmentStmt::new_statement_from_params(
            commitment_bases.to_vec(),
            cmtmt,
        ));
        // 0th statement's witness for attribute is equal to i+1th statement's 0th
        // witness; +1 because PoKSignature statement is first
        meta_statements.add_witness_equality(EqualWitnesses(
            vec![(0, attr_idx), (1 + pedersen_stmt_idx, 0)]
                .into_iter()
                .collect::<BTreeSet<WitnessRef>>(),
        ));
        pedersen_stmt_idx += 1;
    }

    Ok((statements, meta_statements))
}

impl SpecificComposableCommittedComponent for BbsSdDncps {
    type ValueType = BlsFr;
    type RandomnessType = BlsFr;
    type CommitmentType = BbsSdDncpsCommitment;
    type CommonSetupArgs = BbsSdDncpsCommonSetupArgs;
    type CommonSetup = BbsSdDncpsCommonSetup;
    type CommitArgs = BbsSdDncpsCommitArgs;
    type CommitmentHandle = BbsSdDncpsCommitmentHandle;
    type ProveArgs = BbsSdDncpsProveArgs;
    type Proof = BbsSdDncpsProof;
    type VerifyArgs = BbsSdDncpsVerifyArgs;
    type VerifyReturn = ();

    fn common_setup(args: &BbsSdDncpsCommonSetupArgs) -> CCCResult<BbsSdDncpsCommonSetup> {
        Ok(bbs_sd_dncps_common_setup(args))
    }

    fn commit(
        setup: &BbsSdDncpsCommonSetup,
        args: &BbsSdDncpsCommitArgs,
    ) -> CCCResult<(
        HashMap<BbsSdDncpsCommitmentHandle, ValueAndRandomnessBls>,
        HashMap<BbsSdDncpsCommitmentHandle, BbsSdDncpsCommitment>,
    )> {
        args.validate()?;
        let mut values = HashMap::new();
        let mut commitments = HashMap::new();

        for attr_idx in args.idxs_to_commit.clone() {
            let value = args.messages[attr_idx];
            let (randomness, cmtmt) = commit_to_value_on_bls(&setup.comm_key, &value);
            let handle = BbsSdDncpsCommitmentHandle(attr_idx);
            values.insert(handle.clone(), ValueAndRandomness { value, randomness });
            commitments.insert(handle, BbsSdDncpsCommitment(cmtmt));
        }

        Ok((values, commitments))
    }

    fn prove(
        setup: &BbsSdDncpsCommonSetup,
        values_map: &HashMap<BbsSdDncpsCommitmentHandle, ValueAndRandomnessBls>,
        commitments_map: &HashMap<BbsSdDncpsCommitmentHandle, BbsSdDncpsCommitment>,
        args: &BbsSdDncpsProveArgs,
    ) -> CCCResult<Proof<Bls12_381>> {
        let cmtmt_key_bases =
            BbsSdDncps::cmtmt_key_bases_from_pedersen_commitment_key(&setup.comm_key);
        let mut witnesses = Witnesses::new();

        let mut handles: Vec<_> = commitments_map.keys().cloned().collect();
        handles.sort_by_key(|h| h.0);

        for handle in &handles {
            if !values_map.contains_key(handle) {
                return Err(CCCError::General(format!(
                    "missing value/randomness for commitment handle {:?}",
                    handle
                )));
            }
        }

        let committed_attrs = handles
            .iter()
            .map(|handle| {
                commitments_map
                    .get(handle)
                    .map(|c| (handle.0, c.0))
                    .ok_or_else(|| {
                        CCCError::General(format!(
                            "missing commitment for attribute index {}",
                            handle.0
                        ))
                    })
            })
            .collect::<CCCResult<Vec<_>>>()?;

        let (statements, meta_statements) = build_statements_and_equalities_for_committed_attrs(
            &setup.bls_sig_params,
            None,
            &cmtmt_key_bases,
            committed_attrs,
            &args.disclosed_messages,
        )?;

        let undisclosed_messages = args
            .messages
            .iter()
            .copied()
            .enumerate()
            .filter(|(idx, _)| !args.disclosed_messages.contains_key(idx))
            .collect::<BTreeMap<_, _>>();
        let sig_witness =
            PoKSignatureBBSG1Wit::new_as_witness(args.sig_bls.clone(), undisclosed_messages);
        witnesses.add(sig_witness);

        for handle in &handles {
            let ValueAndRandomness { value, randomness } = values_map
                .get(handle)
                .ok_or_else(|| {
                    CCCError::General(format!(
                        "missing value/randomness for attribute index {}",
                        handle.0
                    ))
                })?
                .clone();
            witnesses.add(Witness::PedersenCommitment(vec![value, randomness]));
        }

        let proof_spec = ProofSpec::new(
            statements.clone(),
            meta_statements.clone(),
            vec![],
            args.context.clone(),
        );

        proof_spec.validate().map_err(|e| {
            CCCError::General(format!("invalid BBS_SD_DNCPS proof spec (prover): {e:?}"))
        })?;

        let mut rng = StdRng::from_entropy();

        let dnc_proof = Proof::new::<StdRng, Blake2b512>(
            &mut rng,
            proof_spec.clone(),
            witnesses.clone(),
            args.nonce.clone(),
            Default::default(),
        )
        .map_err(|e| CCCError::General(format!("failed to construct BBS_SD_DNCPS proof: {e:?}")))?;
        Ok(dnc_proof.0)
    }

    fn verify(
        setup: &BbsSdDncpsCommonSetup,
        commitments_map: &HashMap<BbsSdDncpsCommitmentHandle, BbsSdDncpsCommitment>,
        args: &BbsSdDncpsVerifyArgs,
        proof: &BbsSdDncpsProof,
    ) -> CCCResult<()> {
        let cmtmt_key_bases =
            BbsSdDncps::cmtmt_key_bases_from_pedersen_commitment_key(&setup.comm_key);

        let mut handles: Vec<_> = commitments_map.keys().cloned().collect();
        handles.sort_by_key(|h| h.0);

        let (statements, meta_statements) = build_statements_and_equalities_for_committed_attrs(
            &setup.bls_sig_params,
            Some(&args.bls_public_key),
            &cmtmt_key_bases,
            handles
                .iter()
                .map(|handle| {
                    commitments_map
                        .get(handle)
                        .map(|c| (handle.0, c.0))
                        .ok_or_else(|| {
                            CCCError::General(format!(
                                "missing commitment for attribute index {}",
                                handle.0
                            ))
                        })
                })
                .collect::<CCCResult<Vec<_>>>()?,
            &args.disclosed_messages,
        )?;

        let verifier_proof_spec = ProofSpec::new(
            statements.clone(),
            meta_statements.clone(),
            vec![],
            args.context.clone(),
        );

        verifier_proof_spec.validate().map_err(|e| {
            CCCError::General(format!("invalid BBS_SD_DNCPS proof spec (verifier): {e:?}"))
        })?;

        let mut rng = StdRng::from_entropy();
        proof
            .clone()
            .verify::<StdRng, Blake2b512>(
                &mut rng,
                verifier_proof_spec,
                args.nonce.clone(),
                Default::default(),
            )
            .map_err(|e| {
                CCCError::General(format!("BBS_SD_DNCPS proof verification failed: {e:?}"))
            })?;
        Ok(())
    }
}

pub fn bbs_sd_dncps_common_setup(args: &BbsSdDncpsCommonSetupArgs) -> BbsSdDncpsCommonSetup {
    let mut rng = ChaChaRng::from_seed(args.seed);
    BbsSdDncpsCommonSetup {
        bls_sig_params: SignatureParamsG1::<Bls12_381>::generate_using_rng(
            &mut rng,
            args.message_count,
        ),
        comm_key: PedersenCommitmentKey::<BlsG1Affine>::new::<Blake2b512>("test1".as_bytes()),
    }
}

pub fn bbs_sd_dncps_component() -> ComposableCommittedComponent {
    ComposableCommittedComponent::from_specific_component::<BbsSdDncps>(
        "BBS+ selective disclosure component via the DNC proof system committing to selected attributes of a credential",
        &["BbsSdDncpsCommitmentHandle(index)"],
    )
}

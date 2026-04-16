use rand_core::OsRng;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};

use ark_bls12_381::{Bls12_381, Fr as BlsFr};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::One;
use ark_secp256r1::{Affine, Fq as SecpFq, Fr as SecpFr, Projective, G_GENERATOR_X, G_GENERATOR_Y};
use ark_std::{
    rand::{rngs::StdRng, SeedableRng},
    vec::Vec,
    UniformRand,
};

use bbs_plus::{
    prelude::KeypairG2,
    setup::{PublicKeyG2, SignatureParamsG1},
    signature::SignatureG1,
};
use equality_across_groups::ec::commitments::from_base_field_to_scalar_field;
use kvac::bbs_sharp::ecdsa;

use crate::{
    api::CCCGraphCreator,
    error::*,
    example_graphs::{
        bbs_sd_dncps_plus_range_check_and_device_binding::{
            BbsSdDncpsPlusRangeCheckAndDeviceBinding,
            BbsSdDncpsPlusRangeCheckAndDeviceBindingSetupArgs,
        },
        bbs_sd_dncps_single_component::{BbsSdDncps, BbsSdDncpsSetupArgs},
        bbs_sd_dncps_with_device_binding::{
            BbsSdDncpsWithDeviceBinding, BbsSdDncpsWithDeviceBindingSetupArgs,
        },
    },
    implementations::{
        components::{
            bbs_sd_dncps::{
                bbs_sd_dncps_common_setup, BbsSdDncpsCommitArgs, BbsSdDncpsCommitmentHandle,
                BbsSdDncpsCommonSetupArgs, BbsSdDncpsProveArgs, BbsSdDncpsVerifyArgs,
            },
            pok_ecdsa_sig_verifies_against_committed_pk::{
                ESVCPKCommonSetupArgs, ESVCPKProverArgs, ESVCPKVerifyArgs,
            },
            range_check_bpp::{
                RangeCheckBppCommitArgs, RangeCheckBppCommonSetupArgs, RangeCheckBppProveArgs,
                RangeCheckBppVerifyArgs,
            },
        },
        registry::{RegisteredComponent, RegisteredEquality},
    },
    types::{api_types::*, ValueAndRandomness},
    utils::merge_disjoint_maps,
    CCCGraph,
};

// ----------------------------------------------------------------------------
// Types for collecting per-role data and enabling setup/commit/prove/verify tests

/// Per-graph bundle grouped by roles.
#[derive(Clone)]
pub struct GraphBundleForTest {
    pub graph: CCCGraph,
    pub issuer: IssuerData,
    pub prover: ProverData,
    pub verifier: VerifierData,
}

/// Data for each role has common Api* maps plus role-specific extras.
#[derive(Clone)]
pub struct IssuerData {
    pub common_setup_args: HashMap<ComponentId, ApiCommonSetupArgs>,
}

#[derive(Clone)]
pub struct ProverData {
    pub commit_args: HashMap<ComponentId, ApiCommitArgs>,
    pub prove_args: HashMap<ComponentId, ApiProveArgs>,
}

#[derive(Clone)]
pub struct VerifierData {
    pub verify_args: HashMap<ComponentId, ApiVerifyArgs>,
}

// ----------------------------------------------------------------------------
// GraphBundle for BBS+ selective disclosure tests (via the DNC proof system)

#[derive(Clone, Copy)]
pub enum CommitOption {
    Commit,
    DoNotCommit,
}

#[derive(Clone, Copy)]
pub enum DiscloseOption {
    Disclose,
    DoNotDisclose,
}

// ----------------------------------------------------------------------------
// Constants used for various tests
pub const BBS_SD_DNCPS_ECDSA_PK_X_IDX: usize = 3;
pub const BBS_SD_DNCPS_ECDSA_PK_Y_IDX: usize = 4;
pub const BBS_SD_DNCPS_MESSAGE_COUNT_1: u32 = 5;
pub const BBS_SD_DNCPS_MESSAGE_COUNT_2: u32 = 10;
pub const BBS_SD_DNCPS_EQUAL_IDX_1: usize = 4;
pub const BBS_SD_DNCPS_EQUAL_IDX_2: usize = 9;
pub const BBS_SD_DNCPS_INTEGER_ATTRIBUTE_IDX: usize = 2;
pub const BBS_SD_DNCPS_NUMBER_OF_MESSAGES_INT_EXAMPLE: u32 = 5;

/// Build a BBS_SD_DNCPS-only graph, and create a GraphBundleForTest using it, populated with
/// arguments for setup/commit/prove/verify enabling tests with message_count messages,
/// with the message at index int_idx representing an integer, and optionally discloseing
/// the message and/or committing it, enabling various combinations to be tested, and
/// extending the graph with other components such as range proofs.  str is used for
/// various purposes in testing, such as creating seeds and distinguishing components
/// when multiple graphs produced by this function are combined.
pub fn build_graph_bundle_for_bbs_sd_dncps_with_integer_attr(
    message_count: u32,
    int_idx: usize,
    int_value: BlsFr,
    str: &str,
    commit_opt: CommitOption,
    disclose_opt: DiscloseOption,
) -> GraphBundleForTest {
    // Use example graph BbsSdDncps, which has a single component
    // enabling a BBS+ signature and selective disclosure (via the DNC proof system)
    let graph = BbsSdDncps::create_graph(BbsSdDncpsSetupArgs, str).unwrap();

    // Get the component id for the single component, knowing it's a BBS_SD_DNCPS registered component
    let component_id = graph
        .get_unique_component_id_by_type(RegisteredComponent::BBS_SD_DNCPS)
        .expect("BbsSdDncps graph should contain one component");

    // Create setup arguments
    let common_setup_args = bbs_sd_dncps_common_setup_args(str, message_count);
    let mut common_setup_map = HashMap::new();
    common_setup_map.insert(
        component_id.clone(),
        common_setup_args.clone().to_api().unwrap(),
    );

    // Create the common setup, which is known to both Prover and Verifier (contains information
    // like signature parameters and commitment key)
    let setup = bbs_sd_dncps_common_setup(&common_setup_args);

    // Create a key pair, messages to sign, and signature
    let (bls_public_key, messages, sig_bls) = bbs_sd_dncps_setup_key_and_sig(
        message_count,
        &setup.bls_sig_params,
        None,
        &[(int_idx, &int_value)],
    );

    // Create arguments for commit step, optionally committing to the integer message
    let commit_args = BbsSdDncpsCommitArgs {
        messages: messages.clone(),
        idxs_to_commit: match commit_opt {
            CommitOption::Commit => vec![int_idx],
            CommitOption::DoNotCommit => vec![],
        },
    }
    .to_api()
    .unwrap();
    let mut commit_args_map = HashMap::new();
    commit_args_map.insert(component_id.clone(), commit_args);

    // Create arguments for the prove step, optionally including disclosing the integer message
    let disclosed_messages = match disclose_opt {
        DiscloseOption::Disclose => BTreeMap::from([(int_idx, messages[int_idx])]),
        DiscloseOption::DoNotDisclose => BTreeMap::new(),
    };
    let context = Some(format!("ctx-{str}").into_bytes());
    let nonce = Some(format!("nonce-{str}").into_bytes());

    let prove_args = BbsSdDncpsProveArgs {
        sig_bls: sig_bls.clone(),
        messages: messages.clone(),
        disclosed_messages: disclosed_messages.clone(),
        context: context.clone(),
        nonce: nonce.clone(),
    }
    .to_api()
    .unwrap();
    let mut prove_args_map = HashMap::new();
    prove_args_map.insert(component_id.clone(), prove_args);

    // Create arguments for the verify step.
    let verify_args = BbsSdDncpsVerifyArgs {
        bls_public_key,
        disclosed_messages: disclosed_messages,
        context,
        nonce,
    }
    .to_api()
    .unwrap();
    let mut verify_args_map = HashMap::new();
    verify_args_map.insert(component_id, verify_args);

    // Create GraphBundleForTest with graph and arguments for each step
    GraphBundleForTest {
        graph,
        issuer: IssuerData {
            common_setup_args: common_setup_map,
        },
        prover: ProverData {
            commit_args: commit_args_map,
            prove_args: prove_args_map,
        },
        verifier: VerifierData {
            verify_args: verify_args_map,
        },
    }
}

pub fn bbs_sd_dncps_common_setup_args(
    seed_prefix: &str,
    message_count: u32,
) -> BbsSdDncpsCommonSetupArgs {
    BbsSdDncpsCommonSetupArgs {
        message_count,
        seed: seed_from_str(format!("{seed_prefix}_bbs_sd_dncps")),
    }
}

/// Ensure the BBS_SD_DNCPS commit args for a graph include a specific attribute index.
pub fn ensure_bbs_sd_dncps_committed(
    prover: &mut ProverData,
    component_id: &ComponentId,
    idx: usize,
) -> CCCResult<()> {
    let entry = prover
        .commit_args
        .get(component_id)
        .ok_or_else(|| CCCError::General(format!("missing commit args for '{component_id}'")))?;
    let mut args = BbsSdDncpsCommitArgs::from_api(entry.clone())?;
    if !args.idxs_to_commit.contains(&idx) {
        args.idxs_to_commit.push(idx);
    }
    prover
        .commit_args
        .insert(component_id.clone(), args.to_api()?);
    Ok(())
}

/// Extract a BBS_SD_DNCPS value from commit returns for the given component id.
pub fn extract_bbs_sd_dncps_value(
    commitment_openings: &AllApiCommitmentOpenings,
    component_id: &ComponentId,
    idx: usize,
) -> CCCResult<BlsFr> {
    let commit_return = commitment_openings.get(component_id).ok_or_else(|| {
        CCCError::General(format!(
            "missing commit return for component '{component_id}'"
        ))
    })?;
    let handle = BbsSdDncpsCommitmentHandle(idx).to_api()?;
    let value_and_randomness_api = commit_return.get(&handle).ok_or_else(|| {
        CCCError::General(format!(
            "missing value/randomness for handle {handle:?} in component '{component_id}'"
        ))
    })?;
    let vr: ValueAndRandomness<BlsFr, BlsFr> =
        ValueAndRandomness::from_api(value_and_randomness_api.clone())?;
    Ok(vr.value)
}

/// Convenience helper: read the value the verifier expects to be disclosed for a BBS_SD_DNCPS component/index.
pub fn get_value_to_be_verified_as_revealed(
    bundle: &GraphBundleForTest,
    component_id: &ComponentId,
    idx: usize,
) -> CCCResult<Option<BlsFr>> {
    let args_api = match bundle.verifier.verify_args.get(component_id) {
        Some(a) => a,
        None => return Ok(None),
    };
    let args = BbsSdDncpsVerifyArgs::from_api(args_api.clone())?;
    Ok(args.disclosed_messages.get(&idx).copied())
}

// ----------------------------------------------------------------------------
// GraphBundle for device binding tests

/// Build a graph and role-partitioned arguments for a given suffix without executing
/// setup/commit/prove/verify.  The constructed graph represents "device binding" combined with a
/// BBS+ selective-disclosure proof (via the DNC proof system) and proof that the public key used
/// for the device binding signature verification is equal to the one represented by the attributes
/// signed into indexes pk_x_idx and pk_y_idx.
pub fn build_graph_bundle_for_device_binding_example(
    message_count: u32,
    pk_x_idx: usize,
    pk_y_idx: usize,
    suffix: impl Into<String>,
    supplied_messages: &[(usize, &BlsFr)],
) -> GraphBundleForTest {
    let suffix: String = suffix.into();
    let graph = BbsSdDncpsWithDeviceBinding::create_graph(
        BbsSdDncpsWithDeviceBindingSetupArgs { pk_x_idx, pk_y_idx },
        suffix.clone(),
    )
    .unwrap();
    let esvcpk_common_setup_args_api = esvcpk_common_setup_args("esvcpk test seed")
        .to_api()
        .unwrap();
    let bbs_sd_dncps_common_setup_args =
        bbs_sd_dncps_common_setup_args("bbs_sd_dncps test seed", message_count);
    let bbs_sd_dncps_common_setup_args_api =
        bbs_sd_dncps_common_setup_args.clone().to_api().unwrap();

    let esvcpk_id = ComponentId::new(RegisteredComponent::ESVCPK, suffix.clone());
    let bbs_sd_dncps_id = ComponentId::new(RegisteredComponent::BBS_SD_DNCPS, suffix.clone());

    let common_setup_args: HashMap<ComponentId, ApiCommonSetupArgs> = HashMap::from([
        (esvcpk_id.clone(), esvcpk_common_setup_args_api),
        (bbs_sd_dncps_id.clone(), bbs_sd_dncps_common_setup_args_api),
    ]);

    let (pk, ecdsa_challenge, sig) =
        ecdsa_setup_key_and_sig(seed_from_str(format!("random_seed_for_test_{suffix}")));

    let bbs_sd_dncps_setup = bbs_sd_dncps_common_setup(&bbs_sd_dncps_common_setup_args);

    let (bls_public_key, messages, sig_bls) = bbs_sd_dncps_setup_key_and_sig(
        message_count,
        &bbs_sd_dncps_setup.bls_sig_params,
        Some((&pk, pk_x_idx, pk_y_idx)),
        supplied_messages,
    );

    let bbs_sd_dncps_commit_args_api: ApiCommitArgs = BbsSdDncpsCommitArgs {
        messages: messages.clone(),
        idxs_to_commit: vec![pk_x_idx, pk_y_idx],
    }
    .to_api()
    .unwrap();
    let esvcpk_commit_args_api = pk.to_api().unwrap();
    let commit_args = HashMap::from([
        (esvcpk_id.clone(), esvcpk_commit_args_api),
        (bbs_sd_dncps_id.clone(), bbs_sd_dncps_commit_args_api),
    ]);

    let esvcpk_prover_args_api = ESVCPKProverArgs {
        sig,
        ecdsa_challenge,
        pk,
    }
    .to_api()
    .unwrap();
    let context = Some(format!("test context {suffix}").into_bytes());
    let nonce = Some(format!("test nonce {suffix}").into_bytes());
    let bbs_sd_dncps_prover_args_api = BbsSdDncpsProveArgs {
        sig_bls: sig_bls.clone(),
        messages: messages.clone(),
        disclosed_messages: BTreeMap::new(),
        context: context.clone(),
        nonce: nonce.clone(),
    }
    .to_api()
    .unwrap();
    let prove_args = HashMap::from([
        (esvcpk_id.clone(), esvcpk_prover_args_api),
        (bbs_sd_dncps_id.clone(), bbs_sd_dncps_prover_args_api),
    ]);

    let esvcpk_verify_args_api = ESVCPKVerifyArgs { ecdsa_challenge }.to_api().unwrap();
    let bbs_sd_dncps_verify_args_api = BbsSdDncpsVerifyArgs {
        bls_public_key: bls_public_key.clone(),
        disclosed_messages: BTreeMap::new(),
        context,
        nonce,
    }
    .to_api()
    .unwrap();
    let verify_args = HashMap::from([
        (esvcpk_id, esvcpk_verify_args_api),
        (bbs_sd_dncps_id, bbs_sd_dncps_verify_args_api),
    ]);

    GraphBundleForTest {
        graph,
        issuer: IssuerData { common_setup_args },
        prover: ProverData {
            commit_args,
            prove_args,
        },
        verifier: VerifierData { verify_args },
    }
}

pub fn esvcpk_common_setup_args(prefix: &str) -> ESVCPKCommonSetupArgs {
    ESVCPKCommonSetupArgs {
        tom_seed: format!("{prefix}_tom").into_bytes(),
        secp_seed: format!("{prefix}_secp").into_bytes(),
        bpp_seed: format!("{prefix}_bpp").into_bytes(),
    }
}

// ----------------------------------------------------------------------------

// Builds a GraphBundle for a test involving a range proof on a committed value that is required to
// be equal to the attribute at index BBS_SD_DNCPS_INTEGER_ATTRIBUTE_IDX for a BBS+ signature.  The
// provided override_value is the value for that attribute and the range_value is the value for the
// range proof.  This enables positive tests in which the values are the same, as required, and
// negative tests in which they differ.
pub fn build_range_graph_bundle(
    override_value: BlsFr,
    range_value: BlsFr,
    suffix: &str,
) -> GraphBundleForTest {
    // Build the composed example graph (BBS_SD_DNCPS + device binding + range check).
    let graph = BbsSdDncpsPlusRangeCheckAndDeviceBinding::create_graph(
        BbsSdDncpsPlusRangeCheckAndDeviceBindingSetupArgs {
            pk_x_idx: BBS_SD_DNCPS_ECDSA_PK_X_IDX,
            pk_y_idx: BBS_SD_DNCPS_ECDSA_PK_Y_IDX,
            range_idx: BBS_SD_DNCPS_INTEGER_ATTRIBUTE_IDX,
        },
        suffix,
    )
    .unwrap();

    let esvcpk_id = graph
        .get_unique_component_id_by_type(RegisteredComponent::ESVCPK)
        .unwrap();
    let bbs_sd_dncps_id = graph
        .get_unique_component_id_by_type(RegisteredComponent::BBS_SD_DNCPS)
        .unwrap();
    let range_id = graph
        .get_unique_component_id_by_type(RegisteredComponent::RANGE_CHECK_BPP)
        .unwrap();

    let common_setup_args = HashMap::from([
        (
            esvcpk_id.clone(),
            esvcpk_common_setup_args(suffix).to_api().unwrap(),
        ),
        (
            bbs_sd_dncps_id.clone(),
            bbs_sd_dncps_common_setup_args(suffix, BBS_SD_DNCPS_MESSAGE_COUNT_1)
                .to_api()
                .unwrap(),
        ),
        (
            range_id.clone(),
            RangeCheckBppCommonSetupArgs {
                num_bits: 32,
                label: b"range-example".to_vec(),
            }
            .to_api()
            .unwrap(),
        ),
    ]);

    // Keys/messages/signatures
    let (pk, ecdsa_challenge, sig) =
        ecdsa_setup_key_and_sig(seed_from_str(format!("random_seed_for_test_{suffix}")));
    let bbs_sd_dncps_setup = bbs_sd_dncps_common_setup(&bbs_sd_dncps_common_setup_args(
        suffix,
        BBS_SD_DNCPS_MESSAGE_COUNT_1,
    ));
    let (bls_public_key, messages, sig_bls) = bbs_sd_dncps_setup_key_and_sig(
        BBS_SD_DNCPS_MESSAGE_COUNT_1,
        &bbs_sd_dncps_setup.bls_sig_params,
        Some((
            &pk,
            BBS_SD_DNCPS_ECDSA_PK_X_IDX,
            BBS_SD_DNCPS_ECDSA_PK_Y_IDX,
        )),
        &[(BBS_SD_DNCPS_INTEGER_ATTRIBUTE_IDX, &override_value)],
    );

    // Commit args
    let bbs_sd_dncps_commit_args = BbsSdDncpsCommitArgs {
        messages: messages.clone(),
        idxs_to_commit: vec![
            BBS_SD_DNCPS_ECDSA_PK_X_IDX,
            BBS_SD_DNCPS_ECDSA_PK_Y_IDX,
            BBS_SD_DNCPS_INTEGER_ATTRIBUTE_IDX,
        ],
    }
    .to_api()
    .unwrap();

    let commit_args = HashMap::from([
        (esvcpk_id.clone(), pk.to_api().unwrap()),
        (bbs_sd_dncps_id.clone(), bbs_sd_dncps_commit_args),
        (
            range_id.clone(),
            RangeCheckBppCommitArgs { value: range_value }
                .to_api()
                .unwrap(),
        ),
    ]);

    // Prove args
    let prove_args = HashMap::from([
        (
            esvcpk_id.clone(),
            ESVCPKProverArgs {
                sig,
                ecdsa_challenge,
                pk,
            }
            .to_api()
            .unwrap(),
        ),
        (
            bbs_sd_dncps_id.clone(),
            BbsSdDncpsProveArgs {
                sig_bls: sig_bls.clone(),
                messages: messages.clone(),
                disclosed_messages: BTreeMap::new(),
                context: Some(format!("ctx-{suffix}").into_bytes()),
                nonce: Some(format!("nonce-{suffix}").into_bytes()),
            }
            .to_api()
            .unwrap(),
        ),
        (
            range_id.clone(),
            RangeCheckBppProveArgs {
                min: 10,
                max: 100,
                transcript_label: None,
            }
            .to_api()
            .unwrap(),
        ),
    ]);

    // Verify args
    let verify_args = HashMap::from([
        (
            esvcpk_id,
            ESVCPKVerifyArgs { ecdsa_challenge }.to_api().unwrap(),
        ),
        (
            bbs_sd_dncps_id,
            BbsSdDncpsVerifyArgs {
                bls_public_key,
                disclosed_messages: BTreeMap::new(),
                context: Some(format!("ctx-{suffix}").into_bytes()),
                nonce: Some(format!("nonce-{suffix}").into_bytes()),
            }
            .to_api()
            .unwrap(),
        ),
        (
            range_id,
            RangeCheckBppVerifyArgs {
                min: 10,
                max: 100,
                transcript_label: None,
            }
            .to_api()
            .unwrap(),
        ),
    ]);

    GraphBundleForTest {
        graph,
        issuer: IssuerData { common_setup_args },
        prover: ProverData {
            commit_args,
            prove_args,
        },
        verifier: VerifierData { verify_args },
    }
}

// Utilities for using GraphBundles

/// Run setup and commit for a given graph/input bundle.
pub fn commit_graph_inputs(
    graph: &CCCGraph,
    common_setup_args: &AllApiCommonSetupArgs,
    commit_args: &AllApiCommitArgs,
) -> CCCResult<(
    AllApiCommonSetups,
    AllApiCommitmentOpenings,
    AllApiCommitments,
)> {
    let setups = graph.setup_common(common_setup_args)?;
    let (commits_for_prover, commits_for_verifier) = graph.commit(&setups, commit_args)?;
    Ok((setups, commits_for_prover, commits_for_verifier))
}

/// Execute setup -> commit -> prove -> verify for a GraphBundleForTest and return the intermediate
/// values for optional inspection.
pub fn run_graph_bundle(
    bundle: &GraphBundleForTest,
) -> CCCResult<(
    AllApiCommonSetups,
    AllApiCommitmentOpenings,
    AllApiCommitments,
    AllApiProofs,
)> {
    let setups = bundle
        .graph
        .setup_common(&bundle.issuer.common_setup_args)?;
    let (commits_for_prover, commits_for_verifier) =
        bundle.graph.commit(&setups, &bundle.prover.commit_args)?;
    let proofs = bundle.graph.prove(
        &setups,
        &commits_for_prover,
        &commits_for_verifier,
        &bundle.prover.prove_args,
    )?;
    bundle.graph.verify(
        &setups,
        &commits_for_verifier,
        &bundle.verifier.verify_args,
        &proofs,
    )?;
    Ok((setups, commits_for_prover, commits_for_verifier, proofs))
}

// ----------------------------------------------------------------------------
// Utilities for merging GraphBundle pieces

pub fn merge_issuer_data(
    left: &IssuerData,
    right: &IssuerData,
) -> CCCResult<HashMap<ComponentId, ApiCommonSetupArgs>> {
    let mut out = left.common_setup_args.clone();
    merge_disjoint_maps(&mut out, &right.common_setup_args, "common_setup_args")?;
    Ok(out)
}

pub fn merge_prover_data(
    left: &ProverData,
    right: &ProverData,
) -> CCCResult<(
    HashMap<ComponentId, ApiCommitArgs>,
    HashMap<ComponentId, ApiProveArgs>,
)> {
    let mut commit_args = left.commit_args.clone();
    merge_disjoint_maps(&mut commit_args, &right.commit_args, "commit_args")?;
    let mut prove_args = left.prove_args.clone();
    merge_disjoint_maps(&mut prove_args, &right.prove_args, "prove_args")?;
    Ok((commit_args, prove_args))
}

pub fn merge_verifier_data(
    left: &VerifierData,
    right: &VerifierData,
) -> CCCResult<HashMap<ComponentId, ApiVerifyArgs>> {
    let mut verify_args = left.verify_args.clone();
    merge_disjoint_maps(&mut verify_args, &right.verify_args, "verify_args")?;
    Ok(verify_args)
}

/// Merge two graph bundles by merging role data for each role.
pub fn merge_graph_bundles(
    bundle_1: &GraphBundleForTest,
    bundle_2: &GraphBundleForTest,
) -> CCCResult<GraphBundleForTest> {
    let mut graph = bundle_1.graph.clone();
    graph.merge_disjoint(&bundle_2.graph)?;

    let common_setup_args = merge_issuer_data(&bundle_1.issuer, &bundle_2.issuer)?;
    let (commit_args, prove_args) = merge_prover_data(&bundle_1.prover, &bundle_2.prover)?;
    let verify_args = merge_verifier_data(&bundle_1.verifier, &bundle_2.verifier)?;

    Ok(GraphBundleForTest {
        graph,
        issuer: IssuerData { common_setup_args },
        prover: ProverData {
            commit_args,
            prove_args,
        },
        verifier: VerifierData { verify_args },
    })
}

/// Build two device-binding graphs, merge them, add an equality constraint, and optionally
/// succeed or fail depending on the provided parameters. Used by tests that expect success/failure
/// when values match/differ or are/aren't committed.
pub fn build_merged_for_bbs_sd_dncps_equality(
    match_values: bool,
    commit_equal_idx_on_second_graph: bool,
) -> CCCResult<()> {
    let bbs_sd_dncps_label_1 = "bbs_sd_dncps_label_1";
    let bbs_sd_dncps_label_2 = "bbs_sd_dncps_label_2";

    // Build first graph inputs and commit to extract the target value
    let graph_bundle_1 = build_graph_bundle_for_device_binding_example(
        BBS_SD_DNCPS_MESSAGE_COUNT_1,
        BBS_SD_DNCPS_ECDSA_PK_X_IDX,
        BBS_SD_DNCPS_ECDSA_PK_Y_IDX,
        bbs_sd_dncps_label_1,
        &[],
    );
    let (_common_setups_1, commitment_openings_1_for_prover, _commitments_1_for_verifier) =
        commit_graph_inputs(
            &graph_bundle_1.graph,
            &graph_bundle_1.issuer.common_setup_args,
            &graph_bundle_1.prover.commit_args,
        )?;

    let dnc_component_id_1 = graph_bundle_1
        .graph
        .get_unique_component_id_by_type(RegisteredComponent::BBS_SD_DNCPS)
        .unwrap();
    assert_eq!(dnc_component_id_1.instance_label, bbs_sd_dncps_label_1);
    let value_to_match = extract_bbs_sd_dncps_value(
        &commitment_openings_1_for_prover,
        &dnc_component_id_1,
        BBS_SD_DNCPS_EQUAL_IDX_1,
    )?;

    // Decide which value to use on the second graph
    let override_value = if match_values {
        value_to_match
    } else {
        value_to_match + BlsFr::one() // intentionally different
    };

    // Build second graph inputs, overriding one message
    let mut graph_bundle_2 = build_graph_bundle_for_device_binding_example(
        BBS_SD_DNCPS_MESSAGE_COUNT_2,
        BBS_SD_DNCPS_ECDSA_PK_X_IDX,
        BBS_SD_DNCPS_ECDSA_PK_Y_IDX,
        bbs_sd_dncps_label_2,
        &[(BBS_SD_DNCPS_EQUAL_IDX_2, &override_value)],
    );
    let dnc_component_id_2 = graph_bundle_2
        .graph
        .get_unique_component_id_by_type(RegisteredComponent::BBS_SD_DNCPS)
        .unwrap();
    assert_eq!(dnc_component_id_2.instance_label, bbs_sd_dncps_label_2);
    if commit_equal_idx_on_second_graph {
        ensure_bbs_sd_dncps_committed(
            &mut graph_bundle_2.prover,
            &dnc_component_id_2,
            BBS_SD_DNCPS_EQUAL_IDX_2,
        )?;
    }

    // Merge the two GraphBundleForTests
    let mut merged_bundle = merge_graph_bundles(&graph_bundle_1, &graph_bundle_2)?;

    // Sanity checks
    merged_bundle.graph.validate().unwrap();
    // Graph is not connected
    merged_bundle.graph.validate_connected().unwrap_err();

    merged_bundle.graph.add_equality_spec(
        RegisteredEquality::EqualityByEqualCommittedValuesBlsBls,
        "overridden_messages_equal",
        (
            dnc_component_id_1,
            BbsSdDncpsCommitmentHandle(BBS_SD_DNCPS_EQUAL_IDX_1).to_api()?,
        ),
        (
            dnc_component_id_2,
            BbsSdDncpsCommitmentHandle(BBS_SD_DNCPS_EQUAL_IDX_2).to_api()?,
        ),
    )?;

    // Graph is now connected
    merged_bundle.graph.validate_connected().unwrap();

    run_graph_bundle(&merged_bundle).map(|_| ())
}

// ----------------------------------------------------------------------------
// Utilities for setting up keys and signatures for tests

/// Deterministically derive a 32-byte seed from a string by hashing it with SHA-256.
pub fn seed_from_str(s: String) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(s.as_bytes());
    let hash = hasher.finalize();
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&hash[..32]);
    seed
}

pub type BbsSdDncPsKeyAndSig = (PublicKeyG2<Bls12_381>, Vec<BlsFr>, SignatureG1<Bls12_381>);

/// Generate a key pair for message_count messages, generate random values to sign
/// (with some optionally overridden by provided values), include x and y parts of
/// provided ECDSA public key in specified messages, sign the messages and return
/// the publick key, messages, and signature.
pub fn bbs_sd_dncps_setup_key_and_sig(
    message_count: u32,
    bls_sig_params: &SignatureParamsG1<Bls12_381>,
    pk_with_idxs: Option<(&Affine, usize, usize)>,
    supplied_messages: &[(usize, &BlsFr)],
) -> BbsSdDncPsKeyAndSig {
    let mut rng = OsRng;
    let bls_keypair = KeypairG2::<Bls12_381>::generate_using_rng(&mut rng, bls_sig_params);

    let mut rng_bls = StdRng::seed_from_u64(0u64);
    let mut messages: Vec<BlsFr> = (0..message_count)
        .map(|_| BlsFr::rand(&mut rng_bls))
        .collect();
    // Replace random messages with supplied ones
    for (idx, msg) in supplied_messages {
        if let Some((_, pk_x_idx, pk_y_idx)) = pk_with_idxs {
            if *idx == pk_x_idx || *idx == pk_y_idx {
                panic!(
                    "Error: message supplied for {idx}, which is one of the PK indexes ({pk_x_idx},{pk_y_idx})"
                )
            };
        }
        messages[*idx] = **msg
    }
    // Replace random messages with PK components
    if let Some((pk, pk_x_idx, pk_y_idx)) = pk_with_idxs {
        let pk_x = pk.x().unwrap();
        let pk_y = pk.y().unwrap();
        messages[pk_x_idx] = from_base_field_to_scalar_field::<SecpFq, BlsFr>(pk_x);
        messages[pk_y_idx] = from_base_field_to_scalar_field::<SecpFq, BlsFr>(pk_y);
    }
    let sig_bls =
        SignatureG1::<Bls12_381>::new(&mut rng, &messages, &bls_keypair.secret_key, bls_sig_params)
            .unwrap();
    sig_bls
        .verify(
            &messages,
            bls_keypair.public_key.clone(),
            bls_sig_params.clone(),
        )
        .unwrap();
    (bls_keypair.public_key.clone(), messages, sig_bls)
}

pub type EcdsaKeyChallengeAndSig = (Affine, SecpFr, ecdsa::Signature);

/// Generate an ECDSA key pair over secp256r1, sign a random challenge,
/// and return the public key, challenge, and signature.
pub fn ecdsa_setup_key_and_sig(seed: [u8; 32]) -> EcdsaKeyChallengeAndSig {
    let mut rng = StdRng::from_seed(seed);
    let generator: Projective = Affine::new_unchecked(G_GENERATOR_X, G_GENERATOR_Y).into();
    let sk = SecpFr::rand(&mut rng);
    let pk = (generator * sk).into_affine();

    let message = SecpFr::rand(&mut rng);
    let sig = ecdsa::Signature::new_prehashed(&mut rng, message, sk);

    (pk, message, sig)
}

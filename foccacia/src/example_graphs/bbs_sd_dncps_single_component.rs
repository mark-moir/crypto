use std::collections::HashMap;

use crate::{
    api::CCCGraphCreator, implementations::registry::RegisteredComponent, CCCGraph, CCCResult,
};

/// Minimal graph consisting of a single BBS_SD_DNCPS component backed by a BBS+ signature
/// presented via the DNC proof system.
///
/// # Example
/// Build the graph, commit three messages, selectively disclose one, and verify.
///
/// ```
/// use foccacia::{
///     api::SetupCCCGraph,
///     example_graphs::bbs_sd_dncps_single_component::{
///         BbsSdDncps, BbsSdDncpsSetupArgs,
///     },
///     implementations::components::bbs_sd_dncps::{
///         bbs_sd_dncps_common_setup, BbsSdDncpsCommitArgs, BbsSdDncpsCommonSetupArgs, BbsSdDncpsProveArgs,
///         BbsSdDncpsVerifyArgs,
///     },
///     implementations::registry::RegisteredComponent,
///     types::api_types::ToApi,
///     CCCGraphApi,
/// };
/// use ark_bls12_381::{Bls12_381, Fr as BlsFr};
/// use bbs_plus::{prelude::KeypairG2, signature::SignatureG1};
/// use rand_core::OsRng;
/// use std::collections::BTreeMap;
///
/// const MSG_COUNT: u32 = 5;
///
/// // Set up the graph
/// let graph =
///     BbsSdDncps::setup(BbsSdDncpsSetupArgs, "doc").unwrap();
/// let component_id = graph
///     .get_unique_component_id_by_type(RegisteredComponent::BBS_SD_DNCPS)
///     .unwrap();
///
/// // Common setup shared by prover and verifier
/// let common_setup_args = BbsSdDncpsCommonSetupArgs {
///     message_count: MSG_COUNT,
///     seed: [42u8; 32],
/// };
/// let common_setup_args_api = common_setup_args.clone().to_api().unwrap();
/// let common_setup = bbs_sd_dncps_common_setup(&common_setup_args);
///
/// // Create messages and signature
/// let mut rng = OsRng;
/// let mut messages = vec![
///     BlsFr::from(7u64),
///     BlsFr::from(123u64),
///     BlsFr::from(9u64),
///     BlsFr::from(1u64),
///     BlsFr::from(2u64)
/// ];
/// let keypair = KeypairG2::<Bls12_381>::generate_using_rng(&mut rng, &common_setup.bls_sig_params);
/// let sig = SignatureG1::<Bls12_381>::new(
///     &mut rng,
///     &messages,
///     &keypair.secret_key,
///     &common_setup.bls_sig_params,
/// )
/// .unwrap();
///
/// // Build API arguments for commit, prove and verify
/// let commit_args = BbsSdDncpsCommitArgs {
///     messages: messages.clone(),
///     idxs_to_commit: vec![],
/// }
/// .to_api()
/// .unwrap();
/// let prove_args = BbsSdDncpsProveArgs {
///     sig_bls: sig.clone(),
///     messages: messages.clone(),
///     disclosed_messages: BTreeMap::from([(1usize, messages[1])]),
///     context: None,
///     nonce: None,
/// }
/// .to_api()
/// .unwrap();
/// let verify_args = BbsSdDncpsVerifyArgs {
///     bls_public_key: keypair.public_key.clone(),
///     disclosed_messages: BTreeMap::from([(1usize, messages[1])]),
///     context: None,
///     nonce: None,
/// }
/// .to_api()
/// .unwrap();
///
/// // Run commit / prove / verify through the graph API
/// use std::collections::HashMap;
/// let setups = graph
///     .setup_common(&HashMap::from([(component_id.clone(), common_setup_args_api)]))
///     .unwrap();
/// let (commits_for_prover, commits_for_verifier) = graph
///     .commit(&setups, &HashMap::from([(component_id.clone(), commit_args)]))
///     .unwrap();
/// let proofs = graph
///     .prove(
///         &setups,
///         &commits_for_prover,
///         &commits_for_verifier,
///         &HashMap::from([(component_id.clone(), prove_args)]),
///     )
///     .unwrap();
/// graph
///     .verify(
///         &setups,
///         &commits_for_verifier,
///         &HashMap::from([(component_id, verify_args)]),
///         &proofs,
///     )
///     .unwrap();
/// ```
pub struct BbsSdDncps;

// This simple graph does not require any setup arguments
pub struct BbsSdDncpsSetupArgs;

impl CCCGraphCreator for BbsSdDncps {
    type GraphCreationArguments = BbsSdDncpsSetupArgs;

    fn create_graph(_args: BbsSdDncpsSetupArgs, id: impl Into<String>) -> CCCResult<CCCGraph> {
        // Begin with an empty graph
        let mut graph = CCCGraph::from_map(HashMap::new());

        // Add a registered component by name; see ../implementations/registry.rs
        let _ = graph.add_component(RegisteredComponent::BBS_SD_DNCPS, id)?;

        // Validate the labels in the graph
        graph.validate()?;

        // Validate that the graph is connected
        graph.validate_connected()?;
        graph.set_graph_metadata(
            Some("BBS+ selective disclosure (DNC proof system) single-component graph".to_string()),
            Some("bbs_sd_dncps_disclose_one_integer_self_contained".to_string()),
        );
        Ok(graph)
    }
}

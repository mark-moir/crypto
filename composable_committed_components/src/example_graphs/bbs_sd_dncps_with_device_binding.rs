use std::collections::HashMap;

use crate::{
    api::CCCGraphCreator,
    implementations::{
        components::{
            bbs_sd_dncps::BbsSdDncpsCommitmentHandle,
            pok_ecdsa_sig_verifies_against_committed_pk::ESVCPKCommitmentHandle,
        },
        registry::{RegisteredComponent, RegisteredEquality},
    },
    types::api_types::ToApi,
    CCCGraph, CCCResult,
};

/// Graph that verifies knowledge of an ECDSA signature on a challenge messsage for a committed ECDSA public key
/// and ties the public key to two attributes inside a BBS_SD_DNCPS signature (BBS+ via the DNC proof system).
///
/// # Example
/// Build the graph, commit the ECDSA public key and the signed attributes, and verify the combined proof.
///
/// ```
/// use std::collections::HashMap;
/// use ark_bls12_381::Fr as BlsFr;
/// use composable_committed_components::{
///     api::SetupCCCGraph,
///     example_graphs::bbs_sd_dncps_with_device_binding::{
///         BbsSdDncpsWithDeviceBinding, BbsSdDncpsWithDeviceBindingSetupArgs,
///     },
///     implementations::components::{
///         bbs_sd_dncps::{
///             bbs_sd_dncps_common_setup, BbsSdDncpsCommitArgs, BbsSdDncpsCommonSetupArgs, BbsSdDncpsProveArgs, BbsSdDncpsVerifyArgs,
///         },
///         pok_ecdsa_sig_verifies_against_committed_pk::{ESVCPKProverArgs, ESVCPKVerifyArgs},
///     },
///     implementations::registry::RegisteredComponent,
///     types::api_types::ToApi,
///     utils::test_support::{
///         bbs_sd_dncps_setup_key_and_sig, ecdsa_setup_key_and_sig, esvcpk_common_setup_args, seed_from_str,
///     },
///     CCCGraphApi,
/// };
///
/// const MSG_COUNT: u32 = 5;
/// const PK_X_IDX: usize = 3;
/// const PK_Y_IDX: usize = 4;
///
/// // Build the graph
/// let graph = BbsSdDncpsWithDeviceBinding::setup(
///     BbsSdDncpsWithDeviceBindingSetupArgs { pk_x_idx: PK_X_IDX, pk_y_idx: PK_Y_IDX },
///     "doc",
/// ).unwrap();
/// let esvcpk_id = graph
///     .get_unique_component_id_by_type(RegisteredComponent::ESVCPK)
///     .unwrap();
/// let bbs_sd_dncps_id = graph
///     .get_unique_component_id_by_type(RegisteredComponent::BBS_SD_DNCPS)
///     .unwrap();
///
/// // Common setup args
/// let esvcpk_setup_api = esvcpk_common_setup_args("doc_seed").to_api().unwrap();
/// let bbs_sd_dncps_common_setup_args = BbsSdDncpsCommonSetupArgs { message_count: MSG_COUNT, seed: seed_from_str("doc".to_string()) };
/// let bbs_sd_dncps_setup_api = bbs_sd_dncps_common_setup_args.clone().to_api().unwrap();
/// let bbs_sd_dncps_setup = bbs_sd_dncps_common_setup(&bbs_sd_dncps_common_setup_args);
///
/// // Keys, messages, signatures
/// let (pk, ecdsa_challenge, sig) = ecdsa_setup_key_and_sig(seed_from_str("random_seed_for_test_doc".to_string()));
/// let (bls_public_key, messages, sig_bls) = bbs_sd_dncps_setup_key_and_sig(
///     MSG_COUNT,
///     &bbs_sd_dncps_setup.bls_sig_params,
///     Some((&pk, PK_X_IDX, PK_Y_IDX)),
///     &[],
/// );
///
/// // Commit args
/// let commit_args = HashMap::from([
///     (esvcpk_id.clone(), pk.to_api().unwrap()),
///     (
///         bbs_sd_dncps_id.clone(),
///         BbsSdDncpsCommitArgs {
///             messages: messages.clone(),
///             idxs_to_commit: vec![PK_X_IDX, PK_Y_IDX],
///         }
///         .to_api()
///         .unwrap(),
///     ),
/// ]);
///
/// // Prove args
/// let prove_args = HashMap::from([
///     (
///         esvcpk_id.clone(),
///         ESVCPKProverArgs {
///             sig,
///             ecdsa_challenge,
///             pk,
///         }
///         .to_api()
///         .unwrap(),
///     ),
///     (
///         bbs_sd_dncps_id.clone(),
///         BbsSdDncpsProveArgs {
///             sig_bls: sig_bls.clone(),
///             messages: messages.clone(),
///             disclosed_messages: std::collections::BTreeMap::new(),
///             context: Some(b"ctx-doc".to_vec()),
///             nonce: Some(b"nonce-doc".to_vec()),
///         }
///         .to_api()
///         .unwrap(),
///     ),
/// ]);
///
/// // Verify args
/// let verify_args = HashMap::from([
///     (esvcpk_id.clone(), ESVCPKVerifyArgs { ecdsa_challenge }.to_api().unwrap()),
///     (
///         bbs_sd_dncps_id.clone(),
///         BbsSdDncpsVerifyArgs {
///             bls_public_key,
///             disclosed_messages: std::collections::BTreeMap::new(),
///             context: Some(b"ctx-doc".to_vec()),
///             nonce: Some(b"nonce-doc".to_vec()),
///         }
///         .to_api()
///         .unwrap(),
///     ),
/// ]);
///
/// // Run the protocol
/// let setups = graph
///     .setup_common(&HashMap::from([
///         (esvcpk_id.clone(), esvcpk_setup_api),
///         (bbs_sd_dncps_id.clone(), bbs_sd_dncps_setup_api),
///     ]))
///     .unwrap();
/// let (commits_for_prover, commits_for_verifier) = graph.commit(&setups, &commit_args).unwrap();
/// let proofs = graph
///     .prove(&setups, &commits_for_prover, &commits_for_verifier, &prove_args)
///     .unwrap();
/// graph.verify(&setups, &commits_for_verifier, &verify_args, &proofs).unwrap();
/// ```
pub struct BbsSdDncpsWithDeviceBinding;

// The setup argument provides the indexes of the two attributes signed into the BBS+ signature
// corresponding to the x and y components of the public key committed in the ESVCPK component
pub struct BbsSdDncpsWithDeviceBindingSetupArgs {
    pub pk_x_idx: usize,
    pub pk_y_idx: usize,
}

impl CCCGraphCreator for BbsSdDncpsWithDeviceBinding {
    type GraphCreationArguments = BbsSdDncpsWithDeviceBindingSetupArgs;

    fn create_graph(
        args: BbsSdDncpsWithDeviceBindingSetupArgs,
        suffix: impl Into<String>,
    ) -> CCCResult<CCCGraph> {
        let BbsSdDncpsWithDeviceBindingSetupArgs { pk_x_idx, pk_y_idx } = args;
        let suffix: String = suffix.into();
        let pk_x_label = format!("PK_X-{suffix}");
        let pk_y_label = format!("PK_Y-{suffix}");

        // Create an empty graph and add two components to it
        let mut graph = CCCGraph::from_map(HashMap::new());
        let esvcpk_label = graph.add_component(RegisteredComponent::ESVCPK, &suffix)?;
        let bbs_sd_dncps_label = graph.add_component(RegisteredComponent::BBS_SD_DNCPS, &suffix)?;

        // Add one equality requiring that the x component of the ECDSA public key is equal to the
        // corresponding attribute in the BBS signature...
        graph.add_equality_spec(
            RegisteredEquality::EqualityEcdsaPubKeyAndBbsSdDncMsgPs,
            pk_x_label,
            (esvcpk_label.clone(), ESVCPKCommitmentHandle::PkX.to_api()?),
            (
                bbs_sd_dncps_label.clone(),
                BbsSdDncpsCommitmentHandle(pk_x_idx).to_api()?,
            ),
        )?;

        // ... and another equality for the y component of the public key.
        graph.add_equality_spec(
            RegisteredEquality::EqualityEcdsaPubKeyAndBbsSdDncMsgPs,
            pk_y_label,
            (esvcpk_label, ESVCPKCommitmentHandle::PkY.to_api()?),
            (
                bbs_sd_dncps_label,
                BbsSdDncpsCommitmentHandle(pk_y_idx).to_api()?,
            ),
        )?;

        graph.validate()?;
        graph.validate_connected()?;
        graph.set_graph_metadata(
            Some("BBS+ selective disclosure with device binding (DNC proof system)".to_string()),
            Some("device_binding_and_bbs_sd_dncps_happy_path".to_string()),
        );
        Ok(graph)
    }
}

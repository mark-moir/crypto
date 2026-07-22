use crate::{
    api::CCCGraphCreator,
    example_graphs::bbs_sd_dncps_with_device_binding::{
        BbsSdDncpsWithDeviceBinding, BbsSdDncpsWithDeviceBindingSetupArgs,
    },
    implementations::{
        components::{
            bbs_sd_dncps::BbsSdDncpsCommitmentHandle,
            range_check_bpp::RangeCheckBppCommitmentHandle,
        },
        registry::{RegisteredComponent, RegisteredEquality},
    },
    types::api_types::ToApi,
    CCCGraph, CCCResult,
};

/// Graph that ties device binding, selective disclosure, and a range check together.
///
/// # Example
/// Build the graph, commit the ECDSA public key, sign messages containing the pk
/// components and an integer value, and verify all proofs, including integer value
/// being within a specified range.
///
/// ```
/// use std::collections::HashMap;
/// use ark_bls12_381::Fr as BlsFr;
/// use foccacia::{
///     api::SetupCCCGraph,
///     example_graphs::bbs_sd_dncps_plus_range_check_and_device_binding::{
///         BbsSdDncpsPlusRangeCheckAndDeviceBinding,
///         BbsSdDncpsPlusRangeCheckAndDeviceBindingSetupArgs,
///     },
///     implementations::components::{
///         bbs_sd_dncps::{
///             bbs_sd_dncps_common_setup, BbsSdDncpsCommitArgs, BbsSdDncpsCommonSetupArgs, BbsSdDncpsProveArgs,
///             BbsSdDncpsVerifyArgs,
///         },
///         pok_ecdsa_sig_verifies_against_committed_pk::{ESVCPKProverArgs, ESVCPKVerifyArgs},
///         range_check_bpp::{RangeCheckBppCommitArgs, RangeCheckBppCommonSetupArgs, RangeCheckBppProveArgs, RangeCheckBppVerifyArgs},
///     },
///     implementations::registry::RegisteredComponent,
///     types::api_types::ToApi,
///     CCCGraphApi,
/// };
/// use foccacia::utils::test_support::{
///     bbs_sd_dncps_setup_key_and_sig, ecdsa_setup_key_and_sig, esvcpk_common_setup_args, seed_from_str,
/// };
///
/// const MSG_COUNT: u32 = 5;
/// const PK_X_IDX: usize = 3;
/// const PK_Y_IDX: usize = 4;
/// const RANGE_IDX: usize = 2;
/// let range_value = &BlsFr::from(55u64);
///
/// // Build the graph
/// let graph = BbsSdDncpsPlusRangeCheckAndDeviceBinding::setup(
///     BbsSdDncpsPlusRangeCheckAndDeviceBindingSetupArgs {
///         pk_x_idx: PK_X_IDX,
///         pk_y_idx: PK_Y_IDX,
///         range_idx: RANGE_IDX,
///     },
///     "doc_range",
/// )
/// .unwrap();
/// let esvcpk_id = graph
///     .get_unique_component_id_by_type(RegisteredComponent::ESVCPK)
///     .unwrap();
/// let bbs_sd_dncps_id = graph
///     .get_unique_component_id_by_type(RegisteredComponent::BBS_SD_DNCPS)
///     .unwrap();
/// let range_id = graph
///     .get_unique_component_id_by_type(RegisteredComponent::RANGE_CHECK_BPP)
///     .unwrap();
///
/// // Common setup args
/// let esvcpk_setup_api = esvcpk_common_setup_args("doc_range_seed").to_api().unwrap();
/// let bbs_sd_dncps_common_setup_args = BbsSdDncpsCommonSetupArgs { message_count: MSG_COUNT, seed: seed_from_str("doc_range".to_string()) };
/// let bbs_sd_dncps_setup_api = bbs_sd_dncps_common_setup_args.clone().to_api().unwrap();
/// let bbs_sd_dncps_setup = bbs_sd_dncps_common_setup(&bbs_sd_dncps_common_setup_args);
/// let range_setup_api = RangeCheckBppCommonSetupArgs { num_bits: 32, label: b"range-doc".to_vec() }
///     .to_api()
///     .unwrap();
///
/// // Keys, messages, signatures
/// let (pk, ecdsa_challenge, sig) = ecdsa_setup_key_and_sig(seed_from_str("random_seed_for_test_doc_range".to_string()));
/// let (bls_public_key, messages, sig_bls) = bbs_sd_dncps_setup_key_and_sig(
///     MSG_COUNT,
///     &bbs_sd_dncps_setup.bls_sig_params,
///     Some((&pk, PK_X_IDX, PK_Y_IDX)),
///     // Override message at index RANGE_IDX with range_value
///     &[(RANGE_IDX, range_value)],
/// );
///
/// // Commit args
/// let commit_args = HashMap::from([
///     (esvcpk_id.clone(), pk.to_api().unwrap()),
///     (
///         bbs_sd_dncps_id.clone(),
///         BbsSdDncpsCommitArgs {
///             messages: messages.clone(),
///             idxs_to_commit: vec![PK_X_IDX, PK_Y_IDX, RANGE_IDX],
///         }
///         .to_api()
///         .unwrap(),
///     ),
///     (
///         range_id.clone(),
///         RangeCheckBppCommitArgs { value: BlsFr::from(55u64) }.to_api().unwrap(),
///     ),
/// ]);
///
/// // Prove args
/// let prove_args = HashMap::from([
///     (
///         esvcpk_id.clone(),
///         ESVCPKProverArgs { sig, ecdsa_challenge, pk }.to_api().unwrap(),
///     ),
///     (
///         bbs_sd_dncps_id.clone(),
///         BbsSdDncpsProveArgs {
///             sig_bls: sig_bls.clone(),
///             messages: messages.clone(),
///             disclosed_messages: std::collections::BTreeMap::new(),
///             context: Some(b"ctx-range".to_vec()),
///             nonce: Some(b"nonce-range".to_vec()),
///         }
///         .to_api()
///         .unwrap(),
///     ),
///     (
///         range_id.clone(),
///         RangeCheckBppProveArgs { min: 10, max: 100, transcript_label: None }
///             .to_api()
///             .unwrap(),
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
///             context: Some(b"ctx-range".to_vec()),
///             nonce: Some(b"nonce-range".to_vec()),
///         }
///         .to_api()
///         .unwrap(),
///     ),
///     (
///         range_id.clone(),
///         RangeCheckBppVerifyArgs { min: 10, max: 100, transcript_label: None }
///             .to_api()
///             .unwrap(),
///     ),
/// ]);
///
/// // Run protocol
/// let setups = graph
///     .setup_common(&HashMap::from([
///         (esvcpk_id.clone(), esvcpk_setup_api),
///         (bbs_sd_dncps_id.clone(), bbs_sd_dncps_setup_api),
///         (range_id.clone(), range_setup_api),
///     ]))
///     .unwrap();
/// let (commits_for_prover, commits_for_verifier) = graph.commit(&setups, &commit_args).unwrap();
/// let proofs = graph
///     .prove(
///         &setups,
///         &commits_for_prover,
///         &commits_for_verifier,
///         &prove_args,
///     )
///     .unwrap();
/// graph.verify(&setups, &commits_for_verifier, &verify_args, &proofs).unwrap();
/// ```
pub struct BbsSdDncpsPlusRangeCheckAndDeviceBinding;

/// Setup args specify where the ECDSA public key is embedded in the BBS_SD_DNCPS messages
/// and which message index is constrained by the range check.
pub struct BbsSdDncpsPlusRangeCheckAndDeviceBindingSetupArgs {
    pub pk_x_idx: usize,
    pub pk_y_idx: usize,
    pub range_idx: usize,
}

impl CCCGraphCreator for BbsSdDncpsPlusRangeCheckAndDeviceBinding {
    type GraphCreationArguments = BbsSdDncpsPlusRangeCheckAndDeviceBindingSetupArgs;

    fn create_graph(
        args: BbsSdDncpsPlusRangeCheckAndDeviceBindingSetupArgs,
        suffix: impl Into<String>,
    ) -> CCCResult<CCCGraph> {
        let BbsSdDncpsPlusRangeCheckAndDeviceBindingSetupArgs {
            pk_x_idx,
            pk_y_idx,
            range_idx,
        } = args;
        let suffix: String = suffix.into();

        // Start from the device-binding example graph
        let mut graph = BbsSdDncpsWithDeviceBinding::create_graph(
            BbsSdDncpsWithDeviceBindingSetupArgs { pk_x_idx, pk_y_idx },
            suffix.clone(),
        )?;

        // Add range-check component and connect it to the chosen BBS_SD_DNCPS attribute
        let range_label = graph.add_component(RegisteredComponent::RANGE_CHECK_BPP, &suffix)?;
        let bbs_sd_dncps_id =
            graph.get_unique_component_id_by_type(RegisteredComponent::BBS_SD_DNCPS)?;

        graph.add_equality_spec(
            RegisteredEquality::EqualityBbsSdDncpsRange,
            format!("bbs_sd_dncps_range-{suffix}"),
            (
                bbs_sd_dncps_id,
                BbsSdDncpsCommitmentHandle(range_idx).to_api()?,
            ),
            (range_label, RangeCheckBppCommitmentHandle.to_api()?),
        )?;

        graph.validate()?;
        graph.validate_connected()?;
        graph.set_graph_metadata(
            Some(
                "BBS+ selective disclosure with device binding and range check (DNC proof system)"
                    .to_string(),
            ),
            Some("bbs_sd_dncps_value_with_device_binding_and_range_check_happy_path".to_string()),
        );
        Ok(graph)
    }
}

#[cfg(test)]
mod self_contained_tests {
    // A self-contained test intended to illustrate the use of a simple graph BbsSdDncps, which
    // consists of a single Composable Committed Component BBS_SD_DNCPS (Proof System With Committed
    // Messages).  This component enables setting up an "Issuer" that can sign credentials
    // comprising a specified number of attributes ("messages") and enabling a "Holder" to prove
    // knowledge to a "Verifier" of a signature, selectively disclosing some messages.  It also
    // enables committing to some of the messages (see bbs_sd_dncps_disclose_one_integer below
    // for an equlivalent test using utility functions, as well as other tests below it that also use them).
    #[test]
    fn bbs_sd_dncps_disclose_one_integer_self_contained() {
        use rand_core::OsRng;
        use std::collections::{BTreeMap, HashMap};

        use ark_bls12_381::{Bls12_381, Fr as BlsFr};
        use ark_std::{
            rand::{rngs::StdRng, SeedableRng},
            UniformRand,
        };

        use bbs_plus::{prelude::KeypairG2, signature::SignatureG1};

        use foccacia::{
            bbs_sd_dncps::{
                BbsSdDncpsCommitArgs, BbsSdDncpsCommonSetup, BbsSdDncpsCommonSetupArgs,
                BbsSdDncpsProveArgs, BbsSdDncpsVerifyArgs,
            },
            example_graphs::bbs_sd_dncps_single_component::{BbsSdDncps, BbsSdDncpsSetupArgs},
            implementations::registry::RegisteredComponent,
            types::api_types::{FromApi, ToApi},
            CCCGraphApi, CCCGraphCreator,
        };

        const MESSAGE_COUNT: u32 = 3;
        const INT_IDX: usize = 1;
        const INT_VALUE: u64 = 123;
        let int_value = BlsFr::from(INT_VALUE);

        // BbsSdDncps provides a simple example graph with a single DNC proof system component.
        let graph = BbsSdDncps::create_graph(BbsSdDncpsSetupArgs, "test-suffix").unwrap();

        // The describe method documents the structure of a graph.  For this simple graph
        // its output looks like this:
        //
        // Description: BBS+ selective disclosure (DNC proof system) single-component graph
        // Exercised by test: bbs_sd_dncps_disclose_one_integer_self_contained
        // Components:
        //   ComponentId: BBS_SD_DNCPS-test-suffix
        //     - BBS+ selective disclosure component via the DNC proof system committing to selected attributes of a credential
        //     - handles: BbsSdDncpsCommitmentHandle(index)
        //     - types:
        //         setup: bbs_sd_dncps::BbsSdDncpsCommonSetupArgs
        //         commit_args: bbs_sd_dncps::BbsSdDncpsCommitArgs
        //         prove_args: bbs_sd_dncps::BbsSdDncpsProveArgs
        //         verify_args: bbs_sd_dncps::BbsSdDncpsVerifyArgs
        //         handle: bbs_sd_dncps::BbsSdDncpsCommitmentHandle
        // Equalities:
        //   (none)

        assert!(graph.describe().to_string().contains(
            "Description: BBS+ selective disclosure (DNC proof system) single-component graph"
        ));

        // Set up for "Issuer"
        let common_setup_args = BbsSdDncpsCommonSetupArgs {
            message_count: MESSAGE_COUNT,
            seed: [42u8; 32],
        };
        let common_setup_args_api = common_setup_args.clone().to_api().unwrap();

        let components = graph.components_map();
        assert_eq!(components.len(), 1);
        let labels = components
            .keys()
            .map(|x| x.registered_component_id)
            .collect::<Vec<_>>();
        assert_eq!(labels, vec![RegisteredComponent::BBS_SD_DNCPS]);

        // If we know that the graph has a single "BBS_SD_DNCPS" component, we can
        // look it up:
        let component_label = graph
            .get_unique_component_id_by_type(RegisteredComponent::BBS_SD_DNCPS)
            .unwrap();

        let common_setups_api = graph
            .setup_common(&HashMap::from([(
                component_label.clone(),
                common_setup_args_api,
            )]))
            .unwrap();

        let bbs_sd_dncps_setup = BbsSdDncpsCommonSetup::from_api(
            common_setups_api.get(&component_label).unwrap().clone(),
        )
        .unwrap();

        let mut rng = OsRng;
        let bls_keypair = KeypairG2::<Bls12_381>::generate_using_rng(
            &mut rng,
            &bbs_sd_dncps_setup.bls_sig_params,
        );
        let bls_public_key = bls_keypair.public_key.clone();

        // Prepare messages and signature
        let mut rng_bls = StdRng::seed_from_u64(0u64);
        let mut messages: Vec<BlsFr> = (0..MESSAGE_COUNT)
            .map(|_| BlsFr::rand(&mut rng_bls))
            .collect();
        messages[INT_IDX] = int_value;

        let sig_bls = SignatureG1::<Bls12_381>::new(
            &mut rng,
            &messages,
            &bls_keypair.secret_key,
            &bbs_sd_dncps_setup.bls_sig_params,
        )
        .unwrap();

        // Commit to all messages (optional for disclose-only proof)
        let commit_args = BbsSdDncpsCommitArgs {
            messages: messages.clone(),
            idxs_to_commit: Vec::new(),
        }
        .to_api()
        .unwrap();
        let commit_args_map = HashMap::from([(component_label.clone(), commit_args)]);
        let (commits_for_prover, commits_for_verifier) =
            graph.commit(&common_setups_api, &commit_args_map).unwrap();

        // Prove with selective disclose of the integer attribute
        let prove_args = BbsSdDncpsProveArgs {
            sig_bls: sig_bls.clone(),
            messages: messages.clone(),
            disclosed_messages: BTreeMap::from([(INT_IDX, messages[INT_IDX])]),
            context: None,
            nonce: None,
        }
        .to_api()
        .unwrap();
        let prove_args_map = HashMap::from([(component_label.clone(), prove_args)]);
        let proofs = graph
            .prove(
                &common_setups_api,
                &commits_for_prover,
                &commits_for_verifier,
                &prove_args_map,
            )
            .unwrap();

        // Verify and assert the disclosed attribute matches
        let verify_args = BbsSdDncpsVerifyArgs {
            bls_public_key: bls_public_key.clone(),
            disclosed_messages: BTreeMap::from([(INT_IDX, int_value)]),
            context: None,
            nonce: None,
        }
        .to_api()
        .unwrap();
        let verify_args_map = HashMap::from([(component_label.clone(), verify_args)]);

        // Extra assertion on the disclosed value
        let verify_args_api = verify_args_map.get(&component_label).unwrap().clone();
        let verify_args = BbsSdDncpsVerifyArgs::from_api(verify_args_api).unwrap();
        assert_eq!(
            verify_args
                .disclosed_messages
                .get(&INT_IDX)
                .copied()
                .unwrap(),
            int_value
        );

        graph
            .verify(
                &common_setups_api,
                &commits_for_verifier,
                &verify_args_map,
                &proofs,
            )
            .unwrap();
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use ark_bls12_381::Fr as BlsFr;
    use foccacia::{
        example_graphs::bbs_sd_dncps_with_device_binding::{
            BbsSdDncpsWithDeviceBinding, BbsSdDncpsWithDeviceBindingSetupArgs,
        },
        implementations::{
            components::{
                bbs_sd_dncps::BbsSdDncpsCommitmentHandle,
                pok_ecdsa_sig_verifies_against_committed_pk::ESVCPKCommitmentHandle,
            },
            registry::{RegisteredComponent, RegisteredEquality},
        },
        types::api_types::*,
        utils::test_support::*,
        CCCGraphCreator,
    };

    // -------------------------------------------------------------------------
    // Tests involving a single-component (BBS_SD_DNCPS = BBS+ with Selective
    // Disclosure via DockNetwork crypto proof system) graph with variations on
    // disclosing and committing to an integer message
    // -------------------------------------------------------------------------

    /// This is the same test as
    /// bbs_sd_dncps_disclose_one_integer_self_contained, using
    /// a utility function build_graph_bundle_for_bbs_sd_dncps_with_integer_attr to
    /// build the same dingle-component graph and perform the same operations,
    /// but via GraphBundleForTests.  The utility function enables variations on
    /// whether the integer message is disclosed and/or committed.  For this
    /// test it is disclosed and not committed.
    #[test]
    fn bbs_sd_dncps_disclose_one_integer() {
        let int_value = BlsFr::from(37u64);
        let bundle = build_graph_bundle_for_bbs_sd_dncps_with_integer_attr(
            BBS_SD_DNCPS_NUMBER_OF_MESSAGES_INT_EXAMPLE,
            BBS_SD_DNCPS_INTEGER_ATTRIBUTE_IDX,
            int_value,
            "bbs_sd_dncps-int",
            CommitOption::DoNotCommit,
            DiscloseOption::Disclose,
        );

        // Find the ComponentId for the (unique) component in the graph for
        // registered component "BBS_SD_DNCPS" (see related comments in self-contained
        // version above).
        let component_id = bundle
            .graph
            .get_unique_component_id_by_type(RegisteredComponent::BBS_SD_DNCPS)
            .unwrap();

        // Confirm that the Verifier will verify the same
        // value that was signed into the signature
        assert_eq!(
            get_value_to_be_verified_as_revealed(
                &bundle,
                &component_id,
                BBS_SD_DNCPS_INTEGER_ATTRIBUTE_IDX
            )
            .unwrap(),
            Some(int_value)
        );

        // Perform all steps, expecting all to succeed
        run_graph_bundle(&bundle).unwrap();
    }

    /// Same test again, but without disclosig the integer value.  In this case
    /// the Verifier is just verifying that the Prover knows a valid signature.
    #[test]
    fn bbs_sd_dncps_no_disclose() {
        let int_value = BlsFr::from(37u64);
        let bundle = build_graph_bundle_for_bbs_sd_dncps_with_integer_attr(
            BBS_SD_DNCPS_NUMBER_OF_MESSAGES_INT_EXAMPLE,
            BBS_SD_DNCPS_INTEGER_ATTRIBUTE_IDX,
            int_value,
            "bbs_sd_dncps-int",
            CommitOption::DoNotCommit,
            DiscloseOption::DoNotDisclose,
        );

        // Find the ComponentId for the (unique) component in the graph for
        // registered component "BBS_SD_DNCPS"
        let component_id = bundle
            .graph
            .get_unique_component_id_by_type(RegisteredComponent::BBS_SD_DNCPS)
            .unwrap();

        // Confirm that the Verifier will NOT verify any
        // value for BBS_SD_DNCPS_INTEGER_ATTRIBUTE_IDX
        assert_eq!(
            get_value_to_be_verified_as_revealed(
                &bundle,
                &component_id,
                BBS_SD_DNCPS_INTEGER_ATTRIBUTE_IDX
            )
            .unwrap(),
            None
        );

        run_graph_bundle(&bundle).unwrap();
    }

    /// Same test again, but this time committing the integer attribute
    /// (and not disclosing it)
    #[test]
    fn bbs_sd_dncps_commit_one_message() {
        let int_value = BlsFr::from(37u64);
        let bundle = build_graph_bundle_for_bbs_sd_dncps_with_integer_attr(
            BBS_SD_DNCPS_NUMBER_OF_MESSAGES_INT_EXAMPLE,
            BBS_SD_DNCPS_INTEGER_ATTRIBUTE_IDX,
            int_value,
            "bbs_sd_dncps-int",
            CommitOption::Commit,
            DiscloseOption::DoNotDisclose,
        );

        // Find the ComponentId for the (unique) component in the graph for
        // registered component "BBS_SD_DNCPS"
        let component_id = bundle
            .graph
            .get_unique_component_id_by_type(RegisteredComponent::BBS_SD_DNCPS)
            .unwrap();

        // Confirm that the Verifier will NOT verify any
        // value for BBS_SD_DNCPS_INTEGER_ATTRIBUTE_IDX
        assert_eq!(
            get_value_to_be_verified_as_revealed(
                &bundle,
                &component_id,
                BBS_SD_DNCPS_INTEGER_ATTRIBUTE_IDX
            )
            .unwrap(),
            None
        );
        run_graph_bundle(&bundle).unwrap();
    }

    /// Same test again, attempting to both commit and disclose the
    /// integer attribute, which should not succeed (it doesn't make sense
    /// to commit to a value while also disclosing the value).
    #[test]
    fn bbs_sd_dncps_disclose_and_commit() {
        let int_value = BlsFr::from(37u64);
        let bundle = build_graph_bundle_for_bbs_sd_dncps_with_integer_attr(
            BBS_SD_DNCPS_NUMBER_OF_MESSAGES_INT_EXAMPLE,
            BBS_SD_DNCPS_INTEGER_ATTRIBUTE_IDX,
            int_value,
            "bbs_sd_dncps-int",
            CommitOption::Commit,
            DiscloseOption::Disclose,
        );
        let err = run_graph_bundle(&bundle).unwrap_err();
        assert!(err.to_string().contains(
            "failed to construct BBS_SD_DNCPS proof: UnequalWitnessAndStatementCount(1, 2)"
        ))
    }

    // -------------------------------------------------------------------------
    // Tests involving a graph with two components, one BBS_SD_DNCPS and one ESVCPK
    // (Ecdsa Signature Verifies with Committed Public Key), with the two indexes
    // in the DNC signature being required to be proved equal the two parts of the
    // ECDSA public key represented by the ESCCPK component.
    // -------------------------------------------------------------------------

    #[test]
    fn device_binding_and_bbs_sd_dncps_happy_path() {
        let inputs = build_graph_bundle_for_device_binding_example(
            BBS_SD_DNCPS_MESSAGE_COUNT_1,
            BBS_SD_DNCPS_ECDSA_PK_X_IDX,
            BBS_SD_DNCPS_ECDSA_PK_Y_IDX,
            "test_1",
            &[],
        );
        let graph = inputs.graph.clone();
        let (_, _, _, proofs) = run_graph_bundle(&inputs).unwrap();

        // Sanity check proofs
        assert_eq!(proofs.components.len(), 2);
        assert_eq!(proofs.equalities.len(), 2);
        assert_eq!(proofs.equalities.len(), graph.equalities_map().len());
        let component_names: BTreeSet<_> = proofs.components.keys().cloned().collect();
        assert_eq!(component_names, graph.names_vec().into_iter().collect());
        let equality_labels: BTreeSet<_> = proofs.equalities.keys().cloned().collect();
        assert_eq!(
            equality_labels,
            graph.equalities_map().keys().cloned().collect()
        );
    }

    // -------------------------------------------------------------------------
    // Tests involving a graph with two components, one BBS_SD_DNCPS and one ESVCPK
    // (Ecdsa Signature Verifies with Committed Public Key), with the two indexes
    // in the DNC signature being required to be proved equal the two parts of the
    // ECDSA public key represented by the ESCCPK component.
    // -------------------------------------------------------------------------

    #[test]
    fn merge_two_graphs_and_equalize_bbs_sd_dncps_attributes() {
        build_merged_for_bbs_sd_dncps_equality(true, true).unwrap();
    }

    #[test]
    fn merge_fails_when_values_differ() {
        let err = build_merged_for_bbs_sd_dncps_equality(false, true).unwrap_err();
        assert!(
            err.to_string().contains("equal commitment proof failed")
                || err.to_string().contains("values are not equal")
        )
    }

    #[test]
    fn merge_fails_when_index_not_committed() {
        let err = build_merged_for_bbs_sd_dncps_equality(true, false).unwrap_err();
        let err_str = err.to_string();
        assert!(err_str.contains("commitment values for handle"));
        assert!(err_str.contains("on component 'BBS_SD_DNCPS-bbs_sd_dncps_label_2' not found"));
    }

    #[test]
    fn bbs_sd_dncps_value_with_device_binding_and_range_check_happy_path() {
        let v = BlsFr::from(42u64);
        run_graph_bundle(&build_range_graph_bundle(v, v, "range_example_ok")).unwrap();
    }

    #[test]
    fn bbs_sd_dncps_value_with_device_binding_and_range_check_value_out_of_range_equal() {
        let override_value = BlsFr::from(142u64); // Out of range, equal to range_value
        let range_value = BlsFr::from(142u64);
        let err = run_graph_bundle(&build_range_graph_bundle(
            override_value,
            range_value,
            "range_example_mismatch",
        ))
        .expect_err("expected verification to fail when value out of range");
        assert!(
            err.to_string().contains("value is outside supplied bounds")
                || err.to_string().contains("range proof verification failed"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn bbs_sd_dncps_value_with_device_binding_and_range_check_value_out_of_range_not_equal() {
        let override_value = BlsFr::from(142u64); // Out of range, not equal to range_value
        let range_value = BlsFr::from(42u64);
        let err = run_graph_bundle(&build_range_graph_bundle(
            override_value,
            range_value,
            "range_example_mismatch",
        ))
        .expect_err("expected verification to fail when values differ");
        assert!(
            err.to_string().contains("equal commitment proof failed"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn detects_invalid_graph_edge() {
        let graph = BbsSdDncpsWithDeviceBinding::create_graph(
            BbsSdDncpsWithDeviceBindingSetupArgs {
                pk_x_idx: BBS_SD_DNCPS_ECDSA_PK_X_IDX,
                pk_y_idx: BBS_SD_DNCPS_ECDSA_PK_Y_IDX,
            },
            "suffix",
        )
        .unwrap();

        let mut invalid_graph = graph.clone();
        assert!(invalid_graph
            .add_equality_spec(
                RegisteredEquality::EqualityEcdsaPubKeyAndBbsSdDncMsgPs,
                "InvalidName",
                (
                    ComponentId::new(RegisteredComponent::RANGE_CHECK_BPP, "missing".to_string()),
                    ESVCPKCommitmentHandle::PkX.to_api().unwrap()
                ),
                (
                    ComponentId::new(RegisteredComponent::BBS_SD_DNCPS, "suffix".to_string()),
                    BbsSdDncpsCommitmentHandle(BBS_SD_DNCPS_ECDSA_PK_Y_IDX)
                        .to_api()
                        .unwrap(),
                ),
            )
            .is_err());
    }
}

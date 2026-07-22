use std::collections::BTreeMap;

use foccacia::{
    bbs_sd_dncps::*,
    equal_committed_values_tom256_bls12381::*,
    pok_ecdsa_sig_verifies_against_committed_pk::{ESVCPKCommitmentHandle::*, *},
    utils::test_support::{
        bbs_sd_dncps_setup_key_and_sig, ecdsa_setup_key_and_sig, esvcpk_common_setup_args,
        seed_from_str,
    },
    SpecificComposableCommittedComponent,
};

#[test]
fn test_device_binding_with_proof_system() {
    // -----------------------------------------------------------------
    // SetupECDSA: create Ecdsa keys, sign a message
    // -----------------------------------------------------------------

    let (pk, ecdsa_challenge, sig) =
        ecdsa_setup_key_and_sig(seed_from_str("random_seed_for_test".to_string()));

    // -----------------------------------------------------------------
    // PTomSetup: setup to prove knowledge of signature on message
    // that verifies against PK committed in CTom
    // -----------------------------------------------------------------

    let tom_setup = ecdsa_common_setup(&esvcpk_common_setup_args("device_binding"));

    // -----------------------------------------------------------------
    // CTom: Commit to ECDSA public key on Tom-256 curve
    // -----------------------------------------------------------------

    let (tom_values, tom_commitments) = EcdsaSignCommittedPublicKey::commit(&tom_setup, &pk)
        .expect("test setup should commit successfully");

    // -----------------------------------------------------------------
    // PTom: prove knowledge of signature on message that verifies against PK committed in CTom
    // -----------------------------------------------------------------

    let esvcpk_proof = EcdsaSignCommittedPublicKey::prove(
        &tom_setup,
        &tom_values,
        &tom_commitments,
        &ESVCPKProverArgs {
            sig,
            ecdsa_challenge,
            pk,
        },
    )
    .expect("test setup should prove successfully");

    // -----------------------------------------------------------------
    // VTom: verify PTom proof
    // -----------------------------------------------------------------

    EcdsaSignCommittedPublicKey::verify(
        &tom_setup,
        &tom_commitments,
        &ESVCPKVerifyArgs { ecdsa_challenge },
        &esvcpk_proof,
    )
    .expect("test setup should verify successfully");

    // -----------------------------------------------------------------
    // SetupBLS: create BLS keys, sign messages including X and Y
    // components of ECDSA PK as attributes
    // -----------------------------------------------------------------
    const BBS_SD_DNCPS_ECDSA_PK_X_IDX: usize = 3;
    const BBS_SD_DNCPS_ECDSA_PK_Y_IDX: usize = 4;
    const BBS_SD_DNCPS_MESSAGE_COUNT: u32 = 5;

    let bbs_sd_dncps_common_setup = bbs_sd_dncps_common_setup(&BbsSdDncpsCommonSetupArgs {
        message_count: BBS_SD_DNCPS_MESSAGE_COUNT,
        seed: seed_from_str("my_test_seed".to_string()),
    });

    let (bls_public_key, messages, sig_bls) = bbs_sd_dncps_setup_key_and_sig(
        BBS_SD_DNCPS_MESSAGE_COUNT,
        &bbs_sd_dncps_common_setup.bls_sig_params,
        Some((
            &pk,
            BBS_SD_DNCPS_ECDSA_PK_X_IDX,
            BBS_SD_DNCPS_ECDSA_PK_Y_IDX,
        )),
        &[],
    );

    // -----------------------------------------------------------------
    // CBls: commit to PK x and y components on Bls12-381 curve
    // -----------------------------------------------------------------

    let (bbs_values, bbs_commitments) = BbsSdDncps::commit(
        &bbs_sd_dncps_common_setup,
        &BbsSdDncpsCommitArgs {
            messages: messages.clone(),
            idxs_to_commit: vec![BBS_SD_DNCPS_ECDSA_PK_X_IDX, BBS_SD_DNCPS_ECDSA_PK_Y_IDX],
        },
    )
    .expect("test setup should commit successfully");

    // -----------------------------------------------------------------
    // PBls: prove knowledge of signature that verifies and contains X
    // and Y components committed in CBls
    // -----------------------------------------------------------------

    let context = Some(b"test context".to_vec());
    let nonce = Some(b"test nonce".to_vec());

    let dnc_proof = BbsSdDncps::prove(
        &bbs_sd_dncps_common_setup,
        &bbs_values,
        &bbs_commitments,
        &BbsSdDncpsProveArgs {
            sig_bls,
            messages,
            disclosed_messages: BTreeMap::new(),
            context: context.clone(),
            nonce: nonce.clone(),
        },
    )
    .expect("test setup should prove successfully");

    // -----------------------------------------------------------------
    // PBls: verify proof knowledge of signature that verifies and
    // contains X and Y components committed in CBls
    // -----------------------------------------------------------------

    BbsSdDncps::verify(
        &bbs_sd_dncps_common_setup,
        &bbs_commitments,
        &BbsSdDncpsVerifyArgs {
            bls_public_key: bls_public_key.clone(),
            disclosed_messages: BTreeMap::new(),
            context: context.clone(),
            nonce: nonce.clone(),
        },
        &dnc_proof,
    )
    .expect("test setup should verify successfully");

    // -----------------------------------------------------------------
    // PEq: prove values committed in CTom and CBls are equal
    // -----------------------------------------------------------------

    let proof_x = prove_key_component_equals_attribute(
        &tom_setup,
        &bbs_sd_dncps_common_setup,
        &PkX,
        BBS_SD_DNCPS_ECDSA_PK_X_IDX,
        &tom_values,
        &tom_commitments,
        &bbs_values,
        &bbs_commitments,
    )
    .unwrap();
    let proof_y = prove_key_component_equals_attribute(
        &tom_setup,
        &bbs_sd_dncps_common_setup,
        &PkY,
        BBS_SD_DNCPS_ECDSA_PK_Y_IDX,
        &tom_values,
        &tom_commitments,
        &bbs_values,
        &bbs_commitments,
    )
    .unwrap();

    // -----------------------------------------------------------------
    // VEq: verify proof that values committed in CTom and CBls are equal
    // -----------------------------------------------------------------

    verify_key_component_equals_attribute(
        &tom_setup,
        &bbs_sd_dncps_common_setup,
        &PkX,
        BBS_SD_DNCPS_ECDSA_PK_X_IDX,
        &tom_commitments,
        &bbs_commitments,
        &proof_x,
    )
    .unwrap();
    verify_key_component_equals_attribute(
        &tom_setup,
        &bbs_sd_dncps_common_setup,
        &PkY,
        BBS_SD_DNCPS_ECDSA_PK_Y_IDX,
        &tom_commitments,
        &bbs_commitments,
        &proof_y,
    )
    .unwrap();
}

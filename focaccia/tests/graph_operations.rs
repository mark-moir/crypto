use foccacia::{
    implementations::{
        components::{
            bbs_sd_dncps::BbsSdDncpsCommitmentHandle,
            pok_ecdsa_sig_verifies_against_committed_pk::ESVCPKCommitmentHandle,
            range_check_bpp::RangeCheckBppCommitmentHandle,
        },
        registry::{RegisteredComponent, RegisteredEquality},
    },
    types::api_types::ToApi,
    CCCGraph,
};

const PK_X_IDX: usize = 3;

fn build_graph_with_labels(suffix: &str, spec_label: &str) -> CCCGraph {
    let mut graph = CCCGraph::from_map(std::collections::HashMap::new());
    let esvcpk_label = graph
        .add_component(RegisteredComponent::ESVCPK, suffix)
        .unwrap();
    let bbs_sd_dncps_label = graph
        .add_component(RegisteredComponent::BBS_SD_DNCPS, suffix)
        .unwrap();

    graph
        .add_equality_spec(
            RegisteredEquality::EqualityEcdsaPubKeyAndBbsSdDncMsgPs,
            spec_label.to_string(),
            (esvcpk_label, ESVCPKCommitmentHandle::PkX.to_api().unwrap()),
            (
                bbs_sd_dncps_label,
                BbsSdDncpsCommitmentHandle(PK_X_IDX).to_api().unwrap(),
            ),
        )
        .unwrap();

    graph
}

#[test]
fn merge_disjoint_succeeds() {
    let mut left = build_graph_with_labels("left", "SpecLeft");
    let right = build_graph_with_labels("right", "SpecRight");

    left.merge_disjoint(&right).unwrap();
    assert_eq!(left.components_map().len(), 4);
    assert_eq!(left.equalities_map().len(), 2);
    left.validate().unwrap();
    // Graph is not connected as no equality has been added between the two merged graphs
    left.validate_connected().unwrap_err();
}

#[test]
fn merge_fails_on_component_collision() {
    let mut left = build_graph_with_labels("dup", "SpecDup1");
    let right = build_graph_with_labels("dup", "SpecDup2");

    let err = left.merge_disjoint(&right).unwrap_err();
    assert!(err.to_string().contains("component name already exists"));
}

#[test]
fn merge_fails_on_equality_spec_collision() {
    let mut left = build_graph_with_labels("a", "SpecSame");
    let right = build_graph_with_labels("b", "SpecSame");

    let err = left.merge_disjoint(&right).unwrap_err();
    assert!(err
        .to_string()
        .contains("equality spec label already exists"));
}

#[test]
fn validate_connected_detects_disconnected_graph() {
    let mut graph = CCCGraph::from_map(std::collections::HashMap::new());
    let a = graph
        .add_component(RegisteredComponent::ESVCPK, "a")
        .unwrap();
    let b = graph
        .add_component(RegisteredComponent::BBS_SD_DNCPS, "b")
        .unwrap();
    let c = graph
        .add_component(RegisteredComponent::RANGE_CHECK_BPP, "c")
        .unwrap();

    // Connect a <-> b but leave c isolated
    graph
        .add_equality_spec(
            RegisteredEquality::EqualityEcdsaPubKeyAndBbsSdDncMsgPs,
            "ab",
            (a.clone(), ESVCPKCommitmentHandle::PkX.to_api().unwrap()),
            (
                b.clone(),
                BbsSdDncpsCommitmentHandle(PK_X_IDX).to_api().unwrap(),
            ),
        )
        .unwrap();

    let err = graph.validate_connected().unwrap_err();
    assert!(err.to_string().contains("not connected"));

    // Now connect a to c
    let mut graph_1 = graph.clone();
    graph_1
        .add_equality_spec(
            RegisteredEquality::EqualityBbsSdDncpsRange,
            "ac",
            (a, BbsSdDncpsCommitmentHandle(PK_X_IDX).to_api().unwrap()),
            (c.clone(), RangeCheckBppCommitmentHandle.to_api().unwrap()),
        )
        .unwrap();
    graph_1.validate_connected().unwrap();
}

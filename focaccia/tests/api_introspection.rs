use foccacia::{
    api::CCCGraphApi,
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
    implementations::registry::RegisteredComponent,
    CCCGraphCreator,
};

#[test]
fn describe_single_component_graph() {
    let graph = BbsSdDncps::create_graph(BbsSdDncpsSetupArgs, "desc").unwrap();
    let descriptor = graph.describe();
    let printed = descriptor.to_string();

    assert_eq!(descriptor.components.len(), 1);
    assert_eq!(descriptor.equalities.len(), 0);
    let comp = &descriptor.components[0];
    assert_eq!(
        comp.registered_component_id,
        RegisteredComponent::BBS_SD_DNCPS
    );
    assert!(!comp.description.is_empty());
    assert!(!comp.commitment_handles.is_empty());
    assert_eq!(
        comp.id.registered_component_id,
        RegisteredComponent::BBS_SD_DNCPS
    );
    assert_eq!(comp.id.instance_label, "desc");
    assert!(printed.contains("Components:"));
    assert!(printed.contains("Equalities:"));
    assert!(printed.to_lowercase().contains("selective disclosure"));
    assert!(!printed.contains("ApiCommitmentHandle"));

    let ids = graph.get_component_ids_by_type(RegisteredComponent::BBS_SD_DNCPS);
    assert_eq!(ids, vec![comp.id.clone()]);
    let unique = graph
        .get_unique_component_id_by_type(RegisteredComponent::BBS_SD_DNCPS)
        .unwrap();
    assert_eq!(unique, comp.id);
}

#[test]
fn describe_multi_component_graph_with_equalities() {
    let graph = BbsSdDncpsWithDeviceBinding::create_graph(
        BbsSdDncpsWithDeviceBindingSetupArgs {
            pk_x_idx: 3,
            pk_y_idx: 4,
        },
        "suffix",
    )
    .unwrap();

    let descriptor = graph.describe();
    assert_eq!(descriptor.components.len(), 2);
    assert_eq!(descriptor.equalities.len(), 2);

    // Components should include one BBS_SD_DNCPS and one ESVCPK
    let mut names: Vec<_> = descriptor
        .components
        .iter()
        .map(|c| c.registered_component_id)
        .collect();
    names.sort_by_key(|c| c.as_key());
    assert_eq!(
        names,
        vec![
            RegisteredComponent::BBS_SD_DNCPS,
            RegisteredComponent::ESVCPK
        ]
    );
    assert!(descriptor
        .components
        .iter()
        .all(|c| !c.description.is_empty()));
    assert!(descriptor
        .components
        .iter()
        .all(|c| !c.commitment_handles.is_empty()));
    let printed = descriptor.to_string();
    assert!(printed.contains("PkX"));
    assert!(printed.contains("PkY"));
    assert!(printed.contains("BbsSdDncpsCommitmentHandle"));

    // Equalities should connect the two components
    for eq in &descriptor.equalities {
        assert_eq!(eq.endpoint_1.component_id.instance_label, "suffix");
        assert_eq!(eq.endpoint_2.component_id.instance_label, "suffix");
        assert_ne!(
            eq.endpoint_1.component_id.registered_component_id,
            eq.endpoint_2.component_id.registered_component_id
        );
    }

    // Lookup helpers
    let bbs_sd_dncps_ids = graph.get_component_ids_by_type(RegisteredComponent::BBS_SD_DNCPS);
    assert_eq!(bbs_sd_dncps_ids.len(), 1);
    let esvcpk_ids = graph.get_component_ids_by_type(RegisteredComponent::ESVCPK);
    assert_eq!(esvcpk_ids.len(), 1);
    assert_ne!(bbs_sd_dncps_ids[0], esvcpk_ids[0]);

    println!("DESCRIPTOR:\n\n{}", descriptor);
}

#[test]
fn describe_three_component_graph_with_range_check() {
    let graph = BbsSdDncpsPlusRangeCheckAndDeviceBinding::create_graph(
        BbsSdDncpsPlusRangeCheckAndDeviceBindingSetupArgs {
            pk_x_idx: 3,
            pk_y_idx: 4,
            range_idx: 2,
        },
        "suffix",
    )
    .unwrap();

    let descriptor = graph.describe();
    assert_eq!(descriptor.components.len(), 3);
    // equalities: BBS_SD_DNCPS<->ESVCPK x2, plus one tying BBS_SD_DNCPS to Range
    assert_eq!(descriptor.equalities.len(), 3);

    let mut names: Vec<_> = descriptor
        .components
        .iter()
        .map(|c| c.registered_component_id)
        .collect();
    names.sort_by_key(|c| c.as_key());
    assert_eq!(
        names,
        vec![
            RegisteredComponent::BBS_SD_DNCPS,
            RegisteredComponent::ESVCPK,
            RegisteredComponent::RANGE_CHECK_BPP
        ]
    );
    assert!(descriptor
        .components
        .iter()
        .all(|c| !c.description.is_empty()));

    let printed = descriptor.to_string();
    assert!(printed.contains("PkX"));
    assert!(printed.contains("PkY"));
    assert!(printed.contains("BbsSdDncpsCommitmentHandle"));
    assert!(printed.contains("RangeCheckBppCommitmentHandle"));

    // Lookup helpers
    let bbs_sd_dncps_ids = graph.get_component_ids_by_type(RegisteredComponent::BBS_SD_DNCPS);
    let esvcpk_ids = graph.get_component_ids_by_type(RegisteredComponent::ESVCPK);
    let range_ids = graph.get_component_ids_by_type(RegisteredComponent::RANGE_CHECK_BPP);
    assert_eq!(bbs_sd_dncps_ids.len(), 1);
    assert_eq!(esvcpk_ids.len(), 1);
    assert_eq!(range_ids.len(), 1);
    assert!(bbs_sd_dncps_ids[0] != esvcpk_ids[0] && bbs_sd_dncps_ids[0] != range_ids[0]);

    println!("DESCRIPTOR:\n\n{}", descriptor);
}

#[test]
fn unique_component_errors_when_missing_or_duplicate() {
    let graph = BbsSdDncps::create_graph(BbsSdDncpsSetupArgs, "desc").unwrap();
    assert!(graph
        .get_unique_component_id_by_type(RegisteredComponent::RANGE_CHECK_BPP)
        .is_err());

    // Construct a graph with two BBS_SD_DNCPS components to force duplicate error
    let mut g = graph.clone();
    let _ = g
        .add_component(RegisteredComponent::BBS_SD_DNCPS, "other")
        .unwrap();
    let err = g
        .get_unique_component_id_by_type(RegisteredComponent::BBS_SD_DNCPS)
        .expect_err("should fail with duplicate components");
    assert!(
        err.to_string().contains("expected exactly one component"),
        "unexpected error: {err}"
    );
}

use ark_bls12_381::Fr as BlsFr;
use foccacia::{
    implementations::{
        components::range_check_bpp::{
            range_check_bpp_component, RangeCheckBppCommitArgs, RangeCheckBppCommonSetupArgs,
            RangeCheckBppProveArgs, RangeCheckBppVerifyArgs,
        },
        registry::RegisteredComponent,
    },
    types::api_types::*,
    CCCGraph, CCCResult,
};
use std::collections::HashMap;

fn build_basic_graph() -> (CCCGraph, ComponentId, AllApiCommonSetupArgs) {
    let mut components = HashMap::new();
    let range_id = ComponentId::new(RegisteredComponent::RANGE_CHECK_BPP, "Range".to_string());
    components.insert(range_id.clone(), range_check_bpp_component());
    let graph = CCCGraph::from_map(components);
    let setup_args = RangeCheckBppCommonSetupArgs {
        num_bits: 64,
        label: b"range-test".to_vec(),
    }
    .to_api()
    .unwrap();
    let mut setup_map = HashMap::new();
    setup_map.insert(range_id.clone(), setup_args);
    (graph, range_id, setup_map)
}

#[test]
fn range_check_bpp_happy_path() -> CCCResult<()> {
    let (graph, range_id, setup_args) = build_basic_graph();

    let commit_args = RangeCheckBppCommitArgs {
        value: BlsFr::from(42u64),
    }
    .to_api()?;
    let mut commit_map = HashMap::new();
    commit_map.insert(range_id.clone(), commit_args);

    let prove_args = RangeCheckBppProveArgs {
        min: 10,
        max: 100,
        transcript_label: None,
    }
    .to_api()?;
    let mut prove_map = HashMap::new();
    prove_map.insert(range_id.clone(), prove_args);

    let verify_args = RangeCheckBppVerifyArgs {
        min: 10,
        max: 100,
        transcript_label: None,
    }
    .to_api()?;
    let mut verify_map = HashMap::new();
    verify_map.insert(range_id, verify_args);

    let setups = graph.setup_common(&setup_args)?;
    let (commits_for_prover, commits_for_verifier) = graph.commit(&setups, &commit_map)?;
    let proofs = graph.prove(
        &setups,
        &commits_for_prover,
        &commits_for_verifier,
        &prove_map,
    )?;
    graph.verify(&setups, &commits_for_verifier, &verify_map, &proofs)
}

#[test]
fn range_check_bpp_out_of_range_fails() {
    let (graph, range_id, setup_args) = build_basic_graph();

    let commit_args = RangeCheckBppCommitArgs {
        value: BlsFr::from(150u64),
    }
    .to_api()
    .unwrap();
    let mut commit_map = HashMap::new();
    commit_map.insert(range_id.clone(), commit_args);

    let prove_args = RangeCheckBppProveArgs {
        min: 10,
        max: 100,
        transcript_label: None,
    }
    .to_api()
    .unwrap();
    let mut prove_map = HashMap::new();
    prove_map.insert(range_id, prove_args);

    let setups = graph.setup_common(&setup_args).unwrap();
    let (commits_for_prover, commits_for_verifier) = graph.commit(&setups, &commit_map).unwrap();
    let err = match graph.prove(
        &setups,
        &commits_for_prover,
        &commits_for_verifier,
        &prove_map,
    ) {
        Ok(_) => panic!("expected out of range"),
        Err(e) => e,
    };
    assert!(err.to_string().contains("value is outside supplied bounds"));
}

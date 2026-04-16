use crate::{
    types::api_types::*, ApiCommitArgs, ApiCommonSetup, ApiCommonSetupArgs, ApiComponentProof,
    ApiProveArgs, ApiVerifyArgs, CCCError, CCCGraph, CCCResult, ComposableCommittedComponent,
};
use std::collections::HashMap;

fn create_one_common_setup(
    component: &ComposableCommittedComponent,
    setup_args: &ApiCommonSetupArgs,
) -> CCCResult<ApiCommonSetup> {
    (component.common_setup_api)(setup_args)
}

/// Create commitments by name; returns map keyed by component name.
pub fn create_all_common_setups_for_graph(
    graph: &CCCGraph,
    setups: &AllApiCommonSetupArgs,
) -> CCCResult<AllApiCommonSetups> {
    let mut out = HashMap::with_capacity(graph.components_map().len());
    for (id, component) in graph.components_map() {
        let setup_args = setups.get(id).ok_or_else(|| {
            CCCError::General(format!("missing setup args for component: {}", id.label()))
        })?;
        let cr = create_one_common_setup(component, setup_args)?;
        out.insert(id.clone(), cr);
    }
    Ok(out)
}

pub fn create_one_commitment(
    component: &ComposableCommittedComponent,
    setup: &ApiCommonSetup,
    commit_args: &ApiCommitArgs,
) -> CCCResult<(ApiCommitmentOpenings, ApiCommitments)> {
    (component.commit_api)(setup, commit_args)
}

/// Create commitments by name; returns map keyed by component name.
pub fn create_all_commitments_for_graph(
    graph: &CCCGraph,
    setups: &AllApiCommonSetups,
    commit_args: &AllApiCommitArgs,
) -> CCCResult<(AllApiCommitmentOpenings, AllApiCommitments)> {
    let mut values_map = HashMap::with_capacity(graph.components_map().len());
    let mut commitments_map = HashMap::with_capacity(graph.components_map().len());
    for (id, component) in graph.components_map() {
        let setup = setups.get(id).ok_or_else(|| {
            CCCError::General(format!("missing setup for component name: {}", id.label()))
        })?;
        let args = commit_args.get(id).ok_or_else(|| {
            CCCError::General(format!(
                "missing commit args for component name: {}",
                id.label()
            ))
        })?;
        let (values, commits) = create_one_commitment(component, setup, args)?;
        values_map.insert(id.clone(), values);
        commitments_map.insert(id.clone(), commits);
    }
    Ok((values_map, commitments_map))
}

fn create_one_proof(
    component: &ComposableCommittedComponent,
    setup: &ApiCommonSetup,
    commitment_openings: &ApiCommitmentOpenings,
    commitments: &ApiCommitments,
    prove_args: &ApiProveArgs,
) -> CCCResult<ApiComponentProof> {
    (component.prove_api)(setup, commitment_openings, commitments, prove_args)
}

fn verify_one_proof(
    component: &ComposableCommittedComponent,
    setup: &ApiCommonSetup,
    commitments: &ApiCommitments,
    verify_args: &ApiVerifyArgs,
    proof: &ApiComponentProof,
) -> CCCResult<()> {
    (component.verify_api)(setup, commitments, verify_args, proof)
}

pub fn create_all_proofs_for_graph(
    graph: &CCCGraph,
    setups: &AllApiCommonSetups,
    commitment_openings: &AllApiCommitmentOpenings,
    commitments: &AllApiCommitments,
    prove_args: &AllApiProveArgs,
) -> CCCResult<AllApiComponentProofs> {
    let mut out = HashMap::with_capacity(graph.components_map().len());
    for (id, component) in graph.components_map() {
        let setup = setups.get(id).ok_or_else(|| {
            CCCError::General(format!("missing setup for component: {}", id.label()))
        })?;
        let values_for_component = commitment_openings.get(id).ok_or_else(|| {
            CCCError::General(format!(
                "missing commitment values for component: {}",
                id.label()
            ))
        })?;
        let commitments_for_component = commitments.get(id).ok_or_else(|| {
            CCCError::General(format!("missing commitments for component: {}", id.label()))
        })?;
        let args = prove_args.get(id).ok_or_else(|| {
            CCCError::General(format!("missing prove args for component: {}", id.label()))
        })?;
        let pr = create_one_proof(
            component,
            setup,
            values_for_component,
            commitments_for_component,
            args,
        )?;
        out.insert(id.clone(), pr);
    }
    Ok(out)
}
pub fn verify_all_proofs_for_graph(
    graph: &CCCGraph,
    setups: &AllApiCommonSetups,
    commitments_for_verifier: &AllApiCommitments,
    verify_args: &AllApiVerifyArgs,
    proofs: &AllApiComponentProofs,
) -> CCCResult<()> {
    for (id, component) in graph.components_map() {
        let setup = setups.get(id).ok_or_else(|| {
            CCCError::General(format!("missing setup for component: {}", id.label()))
        })?;
        let commitment_for_verifier = commitments_for_verifier.get(id).ok_or_else(|| {
            CCCError::General(format!(
                "missing verifier commitment for component name: {}",
                id.label()
            ))
        })?;
        let args = verify_args.get(id).ok_or_else(|| {
            CCCError::General(format!("missing verify args for component: {}", id.label()))
        })?;
        let proof = proofs.get(id).ok_or_else(|| {
            CCCError::General(format!("missing proof for component: {}", id.label()))
        })?;
        let _ = verify_one_proof(component, setup, commitment_for_verifier, args, proof)?;
    }
    Ok(())
}

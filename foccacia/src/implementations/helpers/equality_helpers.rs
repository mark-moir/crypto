use crate::{
    implementations::ccc_graph::EqualitySpec, types::api_types::*, CCCError, CCCGraph, CCCResult,
    EqualityOfCommittedValues,
};
use std::collections::HashMap;

fn resolve_common_setup<'a>(
    common_setups: &'a AllApiCommonSetups,
    id: &ComponentId,
) -> CCCResult<&'a ApiCommonSetup> {
    common_setups.get(id).ok_or_else(|| {
        CCCError::General(format!(
            "common setup for component '{}' not found",
            id.label()
        ))
    })
}

fn resolve_commit_returns<'a>(
    commitment_openings: &'a AllApiCommitmentOpenings,
    commitments: &'a AllApiCommitments,
    id: &ComponentId,
) -> CCCResult<(&'a ApiCommitmentOpenings, &'a ApiCommitments)> {
    let values = commitment_openings.get(id).ok_or_else(|| {
        CCCError::General(format!(
            "commitment values for component '{}' not found",
            id.label()
        ))
    })?;
    let commitments = commitments.get(id).ok_or_else(|| {
        CCCError::General(format!(
            "commitment outputs for component '{}' not found",
            id.label()
        ))
    })?;
    Ok((values, commitments))
}

struct EdgeShared<'a> {
    id_1: &'a ComponentId,
    id_2: &'a ComponentId,
    handle_1: &'a ApiCommitmentHandle,
    handle_2: &'a ApiCommitmentHandle,
    common_setup_1: &'a ApiCommonSetup,
    common_setup_2: &'a ApiCommonSetup,
}

impl<'a> EdgeShared<'a> {
    fn new(common_setups: &'a AllApiCommonSetups, spec: &'a EqualitySpec) -> CCCResult<Self> {
        let (id_1, key_1) = (&spec.component_1.0, &spec.component_1.1);
        let (id_2, key_2) = (&spec.component_2.0, &spec.component_2.1);
        let common_setup_1 = resolve_common_setup(common_setups, id_1)?;
        let common_setup_2 = resolve_common_setup(common_setups, id_2)?;
        Ok(Self {
            id_1,
            id_2,
            handle_1: key_1,
            handle_2: key_2,
            common_setup_1,
            common_setup_2,
        })
    }
}

fn prove_one_edge(
    common_setups: &AllApiCommonSetups,
    commitment_openings: &AllApiCommitmentOpenings,
    commitments: &AllApiCommitments,
    spec: &EqualitySpec,
) -> CCCResult<ApiEqualityProof> {
    let edge = EdgeShared::new(common_setups, spec)?;

    let (values_1_map, commitments_1_map) =
        resolve_commit_returns(commitment_openings, commitments, edge.id_1)?;
    let (values_2_map, commitments_2_map) =
        resolve_commit_returns(commitment_openings, commitments, edge.id_2)?;

    let values_1 = values_1_map.get(edge.handle_1).ok_or_else(|| {
        CCCError::General(format!(
            "commitment values for handle '{}' on component '{}' not found",
            edge.handle_1.0,
            edge.id_1.label()
        ))
    })?;
    let values_2 = values_2_map.get(edge.handle_2).ok_or_else(|| {
        CCCError::General(format!(
            "commitment values for handle '{}' on component '{}' not found",
            edge.handle_2.0,
            edge.id_2.label()
        ))
    })?;

    let commitment_1 = commitments_1_map.get(edge.handle_1).ok_or_else(|| {
        CCCError::General(format!(
            "commitment for handle '{}' on component '{}' not found",
            edge.handle_1.0,
            edge.id_1.label()
        ))
    })?;
    let commitment_2 = commitments_2_map.get(edge.handle_2).ok_or_else(|| {
        CCCError::General(format!(
            "commitment for handle '{}' on component '{}' not found",
            edge.handle_2.0,
            edge.id_2.label()
        ))
    })?;

    let equality_helper: EqualityOfCommittedValues = spec.equality.get_equality();

    (equality_helper.prove_api)(
        edge.common_setup_1,
        edge.common_setup_2,
        values_1,
        values_2,
        commitment_1,
        commitment_2,
    )
}

pub fn create_equality_proofs_for_graph_by_label(
    graph: &CCCGraph,
    common_setups_by_label: &AllApiCommonSetups,
    commitment_openings: &AllApiCommitmentOpenings,
    commitments: &AllApiCommitments,
) -> CCCResult<AllApiEqualityProofs> {
    let specs_by_label = graph.equalities_map();
    let mut out = HashMap::with_capacity(specs_by_label.len());
    for (label, spec) in specs_by_label {
        let proof = prove_one_edge(
            common_setups_by_label,
            commitment_openings,
            commitments,
            spec,
        )?;
        out.insert(label.clone(), proof);
    }
    Ok(out)
}

fn verify_one_edge(
    common_setups: &AllApiCommonSetups,
    commit_outputs_by_id: &AllApiCommitments,
    spec: &EqualitySpec,
    proof: &ApiEqualityProof,
) -> CCCResult<()> {
    let edge = EdgeShared::new(common_setups, spec)?;

    let commitment_1 = commit_outputs_by_id
        .get(edge.id_1)
        .and_then(|m| m.get(edge.handle_1))
        .ok_or_else(|| {
            CCCError::General(format!(
                "verifier commitment for handle '{}' on component '{}' not found",
                edge.handle_1.0,
                edge.id_1.label()
            ))
        })?;
    let commitment_2 = commit_outputs_by_id
        .get(edge.id_2)
        .and_then(|m| m.get(edge.handle_2))
        .ok_or_else(|| {
            CCCError::General(format!(
                "verifier commitment for handle '{}' on component '{}' not found",
                edge.handle_2.0,
                edge.id_2.label()
            ))
        })?;

    let equality_helper: EqualityOfCommittedValues = spec.equality.get_equality();

    (equality_helper.verify_api)(
        edge.common_setup_1,
        edge.common_setup_2,
        commitment_1,
        commitment_2,
        proof,
    )
}

pub fn verify_equality_proofs_for_graph_by_label(
    graph: &CCCGraph,
    common_setups: &AllApiCommonSetups,
    commitments_for_verifier: &AllApiCommitments,
    proofs_by_label: &AllApiEqualityProofs,
) -> CCCResult<()> {
    let specs_by_label = graph.equalities_map();
    // Key-set equality check
    if specs_by_label.len() != proofs_by_label.len() {
        return Err(CCCError::General(
            "number of proofs does not match equality specs".to_string(),
        ));
    }
    for label in specs_by_label.keys() {
        if !proofs_by_label.contains_key(label) {
            return Err(CCCError::General(format!(
                "missing proof for edge label: {label}"
            )));
        }
    }
    for (label, spec) in specs_by_label {
        let proof = proofs_by_label
            .get(label)
            .ok_or_else(|| CCCError::General(format!("missing proof for edge label: {label}")))?;
        verify_one_edge(common_setups, commitments_for_verifier, spec, proof)?;
    }
    Ok(())
}

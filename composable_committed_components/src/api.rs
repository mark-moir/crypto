use std::{collections::HashMap, fmt};

use crate::{
    implementations::registry::{RegisteredComponent, RegisteredEquality},
    types::{api_types::*, error::CCCResult},
    CCCGraph,
};
/// Runtime-facing operations available on a CCCGraph.
pub trait CCCGraphApi {
    // -------------------------------------------------------------------------
    // Methods for examining graph in preparation for using it
    // -------------------------------------------------------------------------

    /// Describe the graph to aid callers in building argument maps.
    fn describe(&self) -> GraphDescriptor;
    /// Validate internal references among edges and components.
    fn validate(&self) -> CCCResult<()>;
    /// Get ComponentId of the unique component with the provided label (error if none or multiple)
    fn get_unique_component_id_by_type(&self, label: RegisteredComponent)
        -> CCCResult<ComponentId>;
    /// Get ComponentIds of all components with the provided label.
    fn get_component_ids_by_type(&self, label: RegisteredComponent) -> Vec<ComponentId>;

    // -------------------------------------------------------------------------
    // Methods for using graph
    // -------------------------------------------------------------------------

    /// Run setup for all components in the graph using provided args.
    fn setup(&self, args: &AllApiCommonSetupArgs) -> CCCResult<AllApiCommonSetups>;
    /// Commit for all components using prior setups and commit args.
    fn commit(
        &self,
        setups: &AllApiCommonSetups,
        args: &AllApiCommitArgs,
    ) -> CCCResult<(AllApiCommitmentOpenings, AllApiCommitments)>;
    /// Prove for all components and equalities.
    fn prove(
        &self,
        setups: &AllApiCommonSetups,
        commitment_openings: &AllApiCommitmentOpenings,
        commitments: &AllApiCommitments,
        args: &AllApiProveArgs,
    ) -> CCCResult<AllApiProofs>;
    /// Verify all component proofs and equality proofs.
    fn verify(
        &self,
        setups: &AllApiCommonSetups,
        commitments_for_verifier: &AllApiCommitments,
        args: &AllApiVerifyArgs,
        proofs: &AllApiProofs,
    ) -> CCCResult<()>;
}

/// Builder/inspection operations for constructing or introspecting a graph.
pub trait CCCGraphMaker {
    fn from_map(components: AllComposableCommittedComponents) -> Self
    where
        Self: Sized;
    fn from_parts(
        components: AllComposableCommittedComponents,
        equality_specs: HashMap<String, crate::implementations::ccc_graph::EqualitySpec>,
    ) -> CCCResult<Self>
    where
        Self: Sized;
    fn add_component(
        &mut self,
        component: RegisteredComponent,
        suffix: impl Into<String>,
    ) -> CCCResult<ComponentId>;
    fn add_equality_spec(
        &mut self,
        equality: RegisteredEquality,
        label_suffix: impl Into<String>,
        component_1: (ComponentId, ApiCommitmentHandle),
        component_2: (ComponentId, ApiCommitmentHandle),
    ) -> CCCResult<String>;
    fn merge_disjoint(&mut self, other: &Self) -> CCCResult<()>;
    fn components_map(&self) -> &AllComposableCommittedComponents;
    fn component(&self, id: &ComponentId) -> CCCResult<&crate::ComposableCommittedComponent>;
    fn equalities_map(&self) -> &HashMap<String, crate::implementations::ccc_graph::EqualitySpec>;
}

pub trait CCCGraphCreator {
    type GraphCreationArguments;

    // Suffix enables creating multiple graphs of the same type with
    // different labels, so they can be combined
    fn create_graph(
        args: Self::GraphCreationArguments,
        suffix: impl Into<String>,
    ) -> CCCResult<CCCGraph>;
}

/// Convenience blanket trait to offer a `setup` helper on graph creators.
pub trait SetupCCCGraph: CCCGraphCreator {
    fn setup(
        args: <Self as CCCGraphCreator>::GraphCreationArguments,
        suffix: impl Into<String>,
    ) -> CCCResult<CCCGraph> {
        Self::create_graph(args, suffix)
    }
}

impl<T: CCCGraphCreator> SetupCCCGraph for T {}

// -------------------------------------------------------------------------
// Graph descriptors for programmatic inspection

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct GraphDescriptor {
    pub graph_description: Option<String>,
    pub exercised_by_test: Option<String>,
    pub components: Vec<ComponentDescriptor>,
    pub equalities: Vec<EqualityDescriptor>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct ComponentDescriptor {
    pub id: ComponentId,
    pub registered_component_id: RegisteredComponent,
    pub description: String,
    pub commitment_handles: String,
    pub common_setup_args_type: String,
    pub commit_args_type: String,
    pub prove_args_type: String,
    pub verify_args_type: String,
    pub commitment_handle_type: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct EqualityEndpointDescriptor {
    pub component_id: ComponentId,
    pub commitment_handle: ApiCommitmentHandle,
    pub commitment_handle_display: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct EqualityDescriptor {
    pub label: String,
    pub equality_type: String,
    pub description: String,
    pub endpoint_1: EqualityEndpointDescriptor,
    pub endpoint_2: EqualityEndpointDescriptor,
}

impl fmt::Display for GraphDescriptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(desc) = &self.graph_description {
            writeln!(f, "Description: {}", desc)?;
        }
        if let Some(test) = &self.exercised_by_test {
            writeln!(f, "Exercised by test: {}", test)?;
        }
        writeln!(f, "Components:")?;
        if self.components.is_empty() {
            writeln!(f, "  (none)")?;
        } else {
            for comp in &self.components {
                writeln!(f, "  ComponentId: {}", comp.id,)?;
                if !comp.description.is_empty() {
                    writeln!(f, "    - {}", comp.description)?;
                }
                if !comp.commitment_handles.is_empty() {
                    writeln!(f, "    - handles: {}", comp.commitment_handles)?;
                }
                writeln!(f, "    - types:")?;
                writeln!(f, "        setup: {}", comp.common_setup_args_type)?;
                writeln!(f, "        commit_args: {}", comp.commit_args_type)?;
                writeln!(f, "        prove_args: {}", comp.prove_args_type)?;
                writeln!(f, "        verify_args: {}", comp.verify_args_type)?;
                writeln!(f, "        handle: {}", comp.commitment_handle_type)?;
            }
        }

        writeln!(f, "Equalities:")?;
        if self.equalities.is_empty() {
            writeln!(f, "  (none)")?;
        } else {
            for eq in &self.equalities {
                writeln!(f, "  Equality ID: {}", eq.label)?;
                if !eq.description.is_empty() {
                    writeln!(f, "    - {}", eq.description)?;
                }
                writeln!(f, "    - endpoints:")?;
                writeln!(
                    f,
                    "      * {} (handle: {})",
                    eq.endpoint_1.component_id, eq.endpoint_1.commitment_handle_display
                )?;
                writeln!(
                    f,
                    "      * {} (handle: {})",
                    eq.endpoint_2.component_id, eq.endpoint_2.commitment_handle_display
                )?;
            }
        }
        Ok(())
    }
}

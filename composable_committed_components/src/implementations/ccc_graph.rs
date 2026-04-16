use std::collections::{HashMap, HashSet};

use crate::{
    api::{ComponentDescriptor, EqualityDescriptor, EqualityEndpointDescriptor, GraphDescriptor},
    implementations::{
        helpers::{
            component_helpers::{
                create_all_commitments_for_graph, create_all_common_setups_for_graph,
                create_all_proofs_for_graph, verify_all_proofs_for_graph,
            },
            equality_helpers::{
                create_equality_proofs_for_graph_by_label,
                verify_equality_proofs_for_graph_by_label,
            },
        },
        registry::{RegisteredComponent, RegisteredEquality},
    },
    types::{api_types::*, error::CCCError, CCCResult},
    utils::merge_disjoint_maps,
    CCCGraph, CCCGraphApi, CCCGraphMaker, ComposableCommittedComponent,
};

/// Equality spec referencing endpoints by component name
#[derive(Clone)]
pub struct EqualitySpec {
    pub component_1: (ComponentId, ApiCommitmentHandle),
    pub component_2: (ComponentId, ApiCommitmentHandle),
    pub equality: RegisteredEquality,
}

impl EqualitySpec {
    pub fn new(
        component_1: (ComponentId, ApiCommitmentHandle),
        component_2: (ComponentId, ApiCommitmentHandle),
        equality: RegisteredEquality,
    ) -> Self {
        Self {
            component_1,
            component_2,
            equality,
        }
    }
}

impl CCCGraph {
    /// Construct from a map of component name -> component.
    pub fn from_map(components: AllComposableCommittedComponents) -> Self {
        Self {
            components,
            equality_specs: HashMap::new(),
            graph_metadata: Default::default(),
        }
    }

    /// Construct from parts and validate that all named endpoints exist.
    pub fn from_parts(
        components: AllComposableCommittedComponents,
        equality_specs: HashMap<String, EqualitySpec>,
    ) -> CCCResult<Self> {
        let graph = Self {
            components,
            equality_specs,
            graph_metadata: Default::default(),
        };
        graph.validate()?;
        Ok(graph)
    }

    fn validate_spec_references(
        &self,
        label: &str,
        spec: &EqualitySpec,
        context: &str,
    ) -> CCCResult<()> {
        if !self.components.contains_key(&spec.component_1.0) {
            return Err(CCCError::General(format!(
                "{context}: equality spec '{label}' references unknown component '{}'",
                spec.component_1.0.label()
            )));
        }
        if !self.components.contains_key(&spec.component_2.0) {
            return Err(CCCError::General(format!(
                "{context}: equality spec '{label}' references unknown component '{}'",
                spec.component_2.0.label()
            )));
        }
        Ok(())
    }

    pub fn set_graph_metadata(
        &mut self,
        description: impl Into<Option<String>>,
        exercised_by_test: impl Into<Option<String>>,
    ) {
        self.graph_metadata.description = description.into();
        self.graph_metadata.exercised_by_test = exercised_by_test.into();
    }

    /// Add a component; combination of component name and suffix must be unique.
    pub fn add_component(
        &mut self,
        component: RegisteredComponent,
        id: impl Into<String>,
    ) -> CCCResult<ComponentId> {
        let id = id.into();
        let component_id = ComponentId::new(component, id);
        if self.components.contains_key(&component_id) {
            return Err(CCCError::General(format!(
                "component with this name already exists: {}",
                component_id
            )));
        }
        self.components
            .insert(component_id.clone(), component.get_component());
        Ok(component_id)
    }

    /// Add an equality spec by label; label must be unique.
    pub fn add_equality_spec(
        &mut self,
        equality: RegisteredEquality,
        label_suffix: impl Into<String>,
        component_1: (ComponentId, ApiCommitmentHandle),
        component_2: (ComponentId, ApiCommitmentHandle),
    ) -> CCCResult<String> {
        let label = format!("{}-{}", equality.as_key(), label_suffix.into());
        if self.equality_specs.contains_key(&label) {
            return Err(CCCError::General(format!(
                "duplicate equality spec label: {label}"
            )));
        }
        let spec = EqualitySpec::new(component_1, component_2, equality);
        self.validate_spec_references(&label, &spec, "add_equality_spec")?;
        self.equality_specs.insert(label.clone(), spec);
        Ok(label)
    }

    pub fn setup_common(&self, args: &AllApiCommonSetupArgs) -> CCCResult<AllApiCommonSetups> {
        create_all_common_setups_for_graph(self, args)
    }

    /// Ensure all components are mutually reachable via equality edges.
    pub fn validate_connected(&self) -> CCCResult<()> {
        self.validate()?;

        let total = self.components.len();
        if total <= 1 {
            return Ok(());
        }

        // Build undirected adjacency from equality specs
        let mut adj: HashMap<&ComponentId, Vec<&ComponentId>> = HashMap::new();
        for (id, _) in &self.components {
            adj.insert(id, vec![]);
        }
        for spec in self.equality_specs.values() {
            adj.entry(&spec.component_1.0)
                .or_default()
                .push(&spec.component_2.0);
            adj.entry(&spec.component_2.0)
                .or_default()
                .push(&spec.component_1.0);
        }

        // BFS from an arbitrary component
        let mut visited: HashSet<ComponentId> = HashSet::new();
        if let Some(start) = self.components.keys().next().cloned() {
            let mut queue = vec![start];
            while let Some(node) = queue.pop() {
                if visited.insert(node.clone()) {
                    if let Some(neighbors) = adj.get(&node) {
                        for &n in neighbors {
                            if !visited.contains(n) {
                                queue.push(n.clone());
                            }
                        }
                    }
                }
            }
        }

        if visited.len() == total {
            Ok(())
        } else {
            let mut missing: Vec<_> = self
                .components
                .keys()
                .filter(|n| !visited.contains(n))
                .cloned()
                .collect();
            missing.sort();
            Err(CCCError::General(format!(
                "graph is not connected; unreachable components: {:?}",
                missing
            )))
        }
    }

    pub fn commit(
        &self,
        setups: &AllApiCommonSetups,
        args: &AllApiCommitArgs,
    ) -> CCCResult<(AllApiCommitmentOpenings, AllApiCommitments)> {
        create_all_commitments_for_graph(self, setups, args)
    }

    pub fn prove(
        &self,
        setups: &AllApiCommonSetups,
        commitment_openings: &AllApiCommitmentOpenings,
        commitments: &AllApiCommitments,
        args: &AllApiProveArgs,
    ) -> CCCResult<AllApiProofs> {
        let components =
            create_all_proofs_for_graph(self, setups, commitment_openings, commitments, args)?;
        let equalities = create_equality_proofs_for_graph_by_label(
            self,
            setups,
            commitment_openings,
            commitments,
        )?;
        Ok(AllApiProofs {
            components,
            equalities,
        })
    }

    pub fn verify(
        &self,
        setups: &AllApiCommonSetups,
        commitments_for_verifier: &AllApiCommitments,
        args: &AllApiVerifyArgs,
        proofs: &AllApiProofs,
    ) -> CCCResult<()> {
        // It is a common mistake to forget to verify equality of values about which committed
        // proofs are made.  Checking that the graph is fully connected helps to mitigate this risk
        // It does not entirely eliminate it, however.  For example, the CCCGraph created by
        // DncProofSystemWithDeviceBinding::setup creates two equalities between the same pair of
        // components, and this check would not catch the error of omitting one of them.  Note also that:
        // - there is little point in verifying connectedness before prove, because the prover may be dishonest
        //   and could remove the check anyway
        // - we assume that an honest verifier would not request proofs for disconnected graphs, as they
        //   could just request multiple proofs for each connected subset of components; if this is desired
        //   for some reason, we could add a trivial EqualityNotChecked eqwuality that connects components
        //   but does not verify equality
        self.validate_connected()?;
        verify_all_proofs_for_graph(
            self,
            setups,
            commitments_for_verifier,
            args,
            &proofs.components,
        )?;
        verify_equality_proofs_for_graph_by_label(
            self,
            setups,
            commitments_for_verifier,
            &proofs.equalities,
        )
    }

    pub fn merge_disjoint(&mut self, other: &CCCGraph) -> CCCResult<()> {
        merge_disjoint_maps(&mut self.components, &other.components, "component name")?;
        merge_disjoint_maps(
            &mut self.equality_specs,
            &other.equality_specs,
            "equality spec label",
        )?;
        self.validate()
    }

    pub fn components_map(&self) -> &AllComposableCommittedComponents {
        &self.components
    }

    pub fn component(&self, id: &ComponentId) -> CCCResult<&ComposableCommittedComponent> {
        self.components
            .get(id)
            .ok_or_else(|| CCCError::General(format!("component name not found: {}", id.label())))
    }

    /// Return all component ids whose registered name matches the provided value.
    pub fn get_component_ids_by_type(&self, label: RegisteredComponent) -> Vec<ComponentId> {
        let mut matches: Vec<_> = self
            .components
            .keys()
            .filter(|id| id.registered_component_id == label)
            .cloned()
            .collect();
        matches.sort_by(|a, b| a.label().cmp(&b.label()));
        matches
    }

    /// Find the single component whose label matches the provided value.
    /// Error if zero or multiple components share that label.
    pub fn get_unique_component_id_by_type(
        &self,
        label: RegisteredComponent,
    ) -> CCCResult<ComponentId> {
        let matches = self.get_component_ids_by_type(label);
        match matches.len() {
            1 => Ok(matches[0].clone()),
            0 => Err(CCCError::General(format!(
                "no component found with label '{:?}'",
                label
            ))),
            _ => Err(CCCError::General(format!(
                "expected exactly one component named '{:?}', found {}: {:?}",
                label,
                matches.len(),
                matches
            ))),
        }
    }

    pub fn equalities_map(&self) -> &HashMap<String, EqualitySpec> {
        &self.equality_specs
    }

    pub fn names_vec(&self) -> Vec<ComponentId> {
        let mut v: Vec<ComponentId> = self.components.keys().cloned().collect();
        v.sort_by(|a, b| a.label().cmp(&b.label()));
        v
    }

    pub fn validate(&self) -> CCCResult<()> {
        for (label, spec) in &self.equality_specs {
            self.validate_spec_references(label, spec, "validate_edges")?;
        }
        Ok(())
    }
}

impl CCCGraphApi for CCCGraph {
    fn setup(&self, args: &AllApiCommonSetupArgs) -> CCCResult<AllApiCommonSetups> {
        create_all_common_setups_for_graph(self, args)
    }

    fn commit(
        &self,
        setups: &AllApiCommonSetups,
        args: &AllApiCommitArgs,
    ) -> CCCResult<(AllApiCommitmentOpenings, AllApiCommitments)> {
        create_all_commitments_for_graph(self, setups, args)
    }

    fn prove(
        &self,
        setups: &AllApiCommonSetups,
        commitment_openings: &AllApiCommitmentOpenings,
        commitments: &AllApiCommitments,
        args: &AllApiProveArgs,
    ) -> CCCResult<AllApiProofs> {
        let components =
            create_all_proofs_for_graph(self, setups, commitment_openings, commitments, args)?;
        let equalities = create_equality_proofs_for_graph_by_label(
            self,
            setups,
            commitment_openings,
            commitments,
        )?;
        Ok(AllApiProofs {
            components,
            equalities,
        })
    }

    fn verify(
        &self,
        setups: &AllApiCommonSetups,
        commitments_for_verifier: &AllApiCommitments,
        args: &AllApiVerifyArgs,
        proofs: &AllApiProofs,
    ) -> CCCResult<()> {
        verify_all_proofs_for_graph(
            self,
            setups,
            commitments_for_verifier,
            args,
            &proofs.components,
        )?;
        verify_equality_proofs_for_graph_by_label(
            self,
            setups,
            commitments_for_verifier,
            &proofs.equalities,
        )
    }

    fn validate(&self) -> CCCResult<()> {
        for (label, spec) in &self.equality_specs {
            self.validate_spec_references(label, spec, "validate_edges")?;
        }
        Ok(())
    }

    fn get_component_ids_by_type(&self, label: RegisteredComponent) -> Vec<ComponentId> {
        CCCGraph::get_component_ids_by_type(self, label)
    }

    fn get_unique_component_id_by_type(
        &self,
        label: RegisteredComponent,
    ) -> CCCResult<ComponentId> {
        CCCGraph::get_unique_component_id_by_type(self, label)
    }

    fn describe(&self) -> GraphDescriptor {
        let mut components: Vec<ComponentDescriptor> = self
            .components
            .iter()
            .map(|(id, comp)| {
                let meta = &comp.metadata;
                ComponentDescriptor {
                    id: id.clone(),
                    registered_component_id: id.registered_component_id,
                    description: meta.description.to_string(),
                    commitment_handles: meta.commitment_handles.join(", "),
                    common_setup_args_type: meta.common_setup_args_type.to_string(),
                    commit_args_type: meta.commit_args_type.to_string(),
                    prove_args_type: meta.prove_args_type.to_string(),
                    verify_args_type: meta.verify_args_type.to_string(),
                    commitment_handle_type: meta.commitment_handle_type.to_string(),
                }
            })
            .collect();
        components.sort_by(|a, b| a.id.label().cmp(&b.id.label()));

        let mut equalities: Vec<EqualityDescriptor> = self
            .equality_specs
            .iter()
            .map(|(label, spec)| {
                let format_handle = |cid: &ComponentId, handle: &ApiCommitmentHandle| -> String {
                    self.components
                        .get(cid)
                        .map(|c| (c.commitment_handle_formatter)(handle))
                        .unwrap_or_else(|| "<unknown component>".to_string())
                };
                let helper = spec.equality.get_equality();
                EqualityDescriptor {
                    label: label.clone(),
                    equality_type: spec.equality.as_key().to_string(),
                    description: helper.description.to_string(),
                    endpoint_1: EqualityEndpointDescriptor {
                        component_id: spec.component_1.0.clone(),
                        commitment_handle: spec.component_1.1.clone(),
                        commitment_handle_display: format_handle(
                            &spec.component_1.0,
                            &spec.component_1.1,
                        ),
                    },
                    endpoint_2: EqualityEndpointDescriptor {
                        component_id: spec.component_2.0.clone(),
                        commitment_handle: spec.component_2.1.clone(),
                        commitment_handle_display: format_handle(
                            &spec.component_2.0,
                            &spec.component_2.1,
                        ),
                    },
                }
            })
            .collect();
        equalities.sort_by(|a, b| a.label.cmp(&b.label));

        GraphDescriptor {
            graph_description: self.graph_metadata.description.clone(),
            exercised_by_test: self.graph_metadata.exercised_by_test.clone(),
            components,
            equalities,
        }
    }
}

impl CCCGraphMaker for CCCGraph {
    fn from_map(components: AllComposableCommittedComponents) -> Self {
        CCCGraph::from_map(components)
    }

    fn from_parts(
        components: AllComposableCommittedComponents,
        equality_specs: HashMap<String, EqualitySpec>,
    ) -> CCCResult<Self> {
        CCCGraph::from_parts(components, equality_specs)
    }

    fn add_component(
        &mut self,
        component: RegisteredComponent,
        suffix: impl Into<String>,
    ) -> CCCResult<ComponentId> {
        CCCGraph::add_component(self, component, suffix)
    }

    fn add_equality_spec(
        &mut self,
        equality: RegisteredEquality,
        label_suffix: impl Into<String>,
        component_1: (ComponentId, ApiCommitmentHandle),
        component_2: (ComponentId, ApiCommitmentHandle),
    ) -> CCCResult<String> {
        CCCGraph::add_equality_spec(self, equality, label_suffix, component_1, component_2)
    }

    fn merge_disjoint(&mut self, other: &Self) -> CCCResult<()> {
        CCCGraph::merge_disjoint(self, other)
    }

    fn components_map(&self) -> &AllComposableCommittedComponents {
        CCCGraph::components_map(self)
    }

    fn component(&self, id: &ComponentId) -> CCCResult<&ComposableCommittedComponent> {
        CCCGraph::component(self, id)
    }

    fn equalities_map(&self) -> &HashMap<String, EqualitySpec> {
        CCCGraph::equalities_map(self)
    }
}

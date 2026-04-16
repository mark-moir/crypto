use crate::{
    implementations::ccc_graph::EqualitySpec,
    interfaces::{
        metadata::{prettify_type_name, ComponentMetadata},
        SpecificComposableCommittedComponent,
    },
    types::api_types::{
        AllComposableCommittedComponents, ApiCommitmentOpenings, ApiCommitments, FromApi, ToApi,
    },
    ApiCommitArgs, ApiCommitment, ApiCommitmentHandle, ApiCommonSetup, ApiCommonSetupArgs,
    ApiComponentProof, ApiEqualityProof, ApiProveArgs, ApiValueAndRandomness, ApiVerifyArgs,
    CCCResult, SpecificEqualityOfCommittedValues, ValueAndRandomness,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use std::{collections::HashMap, hash::Hash, sync::Arc};

/// Graph of composable committed components plus equality edges.
#[derive(Clone, Default)]
pub struct CCCGraph {
    pub components: AllComposableCommittedComponents,
    pub equality_specs: HashMap<String, EqualitySpec>,
    pub graph_metadata: crate::interfaces::metadata::GraphMetadata,
}

/// Dynamic wrappers around the `ComposableCommittedComponent` trait.  This
/// allows us to collect heterogeneous backend implementations in a single
/// data structure while still enforcing method signatures at the edges.
///
/// Callers interact with the strongly-typed helper methods (`commit`,
/// `extract_value_and_randomness`, etc.) while the struct internally stores
/// erased closures.  This mirrors the layout in `ccc.rs` but in a type-erased,
/// thread-safe form suitable for registries and plugin systems.

#[derive(Clone)]
pub struct ComposableCommittedComponent {
    pub metadata: ComponentMetadata,
    pub common_setup_api:
        Arc<dyn Fn(&ApiCommonSetupArgs) -> CCCResult<ApiCommonSetup> + Send + Sync>,
    pub commitment_handle_formatter: Arc<dyn Fn(&ApiCommitmentHandle) -> String + Send + Sync>,

    pub commit_api: Arc<
        dyn Fn(
                &ApiCommonSetup,
                &ApiCommitArgs,
            ) -> CCCResult<(ApiCommitmentOpenings, ApiCommitments)>
            + Send
            + Sync,
    >,
    pub prove_api: Arc<
        dyn Fn(
                &ApiCommonSetup,
                &ApiCommitmentOpenings,
                &ApiCommitments,
                &ApiProveArgs,
            ) -> CCCResult<ApiComponentProof>
            + Send
            + Sync,
    >,
    pub verify_api: Arc<
        dyn Fn(
                &ApiCommonSetup,
                &ApiCommitments,
                &ApiVerifyArgs,
                &ApiComponentProof,
            ) -> CCCResult<()>
            + Send
            + Sync,
    >,
}

impl ComposableCommittedComponent {
    pub fn from_specific_component<SpecificComponent>(
        description: &'static str,
        commitment_handles: &'static [&'static str],
    ) -> Self
    where
        SpecificComponent: SpecificComposableCommittedComponent + Send + Sync + 'static,
        SpecificComponent::ValueType:
            Clone + CanonicalDeserialize + CanonicalSerialize + Send + Sync + 'static,
        SpecificComponent::RandomnessType:
            Clone + CanonicalDeserialize + CanonicalSerialize + Send + Sync + 'static,
        SpecificComponent::CommitmentType: FromApi<ApiCommitment>
            + ToApi<ApiCommitment>
            + CanonicalDeserialize
            + CanonicalSerialize
            + Clone
            + Send
            + Sync
            + 'static,
        ValueAndRandomness<SpecificComponent::ValueType, SpecificComponent::RandomnessType>:
            ToApi<ApiValueAndRandomness>,
        ValueAndRandomness<SpecificComponent::ValueType, SpecificComponent::RandomnessType>:
            FromApi<ApiValueAndRandomness>,
        SpecificComponent::CommonSetupArgs: FromApi<ApiCommonSetupArgs> + Send + Sync + 'static,
        SpecificComponent::CommonSetup: FromApi<ApiCommonSetup> + Send + Sync + 'static,
        SpecificComponent::CommonSetup: ToApi<ApiCommonSetup> + Send + Sync + 'static,
        SpecificComponent::CommitArgs: FromApi<ApiCommitArgs> + Send + Sync + 'static,
        SpecificComponent::ProveArgs:
            FromApi<ApiProveArgs> + ToApi<ApiProveArgs> + Send + Sync + 'static,
        SpecificComponent::Proof:
            FromApi<ApiComponentProof> + ToApi<ApiComponentProof> + Send + Sync + 'static,
        SpecificComponent::VerifyArgs: FromApi<ApiVerifyArgs> + Send + Sync + 'static,
        SpecificComponent::CommitmentHandle: FromApi<ApiCommitmentHandle>
            + ToApi<ApiCommitmentHandle>
            + Eq
            + Hash
            + std::fmt::Debug
            + Send
            + Sync
            + 'static,
    {
        let metadata = ComponentMetadata {
            description,
            commitment_handles,
            common_setup_args_type: prettify_type_name(std::any::type_name::<
                SpecificComponent::CommonSetupArgs,
            >()),
            commit_args_type: prettify_type_name(std::any::type_name::<
                SpecificComponent::CommitArgs,
            >()),
            prove_args_type: prettify_type_name(
                std::any::type_name::<SpecificComponent::ProveArgs>(),
            ),
            verify_args_type: prettify_type_name(std::any::type_name::<
                SpecificComponent::VerifyArgs,
            >()),
            commitment_handle_type: prettify_type_name(std::any::type_name::<
                SpecificComponent::CommitmentHandle,
            >()),
        };
        let common_setup_api = Arc::new(
            move |common_setup_args: &ApiCommonSetupArgs| -> CCCResult<ApiCommonSetup> {
                let internal_setup_args =
                    SpecificComponent::CommonSetupArgs::from_api(common_setup_args.clone())?;
                SpecificComponent::common_setup(&internal_setup_args)?.to_api()
            },
        );

        let commit_api = Arc::new(
            move |common_setup: &ApiCommonSetup,
                  commit_args: &ApiCommitArgs|
                  -> CCCResult<(ApiCommitmentOpenings, ApiCommitments)> {
                let internal_setup =
                    SpecificComponent::CommonSetup::from_api(common_setup.clone())?;
                let internal_args = SpecificComponent::CommitArgs::from_api(commit_args.clone())?;
                let (values, commitments) =
                    SpecificComponent::commit(&internal_setup, &internal_args)?;

                let mut values_api = ApiCommitmentOpenings::new();
                for (handle, vr) in values {
                    values_api.insert(handle.to_api()?, vr.to_api()?);
                }
                let mut commitments_api = ApiCommitments::new();
                for (handle, comm) in commitments {
                    commitments_api.insert(handle.to_api()?, comm.to_api()?);
                }
                Ok((values_api, commitments_api))
            },
        );

        let prove_api = Arc::new(
            move |common_setup: &ApiCommonSetup,
                  values_map: &ApiCommitmentOpenings,
                  commitments_map: &ApiCommitments,
                  prove_args: &ApiProveArgs|
                  -> CCCResult<ApiComponentProof> {
                let internal_setup =
                    SpecificComponent::CommonSetup::from_api(common_setup.clone())?;
                let internal_prove_args =
                    SpecificComponent::ProveArgs::from_api(prove_args.clone())?;

                let mut internal_values = HashMap::new();
                for (handle, vr) in values_map {
                    internal_values.insert(
                        SpecificComponent::CommitmentHandle::from_api(handle.clone())?,
                        ValueAndRandomness::from_api(vr.clone())?,
                    );
                }
                let mut internal_commitments = HashMap::new();
                for (handle, comm) in commitments_map {
                    internal_commitments.insert(
                        SpecificComponent::CommitmentHandle::from_api(handle.clone())?,
                        SpecificComponent::CommitmentType::from_api(comm.clone())?,
                    );
                }

                let proof = SpecificComponent::prove(
                    &internal_setup,
                    &internal_values,
                    &internal_commitments,
                    &internal_prove_args,
                )?;
                proof.to_api()
            },
        );

        let verify_api = Arc::new(
            move |common_setup: &ApiCommonSetup,
                  commitments_map: &ApiCommitments,
                  verify_args: &ApiVerifyArgs,
                  proof: &ApiComponentProof|
                  -> CCCResult<()> {
                let internal_setup =
                    SpecificComponent::CommonSetup::from_api(common_setup.clone())?;
                let internal_verify_args =
                    SpecificComponent::VerifyArgs::from_api(verify_args.clone())?;
                let internal_proof = SpecificComponent::Proof::from_api(proof.clone())?;

                let mut internal_commitments = HashMap::new();
                for (handle, comm) in commitments_map {
                    internal_commitments.insert(
                        SpecificComponent::CommitmentHandle::from_api(handle.clone())?,
                        SpecificComponent::CommitmentType::from_api(comm.clone())?,
                    );
                }
                SpecificComponent::verify(
                    &internal_setup,
                    &internal_commitments,
                    &internal_verify_args,
                    &internal_proof,
                )
            },
        );

        let commitment_handle_formatter = Arc::new(|h: &ApiCommitmentHandle| -> String {
            SpecificComponent::CommitmentHandle::from_api(h.clone())
                .map(|decoded| format!("{:?}", decoded))
                .unwrap_or_else(|_| "commitment_handle_formatter: <decode error>".to_string())
        });

        Self {
            metadata,
            common_setup_api,
            commitment_handle_formatter,
            commit_api,
            prove_api,
            verify_api,
        }
    }
}

/// Dynamic wrapper around `EqualityOfCommittedValues`. The closures accept opaque
/// API representations and convert them to the concrete backend types before
/// delegating to the underlying implementation.
#[derive(Clone)]
pub struct EqualityOfCommittedValues {
    pub description: &'static str,
    pub prove_api: Arc<
        dyn Fn(
                &ApiCommonSetup,
                &ApiCommonSetup,
                &ApiValueAndRandomness,
                &ApiValueAndRandomness,
                &ApiCommitment,
                &ApiCommitment,
            ) -> CCCResult<ApiEqualityProof>
            + Send
            + Sync,
    >,
    pub verify_api: Arc<
        dyn Fn(
                &ApiCommonSetup,
                &ApiCommonSetup,
                &ApiCommitment,
                &ApiCommitment,
                &ApiEqualityProof,
            ) -> CCCResult<()>
            + Send
            + Sync,
    >,
}

impl EqualityOfCommittedValues {
    pub fn from_components_and_equality<N1, N2, Eq>(description: &'static str) -> Self
    where
        N1: SpecificComposableCommittedComponent + Send + Sync + 'static,
        N1::CommonSetup: FromApi<ApiCommonSetup>,
        N2: SpecificComposableCommittedComponent + Send + Sync + 'static,
        N2::CommonSetup: FromApi<ApiCommonSetup>,
        Eq: SpecificEqualityOfCommittedValues<N1, N2> + Send + Sync + 'static,
        N1::ValueType: Clone + CanonicalDeserialize + CanonicalSerialize + Send + Sync + 'static,
        N1::RandomnessType: Clone + CanonicalDeserialize + CanonicalSerialize + Send + Sync + 'static,
        N1::CommitmentType: Clone
            + CanonicalDeserialize
            + CanonicalSerialize
            + Send
            + Sync
            + ToApi<ApiCommitment>
            + FromApi<ApiCommitment>
            + 'static,
        N2::ValueType: Clone + CanonicalDeserialize + CanonicalSerialize + Send + Sync + 'static,
        N2::RandomnessType: Clone + CanonicalDeserialize + CanonicalSerialize + Send + Sync + 'static,
        N2::CommitmentType: Clone
            + CanonicalDeserialize
            + CanonicalSerialize
            + Send
            + Sync
            + ToApi<ApiCommitment>
            + FromApi<ApiCommitment>
            + 'static,
        Eq::Proof: Clone + Send + Sync + ToApi<ApiEqualityProof> + FromApi<ApiEqualityProof> + 'static,
        ValueAndRandomness<N1::ValueType, N1::RandomnessType>:
            FromApi<ApiValueAndRandomness> + ToApi<ApiValueAndRandomness>,
        ValueAndRandomness<N2::ValueType, N2::RandomnessType>:
            FromApi<ApiValueAndRandomness> + ToApi<ApiValueAndRandomness>,
    {
        let prove_api = Arc::new(
            move |common_setup_1_api: &ApiCommonSetup,
                  common_setup_2_api: &ApiCommonSetup,
                  var1_api: &ApiValueAndRandomness,
                  var2_api: &ApiValueAndRandomness,
                  commitment1_api: &ApiCommitment,
                  commitment2_api: &ApiCommitment|
                  -> CCCResult<ApiEqualityProof> {
                let common_setup_1 = N1::CommonSetup::from_api(common_setup_1_api.clone())?;
                let common_setup_2 = N2::CommonSetup::from_api(common_setup_2_api.clone())?;

                let var1 =
                    ValueAndRandomness::<N1::ValueType, N1::RandomnessType>::from_api(var1_api.clone())?;
                let var2 =
                    ValueAndRandomness::<N2::ValueType, N2::RandomnessType>::from_api(var2_api.clone())?;
                let commitment1 = N1::CommitmentType::from_api(commitment1_api.clone())?;
                let commitment2 = N2::CommitmentType::from_api(commitment2_api.clone())?;
                let proof = Eq::prove(
                    &common_setup_1,
                    &common_setup_2,
                    &var1,
                    &var2,
                    &commitment1,
                    &commitment2,
                )?;
                proof.to_api()
            },
        );

        let verify_api = Arc::new(
            move |common_setup_1_api: &ApiCommonSetup,
                  common_setup_2_api: &ApiCommonSetup,
                  commitment1_api: &ApiCommitment,
                  commitment2_api: &ApiCommitment,
                  proof_api: &ApiEqualityProof|
                  -> CCCResult<()> {
                let common_setup_1 = N1::CommonSetup::from_api(common_setup_1_api.clone())?;
                let common_setup_2 = N2::CommonSetup::from_api(common_setup_2_api.clone())?;
                let commitment1 = N1::CommitmentType::from_api(commitment1_api.clone())?;
                let commitment2 = N2::CommitmentType::from_api(commitment2_api.clone())?;
                let proof = Eq::Proof::from_api(proof_api.clone())?;
                Eq::verify(
                    &common_setup_1,
                    &common_setup_2,
                    &commitment1,
                    &commitment2,
                    &proof,
                )
            },
        );

        Self {
            description,
            prove_api,
            verify_api,
        }
    }
}

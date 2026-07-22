use std::collections::HashMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    error::CCCResult, impl_Debug_for_OpaqueMaterial_wrapper,
    implementations::registry::RegisteredComponent, types::OpaqueMaterial,
    ComposableCommittedComponent,
};

/// Traits connecting backend-native types with the API wrappers. Implementors
/// must supply lossless conversions between the two representations.
pub trait ToApi<ApiType> {
    fn to_api(self) -> CCCResult<ApiType>;
}

pub trait FromApi<ApiType>: Sized {
    fn from_api(api: ApiType) -> CCCResult<Self>;
}

impl ToApi<ApiEqualityProof> for () {
    fn to_api(self) -> CCCResult<ApiEqualityProof> {
        Ok(ApiEqualityProof(String::new()))
    }
}

impl FromApi<ApiEqualityProof> for () {
    fn from_api(_: ApiEqualityProof) -> CCCResult<Self> {
        Ok(())
    }
}

/// Opaque wrapper types used at the public API boundary. Each struct holds
/// serialized material while preserving intent through its name.

#[derive(Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct ApiCommonSetupArgs(pub OpaqueMaterial);
impl_Debug_for_OpaqueMaterial_wrapper! { ApiCommonSetupArgs }

#[derive(Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct ApiCommonSetup(pub OpaqueMaterial);
impl_Debug_for_OpaqueMaterial_wrapper! { ApiCommonSetup }

#[derive(Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq, Hash)]
pub struct ApiCommitArgs(pub OpaqueMaterial);
impl_Debug_for_OpaqueMaterial_wrapper! { ApiCommitArgs }

#[derive(Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq, Hash)]
pub struct ApiCommitmentHandle(pub OpaqueMaterial);
impl_Debug_for_OpaqueMaterial_wrapper! { ApiCommitmentHandle }

#[derive(Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq, Hash)]
pub struct ApiProveArgs(pub OpaqueMaterial);
impl_Debug_for_OpaqueMaterial_wrapper! { ApiProveArgs }

#[derive(Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq, Hash)]
pub struct ApiComponentProof(pub OpaqueMaterial);
impl_Debug_for_OpaqueMaterial_wrapper! { ApiComponentProof }

#[derive(Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq, Hash)]
pub struct ApiVerifyArgs(pub OpaqueMaterial);
impl_Debug_for_OpaqueMaterial_wrapper! { ApiVerifyArgs }

#[derive(Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq, Hash)]
pub struct ApiValueAndRandomness(pub OpaqueMaterial);
impl_Debug_for_OpaqueMaterial_wrapper! { ApiValueAndRandomness }

#[derive(Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq, Hash)]
pub struct ApiCommitment(pub OpaqueMaterial);
impl_Debug_for_OpaqueMaterial_wrapper! { ApiCommitment }

#[derive(Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct ApiEqualityProof(pub OpaqueMaterial);
impl_Debug_for_OpaqueMaterial_wrapper! { ApiEqualityProof }

#[derive(
    Clone, Debug, Serialize, Deserialize, JsonSchema, PartialEq, Eq, Hash, PartialOrd, Ord,
)]
pub struct ComponentId {
    pub registered_component_id: RegisteredComponent,
    pub instance_label: String,
}

impl ComponentId {
    pub fn new(
        registered_component_id: RegisteredComponent,
        instance_label: impl Into<String>,
    ) -> Self {
        Self {
            registered_component_id,
            instance_label: instance_label.into(),
        }
    }

    pub fn label(&self) -> String {
        format!(
            "{}-{}",
            self.registered_component_id.as_key(),
            self.instance_label
        )
    }
}

impl std::fmt::Display for ComponentId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.label())
    }
}

pub type AllApiCommonSetupArgs = HashMap<ComponentId, ApiCommonSetupArgs>;
pub type AllApiCommonSetups = HashMap<ComponentId, ApiCommonSetup>;
pub type AllApiCommitArgs = HashMap<ComponentId, ApiCommitArgs>;
pub type ApiCommitmentOpenings = HashMap<ApiCommitmentHandle, ApiValueAndRandomness>;
pub type ApiCommitments = HashMap<ApiCommitmentHandle, ApiCommitment>;
pub type AllApiCommitmentOpenings = HashMap<ComponentId, ApiCommitmentOpenings>;
pub type AllApiCommitments = HashMap<ComponentId, ApiCommitments>;
pub type AllApiProveArgs = HashMap<ComponentId, ApiProveArgs>;
pub type AllApiComponentProofs = HashMap<ComponentId, ApiComponentProof>;
pub type AllApiVerifyArgs = HashMap<ComponentId, ApiVerifyArgs>;
pub type AllApiEqualityProofs = HashMap<String, ApiEqualityProof>;
pub type AllComposableCommittedComponents = HashMap<ComponentId, ComposableCommittedComponent>;

#[derive(Clone, Serialize, Debug, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct AllApiProofs {
    pub components: AllApiComponentProofs,
    pub equalities: AllApiEqualityProofs,
}

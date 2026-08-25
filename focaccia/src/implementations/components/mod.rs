pub mod bbs_sd_dncps;
pub mod pok_ecdsa_sig_verifies_against_committed_pk;
pub mod range_check_bpp;

pub use bbs_sd_dncps::{bbs_sd_dncps_component, *};
pub use pok_ecdsa_sig_verifies_against_committed_pk::*;
pub use range_check_bpp::{
    RangeCheckBpp, RangeCheckBppCommitArgs, RangeCheckBppCommitment, RangeCheckBppCommitmentHandle,
    RangeCheckBppCommonSetup, RangeCheckBppCommonSetupArgs, RangeCheckBppProof,
    RangeCheckBppProveArgs, RangeCheckBppVerifyArgs,
};

// Helper macros to generate paired ToApi / FromApi implementations that wrap
// opaque encoding/decoding. Kept crate-private for use inside component
// conversion modules.

/// Implement Ark-serialized round-trips for a native type and its API wrapper.
#[macro_export]
macro_rules! impl_api_roundtrip_ark {
    ($native:ty => $api:path) => {
        impl $crate::types::api_types::ToApi<$api> for $native {
            fn to_api(self) -> $crate::error::CCCResult<$api> {
                Ok($api($crate::types::to_opaque_ark(&self)?))
            }
        }
        impl $crate::types::api_types::FromApi<$api> for $native {
            fn from_api(api: $api) -> $crate::error::CCCResult<Self> {
                $crate::types::from_opaque_ark(&api.0)
            }
        }
    };
}

/// Implement JSON-serialized round-trips for a native type and its API wrapper.
#[macro_export]
macro_rules! impl_api_roundtrip_json {
    ($native:ty => $api:path) => {
        impl $crate::types::api_types::ToApi<$api> for $native {
            fn to_api(self) -> $crate::error::CCCResult<$api> {
                Ok($api($crate::types::to_opaque_json(&self)?))
            }
        }
        impl $crate::types::api_types::FromApi<$api> for $native {
            fn from_api(api: $api) -> $crate::error::CCCResult<Self> {
                $crate::types::from_opaque_json(&api.0)
            }
        }
    };
}

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

impl<V, R> crate::types::api_types::ToApi<crate::ApiValueAndRandomness>
    for crate::ValueAndRandomness<V, R>
where
    V: Clone + CanonicalSerialize + CanonicalDeserialize,
    R: Clone + CanonicalSerialize + CanonicalDeserialize,
{
    fn to_api(self) -> crate::error::CCCResult<crate::ApiValueAndRandomness> {
        Ok(crate::ApiValueAndRandomness(crate::types::to_opaque_ark(
            &self,
        )?))
    }
}

impl<V, R> crate::types::api_types::FromApi<crate::ApiValueAndRandomness>
    for crate::ValueAndRandomness<V, R>
where
    V: Clone + CanonicalSerialize + CanonicalDeserialize,
    R: Clone + CanonicalSerialize + CanonicalDeserialize,
{
    fn from_api(api: crate::ApiValueAndRandomness) -> crate::error::CCCResult<Self> {
        crate::types::from_opaque_ark(&api.0)
    }
}

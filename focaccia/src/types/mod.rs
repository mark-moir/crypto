pub mod api_types;
pub use api_types::*;
pub mod error;
pub use error::*;

// ------------------------------------------------------------------------------
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::fmt::{Debug, Formatter, Result as FmtResult};

// ------------------------------------------------------------------------------
use base64::prelude::*;
use serde::{Deserialize, Serialize};
use std::str;
// ------------------------------------------------------------------------------

pub trait CCCTraits: Clone {}
impl<T: Clone> CCCTraits for T {}

#[derive(Clone, CanonicalDeserialize, CanonicalSerialize)]
pub struct ValueAndRandomness<
    Vtype: Clone + CanonicalDeserialize + CanonicalSerialize,
    Rtype: Clone + CanonicalDeserialize + CanonicalSerialize,
> {
    pub value: Vtype,
    pub randomness: Rtype,
}

impl<Vtype, Rtype> Debug for ValueAndRandomness<Vtype, Rtype>
where
    Vtype: Clone + CanonicalDeserialize + CanonicalSerialize,
    Rtype: Clone + CanonicalDeserialize + CanonicalSerialize,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        // We don't require Vtype/Rtype: Debug, so we don't print their contents.
        f.debug_struct("ValueAndRandomness")
            .field("value", &"<value>")
            .field("randomness", &"<randomness>")
            .finish()
    }
}

#[derive(Clone)]
pub struct RandomnessAndCommitment<R, C> {
    pub randomness: R,
    pub cmtmt: C,
}

pub trait CccTryFrom<T>: Sized {
    fn ccc_try_from(value: T) -> CCCResult<Self>;
}

pub fn to_api<FROM, API: CccTryFrom<FROM>>(from: FROM) -> CCCResult<API> {
    API::ccc_try_from(from)
}

pub fn from_api<API, TO: CccTryFrom<API>>(api: API) -> CCCResult<TO> {
    TO::ccc_try_from(api)
}

// ------------------------------------------------------------------------------

pub fn to_opaque_json<T: Serialize>(t: &T) -> CCCResult<String> {
    let s = serde_json::to_string(t)?;
    Ok(to_opaque(s))
}

pub fn from_opaque_json<T: for<'de> Deserialize<'de>>(s: &str) -> CCCResult<T> {
    let s = from_opaque(s)?;
    Ok(serde_json::from_slice::<T>(s.as_bytes())?)
}

// ------------------------------------------------------------------------------

pub fn to_opaque_ark<T: CanonicalSerialize>(t: &T) -> CCCResult<String> {
    let s = ark_serialize(t)?;
    Ok(to_opaque(s))
}

pub fn from_opaque_ark<T: CanonicalDeserialize>(s: &str) -> CCCResult<T> {
    let v = from_opaque_to_vec(s)?;
    let t = ark_deserialize(&v)?;
    Ok(t)
}

// ------------------------------------------------------------------------------

fn to_opaque<S: AsRef<[u8]>>(s: S) -> String {
    BASE64_STANDARD.encode(s)
}

// pub for testing
pub fn from_opaque(s_b64: &str) -> CCCResult<String> {
    let s_bytes = BASE64_STANDARD.decode(s_b64)?;
    let s_utf8 = str::from_utf8(&s_bytes)?;
    Ok(s_utf8.to_string())
}

fn from_opaque_to_vec(s_b64: &str) -> CCCResult<Vec<u8>> {
    let s_bytes = BASE64_STANDARD.decode(s_b64)?;
    Ok(s_bytes)
}

// ------------------------------------------------------------------------------

fn ark_serialize<T: CanonicalSerialize>(t: &T) -> CCCResult<Vec<u8>> {
    let mut serz = vec![];
    match CanonicalSerialize::serialize_compressed(t, &mut serz) {
        Ok(()) => Ok(serz),
        Err(e) => Err(CCCError::General(format!("ark_serialize: {e}"))),
    }
}

fn ark_deserialize<T: CanonicalDeserialize>(s: &[u8]) -> CCCResult<T> {
    match CanonicalDeserialize::deserialize_compressed(s) {
        Ok(deserz) => Ok(deserz),
        Err(e) => Err(CCCError::General(format!("ark_deserialize: {e}"))),
    }
}

// ------------------------------------------------------------------------------

pub type OpaqueMaterial = String;

/// Implements a `Debug` instance for a tuple struct wrapping `OpaqueMaterial`,
/// showing the wrapper name and a short preview of the underlying string.
#[macro_export]
macro_rules! impl_Debug_for_OpaqueMaterial_wrapper {
    ($ty: ident) => {
        impl std::fmt::Debug for $ty {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                const PREVIEW_LEN: usize = 32;
                let preview: String = self.0.chars().take(PREVIEW_LEN).collect();
                let suffix = if self.0.chars().count() > PREVIEW_LEN {
                    "…"
                } else {
                    ""
                };

                f.debug_tuple(stringify!($ty))
                    .field(&format!("{preview}{suffix}"))
                    .finish()
            }
        }
    };
}

use crate::{
    equality_by_equal_committed_values_bbs_sd_dncps_bbs_sd_dncps,
    implementations::{
        components::{
            bbs_sd_dncps::bbs_sd_dncps_component,
            pok_ecdsa_sig_verifies_against_committed_pk::esvcpk_component,
            range_check_bpp::range_check_bpp_component,
        },
        equalities::equal_committed_values_bls_bls::equality_by_equal_committed_values_bbs_sd_dncps_range,
    },
    equality_by_equal_committed_values_ecdsa_pub_key_bbs_sd_dncps, ComposableCommittedComponent, EqualityOfCommittedValues,
};
use schemars::JsonSchema;
#[derive(
    Clone,
    Copy,
    Debug,
    Eq,
    PartialEq,
    PartialOrd,
    Ord,
    Hash,
    serde::Serialize,
    serde::Deserialize,
    JsonSchema,
)]
#[allow(non_camel_case_types)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RegisteredComponent {
    BBS_SD_DNCPS,
    ESVCPK,
    RANGE_CHECK_BPP,
}

impl RegisteredComponent {
    pub fn get_component(self) -> ComposableCommittedComponent {
        match self {
            RegisteredComponent::BBS_SD_DNCPS => bbs_sd_dncps_component(),
            RegisteredComponent::ESVCPK => esvcpk_component(),
            RegisteredComponent::RANGE_CHECK_BPP => range_check_bpp_component(),
        }
    }

    /// String form used for labels; derived from the enum variant name to avoid per-variant boilerplate.
    pub fn as_key(&self) -> String {
        self.to_string()
    }
}

impl std::fmt::Display for RegisteredComponent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RegisteredEquality {
    EqualityBbsSdDncpsRange,
    EqualityByEqualCommittedValuesBlsBls,
    EqualityEcdsaPubKeyAndBbsSdDncMsgPs,
}

impl RegisteredEquality {
    pub fn get_equality(self) -> EqualityOfCommittedValues {
        match self {
            RegisteredEquality::EqualityBbsSdDncpsRange => {
                equality_by_equal_committed_values_bbs_sd_dncps_range()
            },
            RegisteredEquality::EqualityByEqualCommittedValuesBlsBls => {
                equality_by_equal_committed_values_bbs_sd_dncps_bbs_sd_dncps()
            }
            RegisteredEquality::EqualityEcdsaPubKeyAndBbsSdDncMsgPs =>
                equality_by_equal_committed_values_ecdsa_pub_key_bbs_sd_dncps(),
        }
    }

    pub fn as_key(&self) -> String {
        self.to_string()
    }
}

impl std::fmt::Display for RegisteredEquality {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

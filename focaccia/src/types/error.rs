use serde_json;

/// Errors created by this library
pub type CCCResult<T> = Result<T, CCCError>;

#[derive(Debug, Eq, PartialEq)]
pub enum CCCError {
    B64DecodeError(base64::DecodeError),
    B64DecodeSliceError(base64::DecodeSliceError),
    FromUtf8Error(std::string::FromUtf8Error),
    /// Invalid binary or text data
    DeserializationError,
    /// A generic error message
    General(String),
    SerdeError(SerdeJsonError),
    Utf8Error(std::str::Utf8Error),
}

impl std::error::Error for CCCError {}

impl std::fmt::Display for CCCError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            CCCError::B64DecodeError(err) => write!(f, "base64 decode error: {err}"),
            CCCError::B64DecodeSliceError(err) => write!(f, "base64 slice decode error: {err}"),
            CCCError::FromUtf8Error(err) => write!(f, "UTF-8 decode error: {err}"),
            CCCError::DeserializationError => write!(f, "invalid binary or textual encoding"),
            CCCError::General(msg) => write!(f, "{msg}"),
            CCCError::SerdeError(err) => write!(f, "serde json error: {err}"),
            CCCError::Utf8Error(err) => write!(f, "UTF-8 error: {err}"),
        }
    }
}

// From instances to avoid map_err boilerplate
impl From<base64::DecodeError> for CCCError {
    fn from(err: base64::DecodeError) -> Self {
        CCCError::B64DecodeError(err)
    }
}

impl From<base64::DecodeSliceError> for CCCError {
    fn from(err: base64::DecodeSliceError) -> Self {
        CCCError::B64DecodeSliceError(err)
    }
}

impl From<std::string::FromUtf8Error> for CCCError {
    fn from(err: std::string::FromUtf8Error) -> Self {
        CCCError::FromUtf8Error(err)
    }
}

impl From<std::str::Utf8Error> for CCCError {
    fn from(err: std::str::Utf8Error) -> Self {
        CCCError::Utf8Error(err)
    }
}

impl From<serde_json::Error> for CCCError {
    fn from(err: serde_json::Error) -> Self {
        CCCError::SerdeError(SerdeJsonError(err))
    }
}

#[derive(Debug)]
pub struct SerdeJsonError(pub serde_json::Error);

impl PartialEq for SerdeJsonError {
    fn eq(&self, other: &Self) -> bool {
        format!("{self:?}") == format!("{other:?}")
    }
}

impl Eq for SerdeJsonError {}

impl std::fmt::Display for SerdeJsonError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

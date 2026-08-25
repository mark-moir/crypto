#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComponentMetadata {
    pub description: &'static str,
    pub commitment_handles: &'static [&'static str],
    pub common_setup_args_type: String,
    pub commit_args_type: String,
    pub prove_args_type: String,
    pub verify_args_type: String,
    pub commitment_handle_type: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GraphMetadata {
    pub description: Option<String>,
    pub exercised_by_test: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EqualityMetadata {
    pub description: &'static str,
    pub left_common_setup_type: String,
    pub right_common_setup_type: String,
    pub left_commitment_type: String,
    pub right_commitment_type: String,
    pub proof_type: String,
}

/// Produce a shorter, human-readable type name from a fully-qualified `type_name`.
pub fn prettify_type_name(long: &'static str) -> String {
    if let Some((path, generics)) = long.split_once('<') {
        format!("{}<{}", prettify_path(path), generics)
    } else {
        prettify_path(long)
    }
}

fn prettify_path(path: &str) -> String {
    let parts: Vec<_> = path.split("::").collect();
    let keep = parts.iter().rev().take(2).cloned().collect::<Vec<_>>();
    keep.iter().rev().cloned().collect::<Vec<_>>().join("::")
}

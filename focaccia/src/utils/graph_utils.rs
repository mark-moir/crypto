use std::collections::HashMap;

use crate::error::CCCError;

/// Merge two maps, erroring if any key collides.
pub fn merge_disjoint_maps<K, V>(
    target: &mut HashMap<K, V>,
    source: &HashMap<K, V>,
    duplicate_label: &str,
) -> crate::CCCResult<()>
where
    K: Eq + std::hash::Hash + ToString + Clone,
    V: Clone,
{
    if let Some(key) = source.keys().find(|key| target.contains_key(*key)) {
        return Err(CCCError::General(format!(
            "{duplicate_label} already exists: {}",
            key.to_string()
        )));
    }

    target.extend(source.iter().map(|(k, v)| (k.clone(), v.clone())));
    Ok(())
}

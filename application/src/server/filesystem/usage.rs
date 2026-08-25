use compact_str::ToCompactString;
use std::{fmt::Debug, iter::Peekable, path::Path};

#[derive(Debug, Default, Clone, Copy)]
pub struct UsedSpace {
    logical: u64,
    physical: u64,
}

impl UsedSpace {
    #[inline]
    pub fn get_logical(&self) -> u64 {
        self.logical
    }

    #[inline]
    pub fn set_logical(&mut self, val: u64) {
        self.logical = val;
    }

    #[inline]
    pub fn sub_logical(&mut self, val: u64) {
        let logical = self.get_logical();
        self.set_logical(logical.saturating_sub(val));
    }

    #[inline]
    pub fn add_logical(&mut self, val: u64) {
        let logical = self.get_logical();
        self.set_logical(logical.saturating_add(val));
    }

    #[inline]
    pub fn get_physical(&self) -> u64 {
        self.physical
    }

    #[inline]
    pub fn set_physical(&mut self, val: u64) {
        self.physical = val;
    }

    #[inline]
    pub fn sub_physical(&mut self, val: u64) {
        let physical = self.get_physical();
        self.set_physical(physical.saturating_sub(val));
    }

    #[inline]
    pub fn add_physical(&mut self, val: u64) {
        let physical = self.get_physical();
        self.set_physical(physical.saturating_add(val));
    }

    #[inline]
    fn apply_delta(&mut self, add: UsedSpace, sub: UsedSpace) {
        self.add_logical(add.get_logical());
        self.add_physical(add.get_physical());
        self.sub_logical(sub.get_logical());
        self.sub_physical(sub.get_physical());
    }
}

impl std::ops::Add for UsedSpace {
    type Output = Self;

    #[inline]
    fn add(self, rhs: Self) -> Self::Output {
        Self {
            logical: self.logical.saturating_add(rhs.logical),
            physical: self.physical.saturating_add(rhs.physical),
        }
    }
}

impl std::iter::Sum for UsedSpace {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::default(), |acc, x| acc + x)
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct SpaceDelta {
    pub logical: i64,
    pub physical: i64,
}

impl SpaceDelta {
    #[inline]
    pub fn new(logical: i64, physical: i64) -> Self {
        Self { logical, physical }
    }

    #[inline]
    pub fn only_logical(logical: i64) -> Self {
        Self {
            logical,
            physical: 0,
        }
    }
}

impl From<i64> for SpaceDelta {
    #[inline]
    fn from(value: i64) -> Self {
        SpaceDelta {
            logical: value,
            physical: value,
        }
    }
}

/// A BTree-ish structure to track disk usage for directories (and files). Each node represents a directory, with `space` tracking the total space used by that directory and its children,
/// if the directory usage itself is required, simply aggregate all entries, and subtract them from self.space, the remaining will be the directory usage itself. The entries are stored in a sorted vector for efficient lookups and insertions.
///
/// # Importantly,
/// This structure is not supposed to store file sizes, but rather directory sizes. The `space` field of each node should represent the total size of all files in that directory and its subdirectories, while the entries represent the subdirectories.
/// This allows for efficient updates and queries of directory sizes without needing to store individual file sizes.
#[derive(Debug, Default)]
pub struct DiskUsage {
    pub space: UsedSpace,
    entries: thin_vec::ThinVec<(compact_str::CompactString, DiskUsage)>,
}

impl DiskUsage {
    fn upsert_entry(&mut self, key: &str) -> &mut DiskUsage {
        match self.entries.binary_search_by(|a| a.0.as_str().cmp(key)) {
            // SAFETY: The binary search guarantees that the index is within bounds, and the entry at that index has the same key as the provided key.
            Ok(idx) => unsafe { &mut self.entries.get_unchecked_mut(idx).1 },
            Err(idx) => {
                self.entries
                    .insert(idx, (key.to_compact_string(), DiskUsage::default()));
                // SAFETY: We just inserted an entry at the index, so it is guaranteed to be within bounds, and the entry at that index has the same key as the provided key.
                unsafe { &mut self.entries.get_unchecked_mut(idx).1 }
            }
        }
    }

    fn get_mut_entry(&mut self, key: &str) -> Option<&mut DiskUsage> {
        if let Ok(idx) = self.entries.binary_search_by(|a| a.0.as_str().cmp(key)) {
            Some(&mut self.entries.get_mut(idx)?.1)
        } else {
            None
        }
    }

    fn remove_entry(&mut self, key: &str) -> Option<DiskUsage> {
        if let Ok(idx) = self.entries.binary_search_by(|a| a.0.as_str().cmp(key)) {
            Some(self.entries.remove(idx).1)
        } else {
            None
        }
    }

    fn component_key(name: &std::ffi::OsStr) -> std::borrow::Cow<'_, str> {
        let bytes = name.as_encoded_bytes();

        match std::str::from_utf8(bytes) {
            Ok(name) => std::borrow::Cow::Borrowed(name),
            Err(_) => {
                fn hex(nibble: u8) -> char {
                    char::from_digit(nibble as u32, 16)
                        .unwrap_or('0')
                        .to_ascii_uppercase()
                }

                let mut escaped = String::with_capacity(bytes.len() + 8);
                for &byte in bytes {
                    if byte.is_ascii() && byte != b'%' {
                        escaped.push(byte as char);
                    } else {
                        escaped.push('%');
                        escaped.push(hex(byte >> 4));
                        escaped.push(hex(byte & 0x0f));
                    }
                }

                std::borrow::Cow::Owned(escaped)
            }
        }
    }

    pub fn path_component_keys(path: &Path) -> Vec<std::borrow::Cow<'_, str>> {
        path.components()
            .map(|component| Self::component_key(component.as_os_str()))
            .collect()
    }

    #[inline]
    pub fn get_entries(&self) -> &[(compact_str::CompactString, DiskUsage)] {
        &self.entries
    }

    pub fn get_size(&self, path: &Path) -> Option<UsedSpace> {
        if crate::unlikely(path == Path::new("") || path == Path::new("/")) {
            return Some(self.space);
        }

        let mut current = self;
        for component in path.components() {
            let name = Self::component_key(component.as_os_str());
            let idx = current
                .entries
                .binary_search_by(|(n, _)| n.as_str().cmp(&name))
                .ok()?;
            current = &current.entries.get(idx)?.1;
        }

        Some(current.space)
    }

    pub fn get_path(&self, path: &Path) -> Option<&DiskUsage> {
        if crate::unlikely(path == Path::new("") || path == Path::new("/")) {
            return Some(self);
        }

        let mut current = self;
        for component in path.components() {
            let name = Self::component_key(component.as_os_str());
            let idx = current
                .entries
                .binary_search_by(|(n, _)| n.as_str().cmp(&name))
                .ok()?;
            current = &current.entries.get(idx)?.1;
        }

        Some(current)
    }

    pub fn get_path_components(&self, components: &[impl AsRef<str>]) -> Option<&DiskUsage> {
        let mut current = self;
        for component in components {
            let idx = current
                .entries
                .binary_search_by(|(n, _)| n.as_str().cmp(component.as_ref()))
                .ok()?;
            current = &current.entries.get(idx)?.1;
        }

        Some(current)
    }

    pub fn update_size(&mut self, path: &Path, delta: SpaceDelta) {
        if delta.logical >= 0 {
            self.space.add_logical(delta.logical as u64);
        } else {
            self.space.sub_logical(delta.logical.unsigned_abs());
        }
        if delta.physical >= 0 {
            self.space.add_physical(delta.physical as u64);
        } else {
            self.space.sub_physical(delta.physical.unsigned_abs());
        }

        if crate::unlikely(path == Path::new("") || path == Path::new("/")) {
            return;
        }

        let mut current = self;
        for component in path.components() {
            let entry = current.upsert_entry(&Self::component_key(component.as_os_str()));

            if delta.logical >= 0 {
                entry.space.add_logical(delta.logical as u64);
            } else {
                entry.space.sub_logical(delta.logical.unsigned_abs());
            }
            if delta.physical >= 0 {
                entry.space.add_physical(delta.physical as u64);
            } else {
                entry.space.sub_physical(delta.physical.unsigned_abs());
            }

            current = entry;
        }
    }

    #[tracing::instrument(skip(self))]
    pub fn update_size_iterator(
        &mut self,
        path: impl IntoIterator<Item = impl AsRef<str> + Debug> + Debug,
        delta: SpaceDelta,
    ) {
        if delta.logical >= 0 {
            self.space.add_logical(delta.logical as u64);
        } else {
            self.space.sub_logical(delta.logical.unsigned_abs());
        }
        if delta.physical >= 0 {
            self.space.add_physical(delta.physical as u64);
        } else {
            self.space.sub_physical(delta.physical.unsigned_abs());
        }

        let mut current = self;
        for component in path {
            let entry = current.upsert_entry(component.as_ref());

            tracing::trace!(?component, "applying path delta");

            if delta.logical >= 0 {
                entry.space.add_logical(delta.logical as u64);
            } else {
                entry.space.sub_logical(delta.logical.unsigned_abs());
            }
            if delta.physical >= 0 {
                entry.space.add_physical(delta.physical as u64);
            } else {
                entry.space.sub_physical(delta.physical.unsigned_abs());
            }

            current = entry;
        }
    }

    #[tracing::instrument(skip(self))]
    pub fn remove_path(&mut self, path: &Path) -> Option<DiskUsage> {
        if crate::unlikely(path == Path::new("") || path == Path::new("/")) {
            return None;
        }

        self.recursive_remove(&mut path.components().peekable())
    }

    fn recursive_remove<'a>(
        &mut self,
        components: &mut Peekable<impl Iterator<Item = std::path::Component<'a>>>,
    ) -> Option<DiskUsage> {
        let component = components.next()?;
        let name = Self::component_key(component.as_os_str());

        tracing::trace!(?component, "applying path delta");

        if components.peek().is_none() {
            let removed = self.remove_entry(&name)?;

            self.space.sub_logical(removed.space.get_logical());
            self.space.sub_physical(removed.space.get_physical());

            return Some(removed);
        }

        if let Some(child) = self.get_mut_entry(&name)
            && let Some(removed) = child.recursive_remove(components)
        {
            self.space.sub_logical(removed.space.get_logical());
            self.space.sub_physical(removed.space.get_physical());
            return Some(removed);
        }

        None
    }

    #[inline]
    pub fn truncate(&mut self) {
        self.space.set_logical(0);
        self.space.set_physical(0);
        self.entries.clear();
    }

    #[tracing::instrument(skip(self, source_dir))]
    pub fn add_directory(
        &mut self,
        target_path: &[impl AsRef<str> + Debug],
        source_dir: DiskUsage,
    ) -> bool {
        if crate::unlikely(target_path.is_empty()) {
            return false;
        }

        let Some((leaf, parents)) = target_path.split_last() else {
            return false;
        };

        let old = self
            .get_path_components(target_path)
            .map(|d| d.space)
            .unwrap_or_default();
        let new = source_dir.space;

        let mut current = self;
        for component in parents {
            tracing::trace!(?component, "applying path delta");

            current.space.apply_delta(new, old);
            current = current.upsert_entry(component.as_ref());
        }

        current.space.apply_delta(new, old);
        *current.upsert_entry(leaf.as_ref()) = source_dir;

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn used(logical: u64, physical: u64) -> UsedSpace {
        let mut s = UsedSpace::default();
        s.set_logical(logical);
        s.set_physical(physical);
        s
    }

    #[test]
    fn distinct_non_utf8_names_do_not_share_a_node() {
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;

            let mut usage = DiskUsage::default();
            let a = Path::new(std::ffi::OsStr::from_bytes(b"dir/\xff\xfe"));
            let b = Path::new(std::ffi::OsStr::from_bytes(b"dir/\xfe\xff"));

            usage.update_size(a, SpaceDelta::new(10, 10));
            usage.update_size(b, SpaceDelta::new(7, 7));

            assert_eq!(usage.get_size(a).map(|s| s.get_logical()), Some(10));
            assert_eq!(usage.get_size(b).map(|s| s.get_logical()), Some(7));
            assert_eq!(
                usage.get_size(Path::new("dir")).map(|s| s.get_logical()),
                Some(17)
            );
        }
    }

    #[test]
    fn summed_deltas_match_applying_them_one_at_a_time() {
        let path = Path::new("a/b");

        let mut per_entry = DiskUsage::default();
        for (logical, physical) in [(3, 4), (5, 8), (11, 16)] {
            per_entry.update_size(path, SpaceDelta::new(logical, physical));
        }

        let mut summed = DiskUsage::default();
        summed.update_size(path, SpaceDelta::new(3 + 5 + 11, 4 + 8 + 16));

        assert_space(
            summed.space,
            per_entry.space.get_logical(),
            per_entry.space.get_physical(),
        );
        for probe in ["a", "a/b"] {
            let expected = per_entry.get_size(Path::new(probe)).expect("probe missing");
            let actual = summed.get_size(Path::new(probe)).expect("probe missing");

            assert_space(actual, expected.get_logical(), expected.get_physical());
        }
    }

    fn assert_space(s: UsedSpace, logical: u64, physical: u64) {
        assert_eq!(s.get_logical(), logical);
        assert_eq!(s.get_physical(), physical);
    }

    // UsedSpace

    #[test]
    fn used_space_add_and_sub() {
        let mut s = UsedSpace::default();
        s.add_logical(100);
        s.add_physical(50);
        assert_space(s, 100, 50);

        s.sub_logical(30);
        s.sub_physical(20);
        assert_space(s, 70, 30);
    }

    #[test]
    fn used_space_sub_saturates_at_zero() {
        let mut s = used(10, 10);
        s.sub_logical(1000);
        s.sub_physical(1000);
        assert_space(s, 0, 0);
    }

    #[test]
    fn used_space_add_saturates_at_max() {
        let mut s = used(u64::MAX, u64::MAX);
        s.add_logical(10);
        s.add_physical(10);
        assert_space(s, u64::MAX, u64::MAX);
    }

    #[test]
    fn used_space_add_trait_saturates() {
        assert_space(used(10, 20) + used(5, 7), 15, 27);
        assert_space(used(u64::MAX, 0) + used(5, 0), u64::MAX, 0);
    }

    #[test]
    fn used_space_sum() {
        let total: UsedSpace = [used(1, 2), used(3, 4), used(5, 6)].into_iter().sum();
        assert_space(total, 9, 12);
    }

    // SpaceDelta

    #[test]
    fn space_delta_constructors() {
        let d = SpaceDelta::new(3, 5);
        assert_eq!((d.logical, d.physical), (3, 5));

        let d = SpaceDelta::only_logical(7);
        assert_eq!((d.logical, d.physical), (7, 0));

        let d = SpaceDelta::from(9);
        assert_eq!((d.logical, d.physical), (9, 9));
    }

    // DiskUsage

    #[test]
    fn update_root_only_for_empty_path() {
        let mut du = DiskUsage::default();
        du.update_size(Path::new(""), SpaceDelta::from(100));
        assert_space(du.space, 100, 100);
        assert!(du.get_entries().is_empty());

        du.update_size(Path::new("/"), SpaceDelta::from(5));
        assert_space(du.space, 105, 105);
        assert!(du.get_entries().is_empty());
    }

    #[test]
    fn update_creates_path_and_accumulates() {
        let mut du = DiskUsage::default();
        du.update_size(Path::new("a/b"), SpaceDelta::from(100));

        assert_space(du.space, 100, 100);
        assert_space(du.get_size(Path::new("a")).unwrap(), 100, 100);
        assert_space(du.get_size(Path::new("a/b")).unwrap(), 100, 100);
    }

    #[test]
    fn update_siblings_aggregate_into_parent() {
        let mut du = DiskUsage::default();
        du.update_size(Path::new("a/b"), SpaceDelta::from(100));
        du.update_size(Path::new("a/c"), SpaceDelta::from(50));

        assert_space(du.space, 150, 150);
        assert_space(du.get_size(Path::new("a")).unwrap(), 150, 150);
        assert_space(du.get_size(Path::new("a/b")).unwrap(), 100, 100);
        assert_space(du.get_size(Path::new("a/c")).unwrap(), 50, 50);
    }

    #[test]
    fn directory_own_usage_via_subtraction() {
        let mut du = DiskUsage::default();
        du.update_size(Path::new("a/b"), SpaceDelta::from(100));
        du.update_size(Path::new("a/c"), SpaceDelta::from(50));

        let a = du.get_path(Path::new("a")).unwrap();
        let children: UsedSpace = a.get_entries().iter().map(|(_, d)| d.space).sum();
        assert_eq!(a.space.get_logical() - children.get_logical(), 0);
    }

    #[test]
    fn update_negative_delta_subtracts_and_saturates() {
        let mut du = DiskUsage::default();
        du.update_size(Path::new("a"), SpaceDelta::from(100));
        du.update_size(Path::new("a"), SpaceDelta::from(-30));
        assert_space(du.get_size(Path::new("a")).unwrap(), 70, 70);

        du.update_size(Path::new("a"), SpaceDelta::from(-1000));
        assert_space(du.get_size(Path::new("a")).unwrap(), 0, 0);
        assert_space(du.space, 0, 0);
    }

    #[test]
    fn entries_stay_sorted_regardless_of_insert_order() {
        let mut du = DiskUsage::default();
        du.update_size(Path::new("c"), SpaceDelta::from(1));
        du.update_size(Path::new("a"), SpaceDelta::from(1));
        du.update_size(Path::new("b"), SpaceDelta::from(1));

        let keys: Vec<_> = du.get_entries().iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(keys, ["a", "b", "c"]);
    }

    #[test]
    fn update_size_iterator_matches_path_form() {
        let mut du = DiskUsage::default();
        du.update_size_iterator(["a", "b"], SpaceDelta::from(100));
        assert_space(du.space, 100, 100);
        assert_space(du.get_size(Path::new("a")).unwrap(), 100, 100);
        assert_space(du.get_size(Path::new("a/b")).unwrap(), 100, 100);

        let mut empty = DiskUsage::default();
        empty.update_size_iterator(std::iter::empty::<&str>(), SpaceDelta::from(50));
        assert_space(empty.space, 50, 50);
        assert!(empty.get_entries().is_empty());
    }

    #[test]
    fn get_size_root_for_empty_and_slash() {
        let mut du = DiskUsage::default();
        du.update_size(Path::new("a"), SpaceDelta::from(42));
        assert_space(du.get_size(Path::new("")).unwrap(), 42, 42);
        assert_space(du.get_size(Path::new("/")).unwrap(), 42, 42);
    }

    #[test]
    fn get_size_missing_is_none() {
        let mut du = DiskUsage::default();
        du.update_size(Path::new("a"), SpaceDelta::from(10));
        assert!(du.get_size(Path::new("missing")).is_none());
        assert!(du.get_size(Path::new("a/missing")).is_none());
    }

    #[test]
    fn get_size_absolute_path_does_not_resolve() {
        let mut du = DiskUsage::default();
        du.update_size(Path::new("a"), SpaceDelta::from(10));
        assert!(du.get_size(Path::new("/a")).is_none());
    }

    #[test]
    fn get_path_returns_node() {
        let mut du = DiskUsage::default();
        du.update_size(Path::new("a/b"), SpaceDelta::from(100));

        let node = du.get_path(Path::new("a")).unwrap();
        assert_space(node.space, 100, 100);
        assert_eq!(node.get_entries().len(), 1);
        assert_eq!(node.get_entries()[0].0.as_str(), "b");

        assert_space(du.get_path(Path::new("")).unwrap().space, 100, 100);
    }

    #[test]
    fn remove_leaf_subtracts_from_ancestors() {
        let mut du = DiskUsage::default();
        du.update_size(Path::new("a/b"), SpaceDelta::from(100));
        du.update_size(Path::new("a/c"), SpaceDelta::from(50));

        let removed = du.remove_path(Path::new("a/b")).unwrap();
        assert_space(removed.space, 100, 100);

        assert_space(du.space, 50, 50);
        assert_space(du.get_size(Path::new("a")).unwrap(), 50, 50);
        assert!(du.get_size(Path::new("a/b")).is_none());
        assert_space(du.get_size(Path::new("a/c")).unwrap(), 50, 50);
    }

    #[test]
    fn remove_subtree_takes_children_and_updates_root() {
        let mut du = DiskUsage::default();
        du.update_size(Path::new("a/b"), SpaceDelta::from(100));
        du.update_size(Path::new("x"), SpaceDelta::from(20));

        let removed = du.remove_path(Path::new("a")).unwrap();
        assert_space(removed.space, 100, 100);
        assert_space(removed.get_size(Path::new("b")).unwrap(), 100, 100);

        assert_space(du.space, 20, 20);
        assert!(du.get_size(Path::new("a")).is_none());
        assert_space(du.get_size(Path::new("x")).unwrap(), 20, 20);
    }

    #[test]
    fn remove_missing_is_none_and_leaves_sizes() {
        let mut du = DiskUsage::default();
        du.update_size(Path::new("a"), SpaceDelta::from(100));

        assert!(du.remove_path(Path::new("missing")).is_none());
        assert!(du.remove_path(Path::new("a/missing")).is_none());

        assert_space(du.space, 100, 100);
        assert_space(du.get_size(Path::new("a")).unwrap(), 100, 100);
    }

    #[test]
    fn remove_root_variants_are_none() {
        let mut du = DiskUsage::default();
        du.update_size(Path::new("a"), SpaceDelta::from(100));
        assert!(du.remove_path(Path::new("")).is_none());
        assert!(du.remove_path(Path::new("/")).is_none());
        assert_space(du.space, 100, 100);
    }

    #[test]
    fn add_directory_empty_target_is_false() {
        let mut du = DiskUsage::default();
        let target: [&str; 0] = [];
        assert!(!du.add_directory(&target, DiskUsage::default()));
    }

    #[test]
    fn add_directory_single_leaf() {
        let mut du = DiskUsage::default();
        assert!(du.add_directory(&["leaf"], used_dir(100, 80)));

        assert_space(du.space, 100, 80);
        assert_space(du.get_size(Path::new("leaf")).unwrap(), 100, 80);
    }

    #[test]
    fn add_directory_nested_accumulates_ancestors() {
        let mut du = DiskUsage::default();
        assert!(du.add_directory(&["a", "b", "leaf"], used_dir(100, 80)));

        assert_space(du.space, 100, 80);
        assert_space(du.get_size(Path::new("a")).unwrap(), 100, 80);
        assert_space(du.get_size(Path::new("a/b")).unwrap(), 100, 80);
        assert_space(du.get_size(Path::new("a/b/leaf")).unwrap(), 100, 80);
    }

    #[test]
    fn add_directory_overwrites_leaf_and_reconciles_ancestors() {
        let mut du = DiskUsage::default();
        du.update_size(Path::new("a/leaf"), SpaceDelta::from(10));
        du.add_directory(&["a", "leaf"], used_dir(100, 80));

        assert_space(du.space, 100, 80);
        assert_space(du.get_size(Path::new("a")).unwrap(), 100, 80);
        assert_space(du.get_size(Path::new("a/leaf")).unwrap(), 100, 80);
    }

    #[test]
    fn add_directory_overwrite_smaller_shrinks_ancestors() {
        let mut du = DiskUsage::default();
        du.update_size(Path::new("a/leaf"), SpaceDelta::from(100));
        du.add_directory(&["a", "leaf"], used_dir(30, 30));

        assert_space(du.space, 30, 30);
        assert_space(du.get_size(Path::new("a")).unwrap(), 30, 30);
        assert_space(du.get_size(Path::new("a/leaf")).unwrap(), 30, 30);
    }

    fn used_dir(logical: u64, physical: u64) -> DiskUsage {
        let mut d = DiskUsage::default();
        d.space.set_logical(logical);
        d.space.set_physical(physical);
        d
    }
}

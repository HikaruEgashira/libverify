//! Union-Find (Disjoint Set Union) data structure for call graph connectivity.
//!
//! # Invariants (Creusot)
//!
//! ```text
//! #[invariant(self.parent.len() == self.rank.len())]
//! #[invariant(forall(|i| i < self.parent.len() ==> self.parent[i] < self.parent.len()))]
//! ```
//!
//! # Properties
//!
//! - `find` is idempotent: `find(find(x)) == find(x)`
//! - `merge` establishes equivalence: after `merge(x, y)`, `find(x) == find(y)`
//! - `component_count` returns the number of distinct roots among file-kind nodes

// Creusot struct-level #[invariant] requires Creusot nightly compiler.
// The structural invariants are documented and tested but not yet machine-proved.
// See doc comments on UnionFind for the intended invariants.

/// The kind of node in the call graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeKind {
    File,
    Function,
}

/// Descriptor for a node in the call graph.
#[derive(Debug, Clone)]
pub struct NodeDescriptor {
    pub file_index: u16,
    pub name: String,
    pub kind: NodeKind,
}

/// Union-Find data structure for tracking connected components in a call graph.
///
/// Invariant: `parent.len() == rank.len() == nodes.len()`
/// Invariant: `parent[i] < parent.len()` for all valid `i`
#[derive(Debug)]
pub struct UnionFind {
    nodes: Vec<NodeDescriptor>,
    parent: Vec<u32>,
    rank: Vec<u8>,
}

impl UnionFind {
    pub fn new() -> Self {
        Self {
            nodes: Vec::new(),
            parent: Vec::new(),
            rank: Vec::new(),
        }
    }

    /// Add a node. Returns existing ID if `(file_index, name)` already present.
    pub fn add_node(&mut self, file_index: u16, name: &str, kind: NodeKind) -> u32 {
        // Deduplicate by (file_index, name)
        for (i, n) in self.nodes.iter().enumerate() {
            if n.file_index == file_index && n.name == name {
                return i as u32;
            }
        }
        let id = self.nodes.len() as u32;
        self.nodes.push(NodeDescriptor {
            file_index,
            name: name.to_string(),
            kind,
        });
        self.parent.push(id); // self-parent
        self.rank.push(0);
        id
    }

    /// Find root with path compression.
    ///
    /// # Postcondition
    /// `find(find(x)) == find(x)` (idempotent)
    pub fn find(&mut self, x: u32) -> u32 {
        let mut current = x;
        while self.parent[current as usize] != current {
            // Path splitting (each node points to its grandparent)
            let parent = self.parent[current as usize];
            self.parent[current as usize] = self.parent[parent as usize];
            current = self.parent[current as usize];
        }
        current
    }

    /// Union by rank.
    ///
    /// # Postcondition
    /// After `merge(a, b)`: `find(a) == find(b)`
    pub fn merge(&mut self, a: u32, b: u32) {
        let ra = self.find(a);
        let rb = self.find(b);
        if ra == rb {
            return;
        }
        if self.rank[ra as usize] < self.rank[rb as usize] {
            self.parent[ra as usize] = rb;
        } else if self.rank[ra as usize] > self.rank[rb as usize] {
            self.parent[rb as usize] = ra;
        } else {
            self.parent[rb as usize] = ra;
            self.rank[ra as usize] += 1;
        }
    }

    /// Count distinct connected components among file-kind nodes only.
    pub fn component_count(&mut self) -> usize {
        // Collect file node indices first to avoid borrow conflict
        let file_indices: Vec<usize> = self
            .nodes
            .iter()
            .enumerate()
            .filter(|(_, n)| n.kind == NodeKind::File)
            .map(|(i, _)| i)
            .collect();

        let mut roots = std::collections::HashSet::new();
        for i in file_indices {
            let root = self.find(i as u32);
            roots.insert(root);
        }
        roots.len()
    }

    /// Return file indices grouped by component.
    pub fn get_components(&mut self) -> Vec<Vec<u16>> {
        // Collect file node info first to avoid borrow conflict
        let file_nodes: Vec<(usize, u16)> = self
            .nodes
            .iter()
            .enumerate()
            .filter(|(_, n)| n.kind == NodeKind::File)
            .map(|(i, n)| (i, n.file_index))
            .collect();

        let mut comp_map: std::collections::HashMap<u32, Vec<u16>> =
            std::collections::HashMap::new();

        for (i, file_index) in file_nodes {
            let root = self.find(i as u32);
            comp_map.entry(root).or_default().push(file_index);
        }

        comp_map.into_values().collect()
    }

    /// Get the node descriptor for a given ID.
    pub fn get_node(&self, id: u32) -> Option<&NodeDescriptor> {
        self.nodes.get(id as usize)
    }

    /// Number of nodes in the graph.
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Returns true if the graph has no nodes.
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }
}

impl Default for UnionFind {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_graph() {
        let mut uf = UnionFind::new();
        assert_eq!(uf.component_count(), 0);
        assert!(uf.is_empty());
    }

    #[test]
    fn single_node() {
        let mut uf = UnionFind::new();
        let a = uf.add_node(0, "main.rs", NodeKind::File);
        assert_eq!(uf.find(a), a);
        assert_eq!(uf.component_count(), 1);
    }

    #[test]
    fn deduplication() {
        let mut uf = UnionFind::new();
        let a = uf.add_node(0, "main.rs", NodeKind::File);
        let b = uf.add_node(0, "main.rs", NodeKind::File);
        assert_eq!(a, b);
        assert_eq!(uf.len(), 1);
    }

    #[test]
    fn merge_reduces_components() {
        let mut uf = UnionFind::new();
        let a = uf.add_node(0, "a.rs", NodeKind::File);
        let b = uf.add_node(1, "b.rs", NodeKind::File);
        assert_eq!(uf.component_count(), 2);

        uf.merge(a, b);
        assert_eq!(uf.component_count(), 1);
        assert_eq!(uf.find(a), uf.find(b));
    }

    #[test]
    fn find_is_idempotent() {
        let mut uf = UnionFind::new();
        let a = uf.add_node(0, "a.rs", NodeKind::File);
        let b = uf.add_node(1, "b.rs", NodeKind::File);
        uf.merge(a, b);

        let root1 = uf.find(a);
        let root2 = uf.find(root1);
        assert_eq!(root1, root2);
    }

    #[test]
    fn merge_is_symmetric() {
        let mut uf1 = UnionFind::new();
        let a1 = uf1.add_node(0, "a.rs", NodeKind::File);
        let b1 = uf1.add_node(1, "b.rs", NodeKind::File);
        uf1.merge(a1, b1);

        let mut uf2 = UnionFind::new();
        let a2 = uf2.add_node(0, "a.rs", NodeKind::File);
        let b2 = uf2.add_node(1, "b.rs", NodeKind::File);
        uf2.merge(b2, a2);

        // Both should have same component count
        assert_eq!(uf1.component_count(), uf2.component_count());
        assert_eq!(uf1.find(a1), uf1.find(b1));
        assert_eq!(uf2.find(a2), uf2.find(b2));
    }

    #[test]
    fn merge_is_transitive() {
        let mut uf = UnionFind::new();
        let a = uf.add_node(0, "a.rs", NodeKind::File);
        let b = uf.add_node(1, "b.rs", NodeKind::File);
        let c_node = uf.add_node(2, "c.rs", NodeKind::File);

        uf.merge(a, b);
        uf.merge(b, c_node);

        assert_eq!(uf.find(a), uf.find(c_node));
        assert_eq!(uf.component_count(), 1);
    }

    #[test]
    fn function_nodes_dont_count_as_components() {
        let mut uf = UnionFind::new();
        let file_a = uf.add_node(0, "a.rs", NodeKind::File);
        let _fn_a = uf.add_node(0, "foo", NodeKind::Function);
        let file_b = uf.add_node(1, "b.rs", NodeKind::File);

        // 2 file components (function node doesn't count)
        assert_eq!(uf.component_count(), 2);

        // Merging function with its file doesn't change file component count
        uf.merge(file_a, _fn_a);
        assert_eq!(uf.component_count(), 2);

        // But merging files does
        uf.merge(file_a, file_b);
        assert_eq!(uf.component_count(), 1);
    }

    #[test]
    fn get_components_returns_grouped_indices() {
        let mut uf = UnionFind::new();
        let _a = uf.add_node(0, "a.rs", NodeKind::File);
        let _b = uf.add_node(1, "b.rs", NodeKind::File);
        let _c = uf.add_node(2, "c.rs", NodeKind::File);

        uf.merge(_a, _b);

        let mut components = uf.get_components();
        components.sort_by_key(|c| c[0]);

        assert_eq!(components.len(), 2);
        // One group has {0, 1}, the other has {2}
        let group_with_a = components.iter().find(|g| g.contains(&0)).unwrap();
        assert!(group_with_a.contains(&1));
        let group_with_c = components.iter().find(|g| g.contains(&2)).unwrap();
        assert_eq!(group_with_c.len(), 1);
    }

    /// Invariant: parent.len() == rank.len() == nodes.len()
    #[test]
    fn structural_invariant_maintained() {
        let mut uf = UnionFind::new();
        for i in 0..100 {
            uf.add_node(i, &format!("file_{i}"), NodeKind::File);
            assert_eq!(uf.nodes.len(), uf.parent.len());
            assert_eq!(uf.nodes.len(), uf.rank.len());
        }

        // After merges, invariant still holds
        for i in 0..99 {
            uf.merge(i, i + 1);
            assert_eq!(uf.nodes.len(), uf.parent.len());
            assert_eq!(uf.nodes.len(), uf.rank.len());
        }
    }

    /// Invariant: parent[i] < parent.len() for all i
    #[test]
    fn parent_bounds_invariant() {
        let mut uf = UnionFind::new();
        for i in 0..50u16 {
            uf.add_node(i, &format!("f{i}"), NodeKind::File);
        }
        // Random-ish merges
        for i in (0..49).step_by(2) {
            uf.merge(i, i + 1);
        }
        for i in (0..48).step_by(4) {
            uf.merge(i, i + 2);
        }

        for (i, &p) in uf.parent.iter().enumerate() {
            assert!(
                (p as usize) < uf.parent.len(),
                "parent[{i}] = {p} >= len {}",
                uf.parent.len()
            );
        }
    }
}

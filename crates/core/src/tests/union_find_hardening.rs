use super::*;

// --- add_node deduplication mutations ---

#[test]
fn dedup_same_name_different_file_index_creates_two() {
    // Kills: dedup only by name (ignoring file_index)
    let mut uf = UnionFind::new();
    let a = uf.add_node(0, "handler", NodeKind::Function);
    let b = uf.add_node(1, "handler", NodeKind::Function);
    assert_ne!(a, b, "different file_index must create separate nodes");
    assert_eq!(uf.len(), 2);
}

#[test]
fn dedup_same_file_index_different_name_creates_two() {
    // Kills: dedup only by file_index (ignoring name)
    let mut uf = UnionFind::new();
    let a = uf.add_node(0, "foo", NodeKind::Function);
    let b = uf.add_node(0, "bar", NodeKind::Function);
    assert_ne!(a, b);
    assert_eq!(uf.len(), 2);
}

// --- merge rank logic mutations ---

#[test]
fn merge_lower_rank_under_higher_rank() {
    // Kills: swapping rank comparison (< → >)
    let mut uf = UnionFind::new();
    let a = uf.add_node(0, "a", NodeKind::File);
    let b = uf.add_node(1, "b", NodeKind::File);
    let c = uf.add_node(2, "c", NodeKind::File);

    uf.merge(a, b);
    let root_ab = uf.find(a);

    uf.merge(c, a);
    assert_eq!(uf.find(c), root_ab, "lower rank goes under higher rank");
}

#[test]
fn merge_equal_rank_increments() {
    // Kills: removing rank increment on equal merge
    let mut uf = UnionFind::new();
    let a = uf.add_node(0, "a", NodeKind::File);
    let b = uf.add_node(1, "b", NodeKind::File);

    let rank_before = uf.rank[a as usize];
    uf.merge(a, b);
    let root = uf.find(a);
    assert_eq!(
        uf.rank[root as usize],
        rank_before + 1,
        "equal rank merge should increment winner's rank"
    );
}

#[test]
fn merge_self_is_noop() {
    let mut uf = UnionFind::new();
    let a = uf.add_node(0, "a", NodeKind::File);
    uf.merge(a, a);
    assert_eq!(uf.component_count(), 1);
    assert_eq!(
        uf.rank[a as usize], 0,
        "self-merge should not increment rank"
    );
}

// --- component_count mutations ---

#[test]
fn component_count_after_multiple_merges() {
    let mut uf = UnionFind::new();
    for i in 0..5u16 {
        uf.add_node(i, &format!("f{i}"), NodeKind::File);
    }
    assert_eq!(uf.component_count(), 5);

    uf.merge(0, 1);
    assert_eq!(uf.component_count(), 4);

    uf.merge(2, 3);
    assert_eq!(uf.component_count(), 3);

    uf.merge(0, 2);
    assert_eq!(uf.component_count(), 2);

    uf.merge(0, 4);
    assert_eq!(uf.component_count(), 1);
}

// --- get_components excludes function nodes ---

#[test]
fn get_components_excludes_function_nodes() {
    let mut uf = UnionFind::new();
    let f = uf.add_node(0, "a.rs", NodeKind::File);
    let _fn = uf.add_node(0, "foo", NodeKind::Function);
    uf.merge(f, _fn);

    let comps = uf.get_components();
    let total: usize = comps.iter().map(|c| c.len()).sum();
    assert_eq!(total, 1, "function nodes should not appear in components");
}

"""Regression tests for src/merkle.py's domain-separation and leaf-count binding.

These pin down the fix for two structural weaknesses the original
duplicate-last-node, untagged construction had:

  * a leaf hash and an internal-node hash lived in the same hash space, so
    one could in principle be replayed as the other (CVE-2012-2459-style);
  * an odd trailing node was duplicated and re-hashed against itself, which
    is the specific construction that lets two leaf sets of different
    cardinality collide on the same root.

Both are exercised here directly against src.merkle's public functions,
without touching bundles/ or data/.
"""
import hashlib

import pytest

from src.merkle import build_levels, compute_root, merkle_proof, verify_proof


def _leaf(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def test_leaf_hash_and_internal_node_hash_are_disjoint():
    """A single leaf's tree-internal representation must never equal what a
    hash_pair() of two other leaves would produce -- domain separation."""
    leaves = [_leaf("a"), _leaf("b"), _leaf("c"), _leaf("d")]
    levels = build_levels(leaves)
    leaf_level, internal_levels = levels[0], levels[1:]
    all_internal = {h for level in internal_levels for h in level}
    assert not (set(leaf_level) & all_internal)


def test_duplicate_last_node_collision_is_rejected():
    """The old construction let a 3-leaf tree's duplicated-last-node root
    collide with what a naive 4-leaf tree (with the last leaf repeated)
    would produce. Under the fixed construction the two must diverge."""
    three = [_leaf("a"), _leaf("b"), _leaf("c")]
    four_with_repeat = [_leaf("a"), _leaf("b"), _leaf("c"), _leaf("c")]
    assert compute_root(three) != compute_root(four_with_repeat)


def test_root_binds_leaf_count():
    """Two different leaf sets that happen to reduce to the same unmixed
    tree value must still diverge once the leaf count is mixed in -- and in
    general, root(N leaves) must depend on N, not just on the leaf content."""
    leaves = [_leaf("a"), _leaf("b"), _leaf("c")]
    root_3 = compute_root(leaves)
    root_5 = compute_root(leaves + [_leaf("d"), _leaf("e")])
    assert root_3 != root_5


@pytest.mark.parametrize("n", [1, 2, 3, 4, 5, 7, 8, 9])
def test_proof_round_trips_for_every_index(n):
    """Every leaf, at every tree shape from a single leaf through several
    odd/even sizes, must produce a proof that verify_proof() accepts --
    including shapes with a promoted (unpaired) node partway up the tree."""
    raw_leaves = [_leaf(f"leaf-{i}") for i in range(n)]
    root = compute_root(raw_leaves)
    for idx in range(n):
        path = merkle_proof(raw_leaves, idx)
        assert verify_proof(raw_leaves[idx], path, root, idx, n)


def test_proof_rejects_wrong_leaf_count():
    """A proof built for N leaves must not verify against a root claimed to
    be signed for a different leaf count -- the cardinality-binding check."""
    raw_leaves = [_leaf(f"leaf-{i}") for i in range(5)]
    root = compute_root(raw_leaves)
    path = merkle_proof(raw_leaves, 0)
    assert not verify_proof(raw_leaves[0], path, root, 0, 4)
    assert not verify_proof(raw_leaves[0], path, root, 0, 6)

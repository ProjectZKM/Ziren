// Package diagonal carries the KoalaBear Poseidon2 internal-layer diagonal as
// plain residues, free of cgo, so it can be tested without linking the host
// field library.
package diagonal

// Width is the Poseidon2 state width the diagonal is defined for.
const Width = 16

// KoalaBearInternalDiagM1 is the diagonal V of the internal (partial-round)
// linear layer s -> (1 + Diag(V)) s, as KoalaBear residues:
//
//	V = [-2, 1, 2, 1/2, 3, 4, -1/2, -3, -4, 1/2^8, 1/8, 1/2^24, -1/2^8, -1/8, -1/16, -1/2^24]
//
// Source: INTERNAL_DIAG_MONTY_16 in koala-bear/src/poseidon2.rs of p3-koala-bear
// (ProjectZKM/Plonky3, branch zkm/whir-pcs, the revision pinned by Cargo.lock).
// TestKoalaBearInternalDiagonal checks these values against the closed form,
// and the Rust test go_internal_diagonal_matches_the_rust_permutation in
// crates/recursion/core carries the same values and checks them against the
// constant the host permutation uses.
var KoalaBearInternalDiagM1 = [Width]string{
	"2130706431",
	"1",
	"2",
	"1065353217",
	"3",
	"4",
	"1065353216",
	"2130706430",
	"2130706429",
	"2122383361",
	"1864368129",
	"2130706306",
	"8323072",
	"266338304",
	"133169152",
	"127",
}

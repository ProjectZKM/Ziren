// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title zkMIPS Verifier Interface
/// @author ZKM Labs
/// @notice This contract is the interface for the zkMIPS Verifier.
interface IZKMVerifier {
    /// @notice Verifies a proof with given public values and vkey.
    /// @dev It is expected that the first 4 bytes of proofBytes must match the first 4 bytes of
    /// target verifier's VERIFIER_HASH.
    /// @param programVKey The verification key for the MIPS program.
    /// @param publicValues The public values encoded as bytes.
    /// @param proofBytes The proof of the program execution the zkMIPS zkVM encoded as bytes.
    function verifyProof(
        bytes32 programVKey,
        bytes calldata publicValues,
        bytes calldata proofBytes
    ) external view;
}

interface IZKMVerifierWithHash is IZKMVerifier {
    /// @notice Returns the hash of the verifier.
    function VERIFIER_HASH() external pure returns (bytes32);
}

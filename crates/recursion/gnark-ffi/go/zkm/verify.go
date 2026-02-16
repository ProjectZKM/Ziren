package zkm

import (
	"bytes"
	"encoding/hex"
	"os"

	"github.com/ProjectZKM/zkm-recursion-gnark/zkm/koalabear"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
)

func VerifyPlonk(verifyCmdDataDir string, verifyCmdProof string, verifyCmdVkeyHash string, verifyCmdCommittedValuesDigest string) error {
	// Sanity check the required arguments have been provided.
	if verifyCmdDataDir == "" {
		panic("--data is required")
	}

	// Decode the proof.
	proofDecodedBytes, err := hex.DecodeString(verifyCmdProof)
	if err != nil {
		panic(err)
	}
	proof := plonk.NewProof(ecc.BN254)
	if _, err := proof.ReadFrom(bytes.NewReader(proofDecodedBytes)); err != nil {
		panic(err)
	}

	// Read the verifier key.
	vkFile, err := os.Open(verifyCmdDataDir + "/" + plonkVkPath)
	if err != nil {
		panic(err)
	}
	vk := plonk.NewVerifyingKey(ecc.BN254)
	vk.ReadFrom(vkFile)

	// Compute the public witness.
	circuit := Circuit{
		Vars:                  []frontend.Variable{},
		Felts:                 []koalabear.Variable{},
		Exts:                  []koalabear.ExtensionVariable{},
		VkeyHash:              verifyCmdVkeyHash,
		CommittedValuesDigest: verifyCmdCommittedValuesDigest,
	}
	witness, err := frontend.NewWitness(&circuit, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}
	publicWitness, err := witness.Public()
	if err != nil {
		panic(err)
	}

	// Verify proof.
	err = plonk.Verify(proof, vk, publicWitness)
	return err
}

func VerifyGroth16Bn254(verifyCmdDataDir string, verifyCmdProof string, verifyCmdVkeyHash string, verifyCmdCommittedValuesDigest string) error {
	// Sanity check the required arguments have been provided.
	if verifyCmdDataDir == "" {
		panic("--data is required")
	}

	// Decode the proof.
	proofDecodedBytes, err := hex.DecodeString(verifyCmdProof)
	if err != nil {
		panic(err)
	}
	proof := groth16.NewProof(ecc.BN254)
	if _, err := proof.ReadFrom(bytes.NewReader(proofDecodedBytes)); err != nil {
		panic(err)
	}

	// Read the verifier key.
	vkFile, err := os.Open(verifyCmdDataDir + "/" + groth16VkPath)
	if err != nil {
		panic(err)
	}
	vk := groth16.NewVerifyingKey(ecc.BN254)
	vk.ReadFrom(vkFile)

	// Compute the public witness.
	circuit := Circuit{
		Vars:                  []frontend.Variable{},
		Felts:                 []koalabear.Variable{},
		Exts:                  []koalabear.ExtensionVariable{},
		VkeyHash:              verifyCmdVkeyHash,
		CommittedValuesDigest: verifyCmdCommittedValuesDigest,
	}
	witness, err := frontend.NewWitness(&circuit, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}
	publicWitness, err := witness.Public()
	if err != nil {
		panic(err)
	}

	// Verify proof.
	err = groth16.Verify(proof, vk, publicWitness)
	return err
}

func VerifyGroth16(verifyCmdDataDir string, verifyCmdProof string, verifyCmdVkeyHash string, verifyCmdCommittedValuesDigest string) error {
	return VerifyGroth16Bn254(
		verifyCmdDataDir,
		verifyCmdProof,
		verifyCmdVkeyHash,
		verifyCmdCommittedValuesDigest,
	)
}

func VerifyGroth16Bls12381(
	verifyCmdDataDir string,
	verifyCmdProof string,
	verifyCmdVkeyHash string,
	verifyCmdCommittedValuesDigest string,
) error {
	if verifyCmdDataDir == "" {
		panic("--data is required")
	}

	proofDecodedBytes, err := hex.DecodeString(verifyCmdProof)
	if err != nil {
		panic(err)
	}
	proof := groth16.NewProof(ecc.BLS12_381)
	if _, err := proof.ReadFrom(bytes.NewReader(proofDecodedBytes)); err != nil {
		panic(err)
	}

	vkFile, err := os.Open(verifyCmdDataDir + "/" + groth16Bls12381VkPath)
	if err != nil {
		panic(err)
	}
	vk := groth16.NewVerifyingKey(ecc.BLS12_381)
	vk.ReadFrom(vkFile)

	circuit := Circuit{
		Vars:                  []frontend.Variable{},
		Felts:                 []koalabear.Variable{},
		Exts:                  []koalabear.ExtensionVariable{},
		VkeyHash:              verifyCmdVkeyHash,
		CommittedValuesDigest: verifyCmdCommittedValuesDigest,
	}
	witness, err := frontend.NewWitness(&circuit, ecc.BLS12_381.ScalarField())
	if err != nil {
		panic(err)
	}
	publicWitness, err := witness.Public()
	if err != nil {
		panic(err)
	}

	err = groth16.Verify(proof, vk, publicWitness)
	return err
}

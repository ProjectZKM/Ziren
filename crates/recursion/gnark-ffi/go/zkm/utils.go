package zkm

import (
	"bytes"
	"encoding/hex"

	"github.com/ProjectZKM/zkm-recursion-gnark/zkm/koalabear"
	frBls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	groth16 "github.com/consensys/gnark/backend/groth16"
	groth16_bls12381 "github.com/consensys/gnark/backend/groth16/bls12-381"
	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	plonk "github.com/consensys/gnark/backend/plonk"
	plonk_bn254 "github.com/consensys/gnark/backend/plonk/bn254"
	"github.com/consensys/gnark/frontend"
)

func NewZKMPlonkBn254Proof(proof *plonk.Proof, witnessInput WitnessInput) Proof {
	var buf bytes.Buffer
	(*proof).WriteRawTo(&buf)
	proofBytes := buf.Bytes()

	var publicInputs [2]string
	publicInputs[0] = witnessInput.VkeyHash
	publicInputs[1] = witnessInput.CommittedValuesDigest

	// Cast plonk proof into plonk_bn254 proof so we can call MarshalSolidity.
	p := (*proof).(*plonk_bn254.Proof)

	encodedProof := p.MarshalSolidity()

	return Proof{
		PublicInputs: publicInputs,
		EncodedProof: hex.EncodeToString(encodedProof),
		RawProof:     hex.EncodeToString(proofBytes),
	}
}

func NewZKMGroth16Proof(proof *groth16.Proof, witnessInput WitnessInput) Proof {
	var buf bytes.Buffer
	(*proof).WriteRawTo(&buf)
	proofBytes := buf.Bytes()

	var publicInputs [2]string
	publicInputs[0] = witnessInput.VkeyHash
	publicInputs[1] = witnessInput.CommittedValuesDigest

	// Cast groth16 proof into groth16_bn254 proof so we can call MarshalSolidity.
	p := (*proof).(*groth16_bn254.Proof)

	encodedProof := p.MarshalSolidity()

	return Proof{
		PublicInputs: publicInputs,
		EncodedProof: hex.EncodeToString(encodedProof),
		RawProof:     hex.EncodeToString(proofBytes),
	}
}

func NewZKMGroth16Bls12381Proof(proof *groth16.Proof, witnessInput WitnessInput) Proof {
	var buf bytes.Buffer
	(*proof).WriteRawTo(&buf)
	proofBytes := buf.Bytes()

	var publicInputs [2]string
	publicInputs[0] = witnessInput.VkeyHash
	publicInputs[1] = witnessInput.CommittedValuesDigest

	p := (*proof).(*groth16_bls12381.Proof)

	var encodedProof bytes.Buffer
	var encodedProofBytes []byte
	if _, err := p.WriteRawTo(&encodedProof); err != nil {
		panic(err)
	}

	// If there are no commitments, we can return only Ar | Bs | Krs
	if len(p.Commitments) > 0 {
		encodedProofBytes = encodedProof.Bytes()
	} else {
		encodedProofBytes = encodedProof.Bytes()[:8*frBls12381.Bytes]
	}

	return Proof{
		PublicInputs: publicInputs,
		EncodedProof: hex.EncodeToString(encodedProofBytes),
		RawProof:     hex.EncodeToString(proofBytes),
	}
}

func NewCircuit(witnessInput WitnessInput) Circuit {
	vars := make([]frontend.Variable, len(witnessInput.Vars))
	felts := make([]koalabear.Variable, len(witnessInput.Felts))
	exts := make([]koalabear.ExtensionVariable, len(witnessInput.Exts))
	for i := 0; i < len(witnessInput.Vars); i++ {
		vars[i] = frontend.Variable(witnessInput.Vars[i])
	}
	for i := 0; i < len(witnessInput.Felts); i++ {
		felts[i] = koalabear.NewF(witnessInput.Felts[i])
	}
	for i := 0; i < len(witnessInput.Exts); i++ {
		exts[i] = koalabear.NewE(witnessInput.Exts[i])
	}
	return Circuit{
		VkeyHash:              witnessInput.VkeyHash,
		CommittedValuesDigest: witnessInput.CommittedValuesDigest,
		Vars:                  vars,
		Felts:                 felts,
		Exts:                  exts,
	}
}

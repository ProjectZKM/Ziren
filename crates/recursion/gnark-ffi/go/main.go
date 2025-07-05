package main

/*
#include "./koalabear.h"
#include <stdlib.h>

typedef struct {
	char *PublicInputs[2];
	char *EncodedProof;
	char *RawProof;
} C_PlonkBn254Proof;

typedef struct {
	char *PublicInputs[2];
	char *EncodedProof;
	char *RawProof;
} C_Groth16Bn254Proof;
*/
import "C"
import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"unsafe"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test/unsafekzg"
	zkm "github.com/ProjectZKM/zkm-recursion-gnark/zkm"
	"github.com/ProjectZKM/zkm-recursion-gnark/zkm/koalabear"
	"github.com/ProjectZKM/zkm-recursion-gnark/zkm/poseidon2"
)

func main() {}

//export ProvePlonkBn254
func ProvePlonkBn254(dataDir *C.char, witnessPath *C.char) *C.C_PlonkBn254Proof {
	dataDirString := C.GoString(dataDir)
	witnessPathString := C.GoString(witnessPath)

	zkmPlonkBn254Proof := zkm.ProvePlonk(dataDirString, witnessPathString)

	ms := C.malloc(C.sizeof_C_PlonkBn254Proof)
	if ms == nil {
		return nil
	}

	structPtr := (*C.C_PlonkBn254Proof)(ms)
	structPtr.PublicInputs[0] = C.CString(zkmPlonkBn254Proof.PublicInputs[0])
	structPtr.PublicInputs[1] = C.CString(zkmPlonkBn254Proof.PublicInputs[1])
	structPtr.EncodedProof = C.CString(zkmPlonkBn254Proof.EncodedProof)
	structPtr.RawProof = C.CString(zkmPlonkBn254Proof.RawProof)
	return structPtr
}

//export FreePlonkBn254Proof
func FreePlonkBn254Proof(proof *C.C_PlonkBn254Proof) {
	C.free(unsafe.Pointer(proof.EncodedProof))
	C.free(unsafe.Pointer(proof.RawProof))
	C.free(unsafe.Pointer(proof.PublicInputs[0]))
	C.free(unsafe.Pointer(proof.PublicInputs[1]))
	C.free(unsafe.Pointer(proof))
}

//export BuildPlonkBn254
func BuildPlonkBn254(dataDir *C.char) {
	// Sanity check the required arguments have been provided.
	dataDirString := C.GoString(dataDir)

	zkm.BuildPlonk(dataDirString)
}

//export VerifyPlonkBn254
func VerifyPlonkBn254(dataDir *C.char, proof *C.char, vkeyHash *C.char, committedValuesDigest *C.char) *C.char {
	dataDirString := C.GoString(dataDir)
	proofString := C.GoString(proof)
	vkeyHashString := C.GoString(vkeyHash)
	committedValuesDigestString := C.GoString(committedValuesDigest)

	err := zkm.VerifyPlonk(dataDirString, proofString, vkeyHashString, committedValuesDigestString)
	if err != nil {
		return C.CString(err.Error())
	}
	return nil
}

var testMutex = &sync.Mutex{}

//export TestPlonkBn254
func TestPlonkBn254(witnessPath *C.char, constraintsJson *C.char) *C.char {
	// Because of the global env variables used here, we need to lock this function
	testMutex.Lock()
	witnessPathString := C.GoString(witnessPath)
	constraintsJsonString := C.GoString(constraintsJson)
	os.Setenv("WITNESS_JSON", witnessPathString)
	os.Setenv("CONSTRAINTS_JSON", constraintsJsonString)
	err := TestMain()
	testMutex.Unlock()
	if err != nil {
		return C.CString(err.Error())
	}
	return nil
}

//export ProveGroth16Bn254
func ProveGroth16Bn254(dataDir *C.char, witnessPath *C.char) *C.C_Groth16Bn254Proof {
	dataDirString := C.GoString(dataDir)
	witnessPathString := C.GoString(witnessPath)

	zkmGroth16Bn254Proof := zkm.ProveGroth16(dataDirString, witnessPathString)

	ms := C.malloc(C.sizeof_C_Groth16Bn254Proof)
	if ms == nil {
		return nil
	}

	structPtr := (*C.C_Groth16Bn254Proof)(ms)
	structPtr.PublicInputs[0] = C.CString(zkmGroth16Bn254Proof.PublicInputs[0])
	structPtr.PublicInputs[1] = C.CString(zkmGroth16Bn254Proof.PublicInputs[1])
	structPtr.EncodedProof = C.CString(zkmGroth16Bn254Proof.EncodedProof)
	structPtr.RawProof = C.CString(zkmGroth16Bn254Proof.RawProof)
	return structPtr
}

//export FreeGroth16Bn254Proof
func FreeGroth16Bn254Proof(proof *C.C_Groth16Bn254Proof) {
	C.free(unsafe.Pointer(proof.EncodedProof))
	C.free(unsafe.Pointer(proof.RawProof))
	C.free(unsafe.Pointer(proof.PublicInputs[0]))
	C.free(unsafe.Pointer(proof.PublicInputs[1]))
	C.free(unsafe.Pointer(proof))
}

//export BuildGroth16Bn254
func BuildGroth16Bn254(dataDir *C.char) {
	// Sanity check the required arguments have been provided.
	dataDirString := C.GoString(dataDir)

	zkm.BuildGroth16(dataDirString)
}

//export VerifyGroth16Bn254
func VerifyGroth16Bn254(dataDir *C.char, proof *C.char, vkeyHash *C.char, committedValuesDigest *C.char) *C.char {
	dataDirString := C.GoString(dataDir)
	proofString := C.GoString(proof)
	vkeyHashString := C.GoString(vkeyHash)
	committedValuesDigestString := C.GoString(committedValuesDigest)

	err := zkm.VerifyGroth16(dataDirString, proofString, vkeyHashString, committedValuesDigestString)
	if err != nil {
		return C.CString(err.Error())
	}
	return nil
}

//export TestGroth16Bn254
func TestGroth16Bn254(witnessJson *C.char, constraintsJson *C.char) *C.char {
	// Because of the global env variables used here, we need to lock this function
	testMutex.Lock()
	witnessPathString := C.GoString(witnessJson)
	constraintsJsonString := C.GoString(constraintsJson)
	os.Setenv("WITNESS_JSON", witnessPathString)
	os.Setenv("CONSTRAINTS_JSON", constraintsJsonString)
	os.Setenv("GROTH16", "1")
	err := TestMain()
	testMutex.Unlock()
	if err != nil {
		return C.CString(err.Error())
	}
	return nil
}

func TestMain() error {
	// Get the file name from an environment variable.
	fileName := os.Getenv("WITNESS_JSON")
	if fileName == "" {
		fileName = "plonk_witness.json"
	}

	// Read the file.
	data, err := os.ReadFile(fileName)
	if err != nil {
		return err
	}

	// Deserialize the JSON data into a slice of Instruction structs
	var inputs zkm.WitnessInput
	err = json.Unmarshal(data, &inputs)
	if err != nil {
		return err
	}

	// Compile the circuit.
	circuit := zkm.NewCircuit(inputs)
	builder := scs.NewBuilder
	scs, err := frontend.Compile(ecc.BN254.ScalarField(), builder, &circuit)
	if err != nil {
		return err
	}
	fmt.Println("[zkm] gnark verifier constraints:", scs.GetNbConstraints())

	// Run the dummy setup.
	srs, srsLagrange, err := unsafekzg.NewSRS(scs)
	if err != nil {
		return err
	}
	var pk plonk.ProvingKey
	pk, _, err = plonk.Setup(scs, srs, srsLagrange)
	if err != nil {
		return err
	}
	fmt.Println("[zkm] run the dummy setup done")

	// Generate witness.
	assignment := zkm.NewCircuit(inputs)
	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		return err
	}
	fmt.Println("[zkm] generate witness done")

	// Generate the proof.
	_, err = plonk.Prove(scs, pk, witness)
	if err != nil {
		return err
	}
	fmt.Println("[zkm] generate the proof done")

	return nil
}

//export TestPoseidonKoalaBear2
func TestPoseidonKoalaBear2() *C.char {
	input := [poseidon2.KOALABEAR_WIDTH]koalabear.Variable{
		koalabear.NewF("0"),
		koalabear.NewF("0"),
		koalabear.NewF("0"),
		koalabear.NewF("0"),
		koalabear.NewF("0"),
		koalabear.NewF("0"),
		koalabear.NewF("0"),
		koalabear.NewF("0"),
		koalabear.NewF("0"),
		koalabear.NewF("0"),
		koalabear.NewF("0"),
		koalabear.NewF("0"),
		koalabear.NewF("0"),
		koalabear.NewF("0"),
		koalabear.NewF("0"),
		koalabear.NewF("0"),
	}

	expectedOutput := [poseidon2.KOALABEAR_WIDTH]koalabear.Variable{
		koalabear.NewF("1246627235"),
		koalabear.NewF("628715430"),
		koalabear.NewF("728127883"),
		koalabear.NewF("1210800983"),
		koalabear.NewF("1104325841"),
		koalabear.NewF("123548278"),
		koalabear.NewF("109211657"),
		koalabear.NewF("1347389604"),
		koalabear.NewF("350632487"),
		koalabear.NewF("1919729472"),
		koalabear.NewF("1334300527"),
		koalabear.NewF("1417472912"),
		koalabear.NewF("1710206249"),
		koalabear.NewF("1032515169"),
		koalabear.NewF("431466777"),
		koalabear.NewF("1825850772"),
	}

	circuit := zkm.TestPoseidon2KoalaBearCircuit{Input: input, ExpectedOutput: expectedOutput}
	assignment := zkm.TestPoseidon2KoalaBearCircuit{Input: input, ExpectedOutput: expectedOutput}

	builder := r1cs.NewBuilder
	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), builder, &circuit)
	if err != nil {
		return C.CString(err.Error())
	}

	var pk groth16.ProvingKey
	pk, err = groth16.DummySetup(r1cs)
	if err != nil {
		return C.CString(err.Error())
	}

	// Generate witness.
	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		return C.CString(err.Error())
	}

	// Generate the proof.
	_, err = groth16.Prove(r1cs, pk, witness)
	if err != nil {
		return C.CString(err.Error())
	}

	return nil
}

//export FreeString
func FreeString(s *C.char) {
	C.free(unsafe.Pointer(s))
}

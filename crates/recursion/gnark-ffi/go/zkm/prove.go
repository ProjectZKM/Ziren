package zkm

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/constraint"
	bcs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"
)

var globalMutex sync.RWMutex
var globalR1csBn254 constraint.ConstraintSystem = groth16.NewCS(ecc.BN254)
var globalR1csBn254Initialized = false
var globalPkBn254 groth16.ProvingKey = groth16.NewProvingKey(ecc.BN254)
var globalPkBn254Initialized = false
var globalR1csBls12381 constraint.ConstraintSystem = groth16.NewCS(ecc.BLS12_381)
var globalR1csBls12381Initialized = false
var globalPkBls12381 groth16.ProvingKey = groth16.NewProvingKey(ecc.BLS12_381)
var globalPkBls12381Initialized = false

func ProvePlonk(dataDir string, witnessPath string) Proof {
	// Sanity check the required arguments have been provided.
	if dataDir == "" {
		panic("dataDirStr is required")
	}
	os.Setenv("CONSTRAINTS_JSON", dataDir+"/"+constraintsJsonFile)

	// Read the R1CS.
	scsFile, err := os.Open(dataDir + "/" + plonkCircuitPath)
	if err != nil {
		panic(err)
	}
	scs := plonk.NewCS(ecc.BN254)
	scs.ReadFrom(scsFile)
	defer scsFile.Close()

	// Read the proving key.
	pkFile, err := os.Open(dataDir + "/" + plonkPkPath)
	if err != nil {
		panic(err)
	}
	pk := plonk.NewProvingKey(ecc.BN254)
	bufReader := bufio.NewReaderSize(pkFile, 1024*1024)
	pk.UnsafeReadFrom(bufReader)
	defer pkFile.Close()

	// Read the verifier key.
	vkFile, err := os.Open(dataDir + "/" + plonkVkPath)
	if err != nil {
		panic(err)
	}
	vk := plonk.NewVerifyingKey(ecc.BN254)
	vk.ReadFrom(vkFile)
	defer vkFile.Close()

	// Read the file.
	data, err := os.ReadFile(witnessPath)
	if err != nil {
		panic(err)
	}

	// Deserialize the JSON data into a slice of Instruction structs
	var witnessInput WitnessInput
	err = json.Unmarshal(data, &witnessInput)
	if err != nil {
		panic(err)
	}

	// Generate the witness.
	assignment := NewCircuit(witnessInput)
	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}
	publicWitness, err := witness.Public()
	if err != nil {
		panic(err)
	}

	// Generate the proof.
	proof, err := plonk.Prove(scs, pk, witness)
	if err != nil {
		panic(err)
	}

	// Verify proof.
	err = plonk.Verify(proof, vk, publicWitness)
	if err != nil {
		panic(err)
	}

	return NewZKMPlonkBn254Proof(&proof, witnessInput)
}

func ProveGroth16Bn254(dataDir string, witnessPath string) Proof {
	// Sanity check the required arguments have been provided.
	if dataDir == "" {
		panic("dataDirStr is required")
	}

	start := time.Now()
	os.Setenv("CONSTRAINTS_JSON", dataDir+"/"+constraintsJsonFile)
	os.Setenv("GROTH16", "1")
	fmt.Printf("Setting environment variables took %s\n", time.Since(start))

	// Read the R1CS.
	globalMutex.Lock()
	if !globalR1csBn254Initialized {
		start = time.Now()
		r1csFile, err := os.Open(dataDir + "/" + groth16CircuitPath)
		if err != nil {
			panic(err)
		}
		r1csReader := bufio.NewReaderSize(r1csFile, 1024*1024)
		globalR1csBn254.ReadFrom(r1csReader)
		defer r1csFile.Close()
		globalR1csBn254Initialized = true
		fmt.Printf("Reading R1CS took %s\n", time.Since(start))
	}
	globalMutex.Unlock()

	// Read the proving key.
	globalMutex.Lock()
	if !globalPkBn254Initialized {
		start = time.Now()
		pkFile, err := os.Open(dataDir + "/" + groth16PkPath)
		if err != nil {
			panic(err)
		}
		pkReader := bufio.NewReaderSize(pkFile, 1024*1024)
		globalPkBn254.ReadDump(pkReader)
		defer pkFile.Close()
		globalPkBn254Initialized = true
		fmt.Printf("Reading proving key took %s\n", time.Since(start))
	}
	globalMutex.Unlock()

	start = time.Now()
	// Read the file.
	data, err := os.ReadFile(witnessPath)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Reading witness file took %s\n", time.Since(start))

	start = time.Now()
	// Deserialize the JSON data into a slice of Instruction structs
	var witnessInput WitnessInput
	err = json.Unmarshal(data, &witnessInput)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Deserializing JSON data took %s\n", time.Since(start))

	start = time.Now()
	// Generate the witness.
	assignment := NewCircuit(witnessInput)
	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}
	fmt.Printf("Generating witness took %s\n", time.Since(start))

	start = time.Now()
	// Generate the proof.
	proof, err := groth16.Prove(globalR1csBn254, globalPkBn254, witness)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		panic(err)
	}
	fmt.Printf("Generating proof took %s\n", time.Since(start))

	return NewZKMGroth16Bn254Proof(&proof, witnessInput)
}

func ProveGroth16(dataDir string, witnessPath string) Proof {
	return ProveGroth16Bn254(dataDir, witnessPath)
}

func ProveGroth16Bls12381(dataDir string, witnessPath string) Proof {
	if dataDir == "" {
		panic("dataDirStr is required")
	}

	start := time.Now()
	os.Setenv("CONSTRAINTS_JSON", dataDir+"/"+constraintsJsonFile)
	os.Setenv("GROTH16", "1")
	fmt.Printf("Setting environment variables took %s\n", time.Since(start))

	globalMutex.Lock()
	if !globalR1csBls12381Initialized {
		start = time.Now()
		r1csFile, err := os.Open(dataDir + "/" + groth16Bls12381CircuitPath)
		if err != nil {
			panic(err)
		}
		r1csReader := bufio.NewReaderSize(r1csFile, 1024*1024)
		globalR1csBls12381.ReadFrom(r1csReader)
		defer r1csFile.Close()
		globalR1csBls12381Initialized = true
		fmt.Printf("Reading R1CS took %s\n", time.Since(start))
	}
	globalMutex.Unlock()

	globalMutex.Lock()
	if !globalPkBls12381Initialized {
		start = time.Now()
		pkFile, err := os.Open(dataDir + "/" + groth16Bls12381PkPath)
		if err != nil {
			panic(err)
		}
		pkReader := bufio.NewReaderSize(pkFile, 1024*1024)
		globalPkBls12381.ReadDump(pkReader)
		defer pkFile.Close()
		globalPkBls12381Initialized = true
		fmt.Printf("Reading proving key took %s\n", time.Since(start))
	}
	globalMutex.Unlock()

	start = time.Now()
	data, err := os.ReadFile(witnessPath)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Reading witness file took %s\n", time.Since(start))

	start = time.Now()
	var witnessInput WitnessInput
	err = json.Unmarshal(data, &witnessInput)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Deserializing JSON data took %s\n", time.Since(start))

	start = time.Now()
	assignment := NewCircuit(witnessInput)
	witness, err := frontend.NewWitness(&assignment, ecc.BLS12_381.ScalarField())
	if err != nil {
		panic(err)
	}
	fmt.Printf("Generating witness took %s\n", time.Since(start))

	start = time.Now()
	proof, err := groth16.Prove(globalR1csBls12381, globalPkBls12381, witness)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		panic(err)
	}
	fmt.Printf("Generating proof took %s\n", time.Since(start))

	return NewZKMGroth16Bls12381Proof(&proof, witnessInput)
}

func SaveWitnessToFile(witnessPath string, storedDir string) {
	fmt.Printf("witnessPATH: %s\n", witnessPath)
	r1csFilePath := filepath.Join(storedDir, "r1cs_cached")
	file, err := os.Open(r1csFilePath)
	if err != nil {
		log.Fatalf("Failed to open file: %v", err)
	}
	var r1cs bcs.R1CS
	bytesRead, err := r1cs.ReadFrom(file)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Successfully read %d bytes from %s\n", bytesRead, r1csFilePath)

	start := time.Now()
	// Read the file.
	data, err := os.ReadFile(witnessPath)
	if err != nil {
		panic(err)
	}

	start = time.Now()
	// Deserialize the JSON data into a slice of Instruction structs
	var witnessInput WitnessInput
	err = json.Unmarshal(data, &witnessInput)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Deserializing JSON data took %s\n", time.Since(start))

	start = time.Now()
	// Generate the witness.
	assignment := NewCircuit(witnessInput)
	witness, err := frontend.NewWitness(&assignment, fr.Modulus())
	if err != nil {
		panic(err)
	}
	fmt.Printf("Generating witness took %s\n", time.Since(start))

	_solution, err := r1cs.Solve(witness)
	if err != nil {
		panic(err)
	}
	solution := _solution.(*bcs.R1CSSolution)

	witnessFilePath := filepath.Join(storedDir, "witness_to_dvsnark")
	wfile, err := os.Create(witnessFilePath)
	if err != nil {
		log.Fatalf("Failed to create file: %v", err)
	}
	defer wfile.Close()

	bytesWritten, err := solution.W.WriteTo(wfile)
	if err != nil {
		log.Fatalf("Failed to write to file: %v", err)
	}

	fmt.Printf("Successfully wrote %d bytes to %s\n", bytesWritten, witnessFilePath)
}

func ProveDvSnark(dataDir string, witnessPath string, storedDir string) Proof {

	fmt.Println("start SaveWitnessToFile")

	SaveWitnessToFile(witnessPath, storedDir)

	fmt.Println("finished SaveWitnessToFile")

	return Proof{
		PublicInputs: [2]string{"", ""},
		EncodedProof: "",
		RawProof:     "",
	}
}

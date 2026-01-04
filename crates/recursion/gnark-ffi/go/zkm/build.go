package zkm

import (
    "bufio"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"path/filepath"
    "io"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/kzg"
	groth16 "github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test/unsafekzg"
	"github.com/ProjectZKM/zkm-recursion-gnark/zkm/trusted_setup"
	bcs "github.com/consensys/gnark/constraint/bn254"
    fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

func BuildPlonk(dataDir string) {
	// Set the environment variable for the constraints file.
	//
	// TODO: There might be some non-determinism if a single process is running this command
	// multiple times.
	os.Setenv("CONSTRAINTS_JSON", dataDir+"/"+constraintsJsonFile)

	// Read the file.
	witnessInputPath := dataDir + "/" + plonkWitnessPath
	data, err := os.ReadFile(witnessInputPath)
	if err != nil {
		panic(err)
	}

	// Deserialize the JSON data into a slice of Instruction structs
	var witnessInput WitnessInput
	err = json.Unmarshal(data, &witnessInput)
	if err != nil {
		panic(err)
	}

	// Initialize the circuit.
	circuit := NewCircuit(witnessInput)

	// Compile the circuit.
	scs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &circuit)
	if err != nil {
		panic(err)
	}

	// Download the trusted setup.
	var srs kzg.SRS = kzg.NewSRS(ecc.BN254)
	var srsLagrange kzg.SRS = kzg.NewSRS(ecc.BN254)
	srsFileName := dataDir + "/" + srsFile
	srsLagrangeFileName := dataDir + "/" + srsLagrangeFile

	srsLagrangeFile, err := os.Create(srsLagrangeFileName)
	if err != nil {
		log.Fatal("error creating srs file: ", err)
		panic(err)
	}
	defer srsLagrangeFile.Close()

	if !strings.Contains(dataDir, "dev") {
		if _, err := os.Stat(srsFileName); os.IsNotExist(err) {
			fmt.Println("downloading aztec ignition srs")
			trusted_setup.DownloadAndSaveAztecIgnitionSrs(174, srsFileName)

			srsFile, err := os.Open(srsFileName)
			if err != nil {
				panic(err)
			}
			defer srsFile.Close()

			_, err = srs.ReadFrom(srsFile)
			if err != nil {
				panic(err)
			}

			srsLagrange = trusted_setup.ToLagrange(scs, srs)
			_, err = srsLagrange.WriteTo(srsLagrangeFile)
			if err != nil {
				panic(err)
			}
		} else {
			srsFile, err := os.Open(srsFileName)
			if err != nil {
				panic(err)
			}
			defer srsFile.Close()

			_, err = srs.ReadFrom(srsFile)
			if err != nil {
				panic(err)
			}

			_, err = srsLagrange.ReadFrom(srsLagrangeFile)
			if err != nil {
				panic(err)
			}

		}
	} else {
		srs, srsLagrange, err = unsafekzg.NewSRS(scs)
		if err != nil {
			panic(err)
		}

		srsFile, err := os.Create(srsFileName)
		if err != nil {
			panic(err)
		}
		defer srsFile.Close()

		_, err = srs.WriteTo(srsFile)
		if err != nil {
			panic(err)
		}

		_, err = srsLagrange.WriteTo(srsLagrangeFile)
		if err != nil {
			panic(err)
		}
	}

	// Generate the proving and verifying key.
	pk, vk, err := plonk.Setup(scs, srs, srsLagrange)
	if err != nil {
		panic(err)
	}

	// Generate proof.
	assignment := NewCircuit(witnessInput)
	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}
	proof, err := plonk.Prove(scs, pk, witness)
	if err != nil {
		panic(err)
	}

	// Verify proof.
	publicWitness, err := witness.Public()
	if err != nil {
		panic(err)
	}
	err = plonk.Verify(proof, vk, publicWitness)
	if err != nil {
		panic(err)
	}

	// Create the build directory.
	os.MkdirAll(dataDir, 0755)

	// Write the solidity verifier.
	solidityVerifierFile, err := os.Create(dataDir + "/" + plonkVerifierContractPath)
	if err != nil {
		panic(err)
	}
	vk.ExportSolidity(solidityVerifierFile)
	defer solidityVerifierFile.Close()

	// Write the R1CS.
	scsFile, err := os.Create(dataDir + "/" + plonkCircuitPath)
	if err != nil {
		panic(err)
	}
	defer scsFile.Close()
	_, err = scs.WriteTo(scsFile)
	if err != nil {
		panic(err)
	}

	// Write the verifier key.
	vkFile, err := os.Create(dataDir + "/" + plonkVkPath)
	if err != nil {
		panic(err)
	}
	defer vkFile.Close()
	_, err = vk.WriteTo(vkFile)
	if err != nil {
		panic(err)
	}

	// Write the proving key.
	pkFile, err := os.Create(dataDir + "/" + plonkPkPath)
	if err != nil {
		panic(err)
	}
	defer pkFile.Close()
	_, err = pk.WriteTo(pkFile)
	if err != nil {
		panic(err)
	}
}

func BuildGroth16(dataDir string) {
	// Set the environment variable for the constraints file.
	//
	// TODO: There might be some non-determinism if a single process is running this command
	// multiple times.
	os.Setenv("CONSTRAINTS_JSON", dataDir+"/"+constraintsJsonFile)
	os.Setenv("GROTH16", "1")

	// Read the file.
	witnessInputPath := dataDir + "/" + groth16WitnessPath
	data, err := os.ReadFile(witnessInputPath)
	if err != nil {
		panic(err)
	}

	// Deserialize the JSON data into a slice of Instruction structs
	var witnessInput WitnessInput
	err = json.Unmarshal(data, &witnessInput)
	if err != nil {
		panic(err)
	}

	// Initialize the circuit.
	circuit := NewCircuit(witnessInput)

	// Compile the circuit.
	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		panic(err)
	}

	// Generate the proving and verifying key.
	pk, vk, err := groth16.Setup(r1cs)
	if err != nil {
		panic(err)
	}

	// Generate proof.
	assignment := NewCircuit(witnessInput)
	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}
	proof, err := groth16.Prove(r1cs, pk, witness)
	if err != nil {
		panic(err)
	}

	// Verify proof.
	publicWitness, err := witness.Public()
	if err != nil {
		panic(err)
	}
	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		panic(err)
	}

	// Create the build directory.
	os.MkdirAll(dataDir, 0755)

	// Write the solidity verifier.
	solidityVerifierFile, err := os.Create(dataDir + "/" + groth16VerifierContractPath)
	if err != nil {
		panic(err)
	}
	vk.ExportSolidity(solidityVerifierFile)
	defer solidityVerifierFile.Close()

	// Write the R1CS.
	r1csFile, err := os.Create(dataDir + "/" + groth16CircuitPath)
	if err != nil {
		panic(err)
	}
	defer r1csFile.Close()
	_, err = r1cs.WriteTo(r1csFile)
	if err != nil {
		panic(err)
	}

	// Write the verifier key.
	vkFile, err := os.Create(dataDir + "/" + groth16VkPath)
	if err != nil {
		panic(err)
	}
	defer vkFile.Close()
	_, err = vk.WriteTo(vkFile)
	if err != nil {
		panic(err)
	}

	// Write the proving key.
	pkFile, err := os.Create(dataDir + "/" + groth16PkPath)
	if err != nil {
		panic(err)
	}
	defer pkFile.Close()
	err = pk.WriteDump(pkFile)
	if err != nil {
		panic(err)
	}
}


// Dump writes the coefficient table and the fully‑expanded R1Cs rows into w.
// Caller decides where w points to (file, buffer, network, …).
// Dump writes the coefficient table and the fully-expanded R1Cs rows into w.
// It is functionally identical to the original version but batches I/O
// through an internal bufio.Writer and uses raw little-endian encodes for
// scalars to avoid reflection overhead in binary.Write.
func Dump(r1cs *bcs.R1CS, w io.Writer) error {
// Wrap the destination with a large buffered writer (1 MiB; tune as needed).
	bw := bufio.NewWriterSize(w, 1<<20)
	defer bw.Flush() // ensure everything is pushed downstream

	coeffs := r1cs.Coefficients
	rows := r1cs.GetR1Cs()

	// A 4-byte scratch reused for every uint32 we encode.
	var scratch [4]byte

	putU32 := func(v uint32) error {
		binary.LittleEndian.PutUint32(scratch[:], v)
		_, err := bw.Write(scratch[:])
		return err
	}

	// 1. Coefficient table ---------------------------------------------------
	if err := putU32(uint32(len(coeffs))); err != nil {
		return err
	}
	for _, c := range coeffs {
		if _, err := bw.Write(c.Marshal()); err != nil { // 32 bytes each
			return err
		}
	}

	// 2. Full R1CS rows ------------------------------------------------------
	if err := putU32(uint32(len(rows))); err != nil {
		return err
	}

	dumpLE := func(expr constraint.LinearExpression) error {
		for _, t := range expr {
			if err := putU32(uint32(t.WireID())); err != nil {
				return err
			}
			if err := putU32(uint32(t.CoeffID())); err != nil {
				return err
			}
		}
		return nil
	}

	for _, r := range rows {
		if err := putU32(uint32(len(r.L))); err != nil {
			return err
		}
		if err := putU32(uint32(len(r.R))); err != nil {
			return err
		}
		if err := putU32(uint32(len(r.O))); err != nil {
			return err
		}

		if err := dumpLE(r.L); err != nil {
			return err
		}
		if err := dumpLE(r.R); err != nil {
			return err
		}
		if err := dumpLE(r.O); err != nil {
			return err
		}
	}

	return bw.Flush() // explicit flush + propagate any error
}

func DumpR1CSIfItExists(storeDir string) bool {
    // Check input exists
    cacheFilePath := filepath.Join(storeDir, "r1cs_cached")
	if stat, err := os.Stat(cacheFilePath); err != nil {
		// doesn't exist or not accessible
		return false
	} else if stat.Size() < 1024 {
		return false
	}

	// Open input
	file, err := os.Open(cacheFilePath)
	if err != nil {
		log.Fatalf("Failed to open file: %v", err)
	}
	var r1cs bcs.R1CS
	bytesRead, err := r1cs.ReadFrom(file)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Successfully read %d bytes from %s\n", bytesRead, cacheFilePath)

	// Create output
	new_r1cs_fn := filepath.Join(storeDir, "r1cs_to_dvsnark")
	new_file, err := os.Create(new_r1cs_fn)
	if err != nil {
		log.Fatalf("Failed to create file: %v", err)
	}
	defer new_file.Close()

	log.Printf("DumpR1CSIfItExists; Dump to file %s", new_r1cs_fn)
	err = Dump(&r1cs, new_file)
	if err != nil {
		log.Fatalf("Failed to dump to file: %v", err)
	}

	return true
}

func BuildDvSnark(dataDir string, storeDir string) {
    r1cs_dumped := DumpR1CSIfItExists(storeDir)
	if r1cs_dumped {
		fmt.Println("r1cs_cache already exists, converted to format r1cs_to_dvsnark")
		return
	}

	// Set the environment variable for the constraints file.
	//
	// TODO: There might be some non-determinism if a single process is running this command
	// multiple times.
	os.Setenv("CONSTRAINTS_JSON", dataDir+"/"+constraintsJsonFile)
	os.Setenv("GROTH16", "1")

	// Read the file.
	witnessInputPath := dataDir + "/" + dvsnarkWitnessPath
	data, err := os.ReadFile(witnessInputPath)
	if err != nil {
		panic(err)
	}

	// Deserialize the JSON data into a slice of Instruction structs
	var witnessInput WitnessInput
	err = json.Unmarshal(data, &witnessInput)
	if err != nil {
		panic(err)
	}

	// Initialize the circuit.
	circuit := NewCircuit(witnessInput)

	// Compile the circuit.
	r1cs, err := frontend.Compile(fr.Modulus(), r1cs.NewBuilder, &circuit)
    if err != nil {
		panic(err)
	}

	{
        // benchmark
        nbCoeff := r1cs.GetNbCoefficients()
        bytesCoeffTable := nbCoeff * 32
        fmt.Printf("Coeff-table: %d elements  ≈  %d bytes\n",
            nbCoeff, bytesCoeffTable)

        var nTerms int

	    r1cs_contr := r1cs.(*bcs.R1CS)
        for _, r := range r1cs_contr.GetR1Cs() { // materialises each row once
            nTerms += len(r.L) + len(r.R) + len(r.O) // three linear-expressions
        }
        fmt.Printf("Total terms in matrix: %d  (≈ %d bytes)\n",
        			nTerms, nTerms*8) // a Term is 2×uint32 = 8 B

	    num_vars := (r1cs.GetNbSecretVariables() + r1cs.GetNbPublicVariables() + r1cs.GetNbInternalVariables())
        naive := 3 * r1cs.GetNbConstraints() * num_vars * 32

        fmt.Printf("Naive cost num_vars=(%d) num_constraints=(%d)  (≈ %d bytes)\n", num_vars, r1cs.GetNbConstraints(), naive) // a Term is 2×uint32 = 8 B
    }

	{
        r1cs_fn := filepath.Join(storeDir, "r1cs_cached")
        file, err := os.Create(r1cs_fn)
        if err != nil {
            log.Fatalf("Failed to create file: %v", err)
        }
        defer file.Close()
        bytesWritten, err := r1cs.WriteTo(file)
        if err != nil {
            panic("err is not nil for solve")
        }
        fmt.Printf("Successfully wrote %d bytes to %s\n", bytesWritten, r1cs_fn)
    }

    {
        r1cs_fn := filepath.Join(storeDir, "r1cs_to_dvsnark")
        file, err := os.Create(r1cs_fn)
        if err != nil {
            log.Fatalf("Failed to create file: %v", err)
        }
        defer file.Close()
        r1cs_contr := r1cs.(*bcs.R1CS)
        Dump(r1cs_contr, file)
    }
}
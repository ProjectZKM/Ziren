# Proof Composition

Ziren enables developers to implement recursive proof verification through its innovative proof composition system, allowing cryptographic proofs to be nested within zkVM programs. This architecture supports aggregation of multiple proofs while maintaining compatibility with Ziren's verification framework.

## Key Use Cases

Proof composition enables developers to verify existing proofs within new ones.Typical use cases include:

- Privacy-Preserving Computation

  - Confidential Data Processing
    
    Execute distributed computations on private data pieces while generating unified proofs.

  - ​Cryptographic Proofs
  
    Verify encrypted values without decryption (e.g., zero-knowledge encryption proofs, digital signatures, homomorphic encryption).
  

- Proof Aggregation 

  - Cross-chain Verification

    Combine proofs from multiple chains into one (e.g., Ethereum).

  - ​Rollup Optimization
  
    Compress numerous transaction proofs into a single batch proof.
  
- Modular Program Architecture
  - Maintainability

    Update modules without recomputing entire workflow. 

  - Pipeline Proof/Verification

    Split computational tasks into independent sub-proofs and execute them concurrently to optimize proving efficiency.

## Core Components

Ziren's proofs are packaged into an object called a receipt. Composition allows users to verify a receipt inside a zkVM program. The result is a proof that a given receipt was verified. Key components include:

- Assumption
  
  Describes an assertion requiring proof verification.

- Receipt Claim 
  
  Receipt statement, used to identify the receipt, containing program image ID and public inputs/outputs (SHA-256 commitment).

- Inner Receipt 
  
  Base proof container, including STARK proof, public values and receipt claim.


- Assumption Receipt
  
  Conditional proof with pending dependencies on other claims.  

- Composite Receipt	

  Recursively verified proof bundle containing multiple verification layers.

- Final Recipt

  Final verification artifact with all assumptions resolved. 
  

## Implementation Workflow

### Proof Generation Process

- Base Proof Generation
  
  Generates STARK proof for nested guest program, derives initial inner receipt.

- Recursive Composition

  Recursive STARK aggregation of the main program, using inner/composite receipts as inputs.

- Final Receipt
  
  Combine all inner receipts and composite receipts.


### Verification Process

- Validate main proof's STARK constraints (composite receipt verification).
- Recursively verify all assumption proofs (inner receipt validation).
- Check SHA-256 commitment consistency across all receipt claims.


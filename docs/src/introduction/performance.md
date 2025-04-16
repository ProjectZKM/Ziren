# Performance

## Metrics
To evaluate a zkVM’s performance, two primary metrics are considered: `Efficiency` and `Cost`.

**Efficiency** 

The `Efficiency`, or cycles per instruction, means how many cycles the zkVM can prove in one second. One cycle is usually mapped to `one` MIPS instruction in zkVM. 

For each MIPS instruction in a shard, it goes through two main phases, execution phase and proving phase, to generate the proof. 

In the execution phase, the MIPS VM (Emulator) reads the instruction at PC from the program image and executes instruction to generate the execution traces (events). The execution traces will be converted to a matrix for later proving phase. This means the number of the traces is related to the instruction sequences of the program, and the shorter the sequences is, more efficient we can achieve to execute and prove.  

In the proving phase, we employ the PCS (FRI in zkMIPS prover) to commit the execution traces, the proving complexity is determined by the matrix size of the trace table.

Therefore the instruction sequence size and prover's efficiency do matter in terms of the total proving performance. 

**Cost**

The proving cost is more comprehensive metrics, which means how much money we spend to prove a specific program. it simply equals to the `Efficiency * Unit`, where Unit is the price of the server shipping the prover in a second. 
 

For example, the [ethproofs.org](https://ethproofs.org/) provides a platform for all zkVMs to submit their Ethereum mainnet block proofs, which includes the proof size, proving time and proving cost per Mgas (`Efficiency * Unit / GasUsed`, where the GasUsed is of unit Mgas).


## zkVM benchmarks

To facilitate a fairer comparison among different zkVMs, we provide the [zkvm-benchmarks](https://github.com/zkMIPS/zkvm-benchmarks)  suite, enabling anyone to reproduce the performance data.


## Performance of zkMIPS

The performance of zkMIPS on an AWS [r6a.8xlarge](https://instances.vantage.sh/aws/ec2/r6a.8xlarge) instance, a CPU-based server, is presented below

Note that all the time is of unit millisecond. Define `Rate = 100*(SP1 - zkMIPS)/zkMIPS`. 


**Fibonacci**

| n      | RISC0 2.0.1 | zkMIPS 0.3 | zkMIPS 1.0 | SP1 4.1.1 | Rate  |
|--------|-------------|--------|--------|-----------|--------|
| 100    | 1691        | 6478   | 1947   | 5828      | 199.33 |
| 1000   | 3291        | 8037   | 1933   | 5728      | 196.32 |
| 10000  | 12881       | 44239  | 2972   | 7932      | 166.89 |
| 58218  | 64648       | 223534 | 14985  | 31063     | 107.29 |

**sha2**

| Byte Length | RISC0 2.0.1 | zkMIPS 0.3 | zkMIPS 1.0 | SP1 4.1.1 | Rate  |
|-------------|-------------|--------|--------|-----------|--------|
| 32          | 3307        | 7866   | 1927   | 5931      | 207.78 |
| 256         | 6540        | 8318   | 1913   | 5872      | 206.95 |
| 512         | 6504        | 11530  | 1970   | 5970      | 203.04 |
| 1024        | 12972       | 13434  | 2192   | 6489      | 196.03 |
| 2048        | 25898       | 22774  | 2975   | 7686      | 158.35 |

**sha3**

| Byte Length | RISC0 2.0.1 | zkMIPS 0.3 | zkMIPS 1.0 | SP1 4.1.1 | Rate  |
|-------------|-------------|--------|--------|-----------|--------|
| 32          | 3303        | 7891   | 1972   | 5942      | 201.31 |
| 256         | 6487        | 10636  | 2267   | 5909      | 160.65 |
| 512         | 12965       | 13015  | 2225   | 6580      | 195.73 |
| 1024        | 13002       | 21044  | 3283   | 7612      | 131.86 |
| 2048        | 26014       | 43249  | 4923   | 10087     | 104.89 |

Proving with precompile:

| Byte Length | zkMIPS 1.0 | SP1 4.1.1 | Rate  |
|-------------|--------|-----------|-------|
| 32          | 646    | 980       | 51.70 |
| 256         | 634    | 990       | 56.15 |
| 512         | 731    | 993       | 35.84 |
| 1024        | 755    | 1034      | 36.95 |
| 2048        | 976    | 1257      | 28.79 |

**big-memory**

| Value | RISC0 2.0.1 | zkMIPS 0.3 | zkMIPS 1.0 | SP1 4.1.1 | Rate  |
|-------|-------------|---------|--------|-----------|-------|
| 5     | 78486       | 199344  | 21218  | 36927     | 74.03 |

**sha2-chain**

| Iterations | RISC0 2.0.1 | zkMIPS 0.3 | zkMIPS 1.0 | SP1 4.1.1 | Rate  |
|------------|-------------|---------|--------|-----------|-------|
| 230        | 53979       | 141451  | 8756   | 15850     | 81.01 |
| 460        | 104584      | 321358  | 17789  | 31799     | 78.75 |

**sha3-chain**

| Iterations | RISC0 2.0.1 | zkMIPS 0.3 | zkMIPS 1.0 | SP1 4.1.1 | Rate  |
|------------|-------------|----------|--------|-----------|-------|
| 230        | 208734      | 718678   | 36205  | 39987     | 10.44 |
| 460        | 417773      | 1358248  | 68488  | 68790     | 0.44  |

Proving with precompile:

| Iterations | zkMIPS 1.0 | SP1 4.1.1 | Rate  |
|------------|----------|-----------|-------|
| 230        | 3491     | 4277      | 22.51 |
| 460        | 6471     | 7924      | 22.45 |

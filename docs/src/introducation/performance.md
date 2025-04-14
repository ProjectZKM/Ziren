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

To achieve a more fair comparison among the different zkVMs, we provides a [zkvm-benchmarks](https://github.com/zkMIPS/zkvm-benchmarks) to allow that anyone can reproduce the performance data. 


## Performance of zkMIPS

On a AWS [r6a.8xlarge](https://instances.vantage.sh/aws/ec2/r6a.8xlarge), which is a CPU server, zkMIPS's performance is shown as below. 


Note that all the time is of unit millisecond. Define `Rate = 100*(SP1 - zkMIPS)/zkMIPS`.


**Fibonacci**

| n      | RISC0  | ZKM    | zkMIPS   | SP1     | Rate |
|--------|--------|--------|--------|---------|-------------------|
| 100    | 3004   | 6478   | 1947   | 5828    | 199.3323061       |
| 1000   | 5854   | 8037   | 1933   | 5728    | 196.3269529       |
| 10000  | 23648  | 44239  | 2972   | 7932    | 166.8909825       |
| 58218  | 59905  | 223534 | 14985  | 31063   | 107.2939606       |

**sha2**

| Byte Length | RISC0  | ZKM    | zkMIPS   | SP1   | Rate |
|-------------|--------|--------|--------|-------|-------------------|
| 32          | 5982   | 7866   | 1927   | 5931  | 207.7841204       |
| 256         | 5939   | 8318   | 1913   | 5872  | 206.9524307       |
| 512         | 11791  | 11530  | 1970   | 5970  | 203.0456853       |
| 1024        | 11941  | 13434  | 2192   | 6489  | 196.0310219       |
| 2048        | 23772  | 22774  | 2975   | 7686  | 158.3529412       |

**sha3**

| Byte Length | RISC0  | ZKM    | zkMIPS   | SP1   | Rate |
|-------------|--------|--------|--------|-------|-----------------------|
| 32          | 5934   | 7891   | 1972   | 5942  | 201.3184584           |
| 256         | 11663  | 10636  | 2267   | 5909  | 160.6528452           |
| 512         | 11776  | 13015  | 2225   | 6580  | 195.7303371           |
| 1024        | 23481  | 21044  | 3283   | 7612  | 131.8611027           |
| 2048        | 47278  | 43249  | 4923   | 10087 | 104.895389            |


**big-memory**

| Value | RISC0   | ZKM     | zkMIPS   | SP1    | Rate |
|-------|---------|---------|--------|--------|-----------------------|
| 5     | 191125  | 199344  | 21218  | 36927  | 74.03619568           |

**sha2-chain**

| Iterations | RISC0  | ZKM     | zkMIPS   | SP1    | Rate |
|------------|--------|---------|--------|--------|-----------------------|
| 230        | 95827  | 141451  | 8756   | 15850  | 81.01873001           |
| 460        | 155192 | 321358  | 17789  | 31799  | 78.75653494           |

**sha3-chain**

| Iterations | RISC0   | ZKM      | zkMIPS   | SP1    | Rate |
|------------|---------|----------|--------|--------|-----------------------|
| 230        | 287944  | 718678   | 36205  | 39987  | 10.44607098           |
| 460        | 574644  | 1358248  | 68488  | 68790  | 0.4409531597          |

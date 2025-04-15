# Performance

## Metrics
To evaluate a zkVM’s performance, two primary metrics are considered: `Efficiency` and `Cost`.

**Efficiency** 

The `Efficiency`, or cycles per instruction, means how many cycles the zkVM can prove in one second. One cycle is usually mapped to `one` MIPS instruction in the zkVM. 

For each MIPS instruction in a shard, it goes through two main phases: the execution phase and the proving phase (to generate the proof). 

In the execution phase, the MIPS VM (Emulator) reads the instruction at the program counter (PC) from the program image and executes it to generate execution traces (events). These traces are converted into a matrix for the proving phase. The number of traces depends on the program's instruction sequence - the shorter the sequence, the more efficient the execution and proving. 

In the proving phase, the zkMIPS prover uses a Polynomial Commitment Scheme (PCS) — specifically FRI — to commit the execution traces. The proving complexity is determined by the matrix size of the trace table.

Therefore, the instruction sequence size and prover efficiency directly impact overall proving performance. 

**Cost**

Proving cost is a more comprehensive metric that measures the total expense of proving a specific program. It can be approximated as: `Prover Efficiency * Unit`, Where Prover Efficiency reflects execution performance, and Unit Price refers to the cost per second of the server running the prover. 

For example, [ethproofs.org](https://ethproofs.org/) provides a platform for all zkVMs to submit their Ethereum mainnet block proofs, which includes the proof size, proving time and proving cost per Mgas (`Efficiency * Unit / GasUsed`, where the GasUsed is of unit Mgas).


## zkVM benchmarks

To facilitate a the fairest possible comparison among different zkVMs, we provide the [zkvm-benchmarks](https://github.com/zkMIPS/zkvm-benchmarks)  suite, enabling anyone to reproduce the performance data.


## Performance of zkMIPS

The performance of zkMIPS on an AWS [r6a.8xlarge](https://instances.vantage.sh/aws/ec2/r6a.8xlarge) instance, a CPU-based server, is presented below:

Note that all the time is of unit millisecond. Define `Rate = 100*(SP1 - zkMIPS)/zkMIPS`.


**Fibonacci**

| n          | R0VM       | zkMIPS 0.3 | zkMIPS 1.0 | SP1         | Rate       |
|------------|------------|------------|------------|-------------|------------|
| 100        | 3004       | 6478       | 1947       | 5828        | 199.33     |
| 1000       | 5854       | 8037       | 1933       | 5728        | 196.32     |
| 10000      | 23648      | 44239      | 2972       | 7932        | 166.89     |
| 58218      | 59905      | 223534     | 14985      | 31063       | 107.29     |

**sha2**

| Byte Length     | R0VM       | zkMIPS 0.3 | zkMIPS 1.0 | SP1       | Rate       |
|-----------------|------------|------------|------------|-----------|------------|
| 32              | 5982       | 7866       | 1927       | 5931      | 207.78     |
| 256             | 5939       | 8318       | 1913       | 5872      | 206.95     |
| 512             | 11791      | 11530      | 1970       | 5970      | 203.04     |
| 1024            | 11941      | 13434      | 2192       | 6489      | 196.03     |
| 2048            | 23772      | 22774      | 2975       | 7686      | 158.35     |

**sha3**

| Byte Length | R0VM       | zkMIPS 0.3 | zkMIPS 1.0 | SP1       | Rate       |
|-------------|------------|------------|------------|-----------|------------|
| 32          | 5934       | 7891       | 1972       | 5942      | 201.31     |
| 256         | 11663      | 10636      | 2267       | 5909      | 160.65     |
| 512         | 11776      | 13015      | 2225       | 6580      | 195.73     |
| 1024        | 23481      | 21044      | 3283       | 7612      | 131.86     |
| 2048        | 47278      | 43249      | 4923       | 10087     | 104.89     |

Proving with precompile:

| Byte Length | zkMIPS 1.0 | SP1       | Rate      |
|-------------|------------|-----------|-----------|
| 32          | 646        | 980       | 51.70     |
| 256         | 634        | 990       | 56.15     |
| 512         | 731        | 993       | 35.84     |
| 1024        | 755        | 1034      | 36.95     |
| 2048        | 976        | 1257      | 28.79     |

**big-memory**

| Value     | R0VM        | zkMIPS 0.3 | zkMIPS 1.0 | SP1        | Rate      |
|-----------|-------------|------------|------------|------------|-----------|
| 5         | 191125      | 199344     | 21218      | 36927      | 74.03     |

**sha2-chain**

| Iterations | R0VM       | zkMIPS 0.3 | zkMIPS 1.0 | SP1        | Rate      |
|------------|------------|------------|------------|------------|-----------|
| 230        | 95827      | 141451     | 8756       | 15850      | 81.01     |
| 460        | 155192     | 321358     | 17789      | 31799      | 78.75     |

**sha3-chain**

| Iterations | R0VM        | zkMIPS 0.3 | zkMIPS 1.0 | SP1        | Rate      |
|------------|-------------|------------|------------|------------|-----------|
| 230        | 287944      | 718678     | 36205      | 39987      | 10.44     |
| 460        | 574644      | 1358248    | 68488      | 68790      | 0.44      |

Proving with precompile:

| Iterations | zkMIPS 1.0 | SP1        | Rate      |
|------------|------------|------------|-----------|
| 230        | 3491       | 4277       | 22.51     |
| 460        | 6471       | 7924       | 22.45     |

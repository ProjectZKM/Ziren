# MIPS ISA

MIPS instructions are categorized into ​core instructions and ​syscalls. 

​Core instructions includes all fundamental operations for program execution:
- ​Arithmetic/Logic: ADD, SUB, AND, OR, XOR
- Data Movement: LW (load from memory), SW (store to memory), MOVZ (conditional move)
- ​Control Flow: BEQ (branch if equal), JAL (jump and link), J (unconditional jump)
- Bit Manipulation: CLZ (count leading zeros) and SLL (logical shift left)
- System Interface: SYSCALL (invoke system services)

​Syscalls are predefined system-level operations for external interactions:
- ​I/O Operations: WRITE (output data), SYSHINTREAD (read input)
- ​Program Control: HALT (terminate program), SYSVERIFY (verify precompiled code)
- Special Modes: ENTER_UNCONSTRAINED (enable unconstrained execution)

ZKM2's virtual machine fully complies with ​MIPS-I ISA (32-bit) and supports:

- ​72 core instructions covering arithmetic, memory, control flow, and privileged operations
- ​7 syscalls for system-level interactions

This implementation provides ​Turing-complete execution for programs compiled from C/C++, Go, Rust, and other high-level languages.

## Supported core instructions
| instruction | Op [31:26] | rs [25:21]  | rt [20:16]  | rd [15:11]  | shamt [10:6] | func [5:0]  | function                                                     |
| ----------- | ---------- | ----------- | ----------- | ----------- | ------------ | ----------- | ------------------------------------------------------------ |
| ADD         | 000000     | rs          | rt          | rd          | 00000        | 100000      | rd = rs+rt                                                   |
| ADDI        | 001000     | rs          | rt          | imm         | imm          | imm         | rt = rs + sext(imm)                                          |
| ADDIU       | 001001     | rs          | rt          | imm         | imm          | imm         | rt = rs + sext(imm)                                          |
| ADDU        | 000000     | rs          | rt          | rd          | 00000        | 100001      | rd = rs+rt                                                   |
| AND         | 000000     | rs          | rt          | rd          | 00000        | 100100      | rd = rs&rt                                                   |
| ANDI        | 001100     | rs          | rt          | imm         | imm          | imm         | rt = rs & zext(imm)                                          |
| BEQ         | 000100     | rs          | rt          | offset      | offset       | offset      | PC = PC + sext(offset << 2)， if rs == rt                    |
| BGEZ        | 000001     | rs          | 00001       | offset      | offset       | offset      | PC = PC + sext(offset << 2)， if rs >= 0                     |
| BGTZ        | 000111     | rs          | 00000       | offset      | offset       | offset      | PC = PC + sext(offset << 2)， if rs > 0                      |
| BLEZ        | 000110     | rs          | 00000       | offset      | offset       | offset      | PC = PC + sext(offset << 2)， if rs <= 0                     |
| BLTZ        | 000001     | rs          | 00000       | offset      | offset       | offset      | PC = PC + sext(offset << 2)， if rs < 0                      |
| BNE         | 000101     | rs          | rt          | offset      | offset       | offset      | PC = PC + sext(offset << 2)， if rs != rt                    |
| CLO         | 011100     | rs          | rt          | rd          | 00000        | 100001      | rd = count_leading_ones(rs)                                  |
| CLZ         | 011100     | rs          | rt          | rd          | 00000        | 100000      | rd = count_leading_zeros(rs)                                 |
| DIV         | 000000     | rs          | rt          | 00000       | 00000        | 011010      | (hi, lo) = rs / rt                                           |
| DIVU        | 000000     | rs          | rt          | 00000       | 00000        | 011011      | (hi, lo) = rs / rt                                           |
| J           | 000010     | instr_index | instr_index | instr_index | instr_index  | instr_index | PC = PC[GPRLEN-1..28] \|\| instr_index \|\| 0 0              |
| JAL         | 000011     | instr_index | instr_index | instr_index | instr_index  | instr_index | r31 = PC +8, PC = PC[GPRLEN-1..28] \|\| instr_index \|\| 0 0 |
| JALR        | 000000     | rs          | 00000       | rd          | hint         | 001001      | rd = PC +8, PC = rs                                          |
| JR          | 000000     | rs          | 00000       | 00000       | hint         | 001000      | pc = rs                                                      |
| LB          | 100000     | base        | rt          | offset      | offset       | offset      | rt = sext(mem_byte(base + offset))                           |
| LBU         | 100100     | base        | rt          | offset      | offset       | offset      | rt = zext(mem_byte(base + offset))                           |
| LH          | 100001     | base        | rt          | offset      | offset       | offset      | rt = sext(mem_halfword(base + offset))                       |
| LHU         | 100101     | base        | rt          | offset      | offset       | offset      | rt = zext(mem_halfword(base + offset))                       |
| LL          | 110000     | base        | rt          | offset      | offset       | offset      | rt = mem_word(base + offset)                                 |
| LUI         | 001111     | 00000       | rt          | imm         | imm          | imm         | rt = imm << 16                                               |
| LW          | 100011     | base        | rt          | offset      | offset       | offset      | rt = mem_word(base + offset)                                 |
| LWL         | 100010     | base        | rt          | offset      | offset       | offset      | rt = rt merge mem(base+offset)                               |
| LWR         | 100110     | base        | rt          | offset      | offset       | offset      | rt = rt merge mem(base+offset)                               |
| MFHI        | 000000     | 00000       | 00000       | rd          | 00000        | 010000      | rd = hi                                                      |
| MFLO        | 000000     | 00000       | 00000       | rd          | 00000        | 010010      | rd = lo                                                      |
| MOVN        | 000000     | rs          | rt          | rd          | 00000        | 001011      | rd = rs, if rt != 0                                          |
| MOVZ        | 000000     | rs          | rt          | rd          | 00000        | 001010      | rd = rs, if rt == 0                                          |
| MTHI        | 000000     | rs          | 00000       | 00000       | 00000        | 010001      | hi = rs                                                      |
| MTLO        | 000000     | rs          | 00000       | 00000       | 00000        | 010011      | lo = rs                                                      |
| MUL         | 011100     | rs          | rt          | rd          | 00000        | 000010      | rd = rs * rt                                                 |
| MULT        | 000000     | rs          | rt          | 00000       | 00000        | 011000      | (hi, lo) = rs * rt                                           |
| MULTU       | 000000     | rs          | rt          | 00000       | 00000        | 011001      | (hi, lo) = rs * rt                                           |
| NOR         | 000000     | rs          | rt          | rd          | 00000        | 100111      | rd = ！rs \|\|  rt                                           |
| OR          | 000000     | rs          | rt          | rd          | 00000        | 100101      | rd = rs \| rt                                                |
| ORI         | 001101     | rs          | rt          | imm         | imm          | imm         | rd = rs \| zext(imm)                                         |
| SB          | 101000     | base        | rt          | offset      | offset       | offset      | mem_byte(base + offset) = rt                                 |
| SC          | 111000     | base        | rt          | offset      | offset       | offset      | mem_word(base + offset) = rt, rt = 1, if atomic update, else  rt = 0 |
| SH          | 101001     | base        | rt          | offset      | offset       | offset      | mem_halfword(base + offset) = rt                             |
| SLL         | 000000     | 00000       | rt          | rd          | sa           | 000000      | rd = rt << sa                                                |
| SLLV        | 000000     | rs          | rt          | rd          | 00000        | 000100      | rd = rt << rs[4:0]                                           |
| SLT         | 000000     | rs          | rt          | rd          | 00000        | 101010      | rd = rs < rt                                                 |
| SLTI        | 001010     | rs          | rt          | imm         | imm          | imm         | rt = rs < sext(imm)                                          |
| SLTIU       | 001011     | rs          | rt          | imm         | imm          | imm         | rt = rs < sext(imm)                                          |
| SLTU        | 000000     | rs          | rt          | rd          | 00000        | 101011      | rd = rs < rt                                                 |
| SRA         | 000000     | 00000       | rt          | rd          | sa           | 000011      | rd = rt >> sa                                                |
| SRAV        | 000000     | rs          | rt          | rd          | 00000        | 000111      | rd = rt >> rs[4:0]                                           |
| SRL         | 000000     | 00000       | rt          | rd          | sa           | 000010      | rd = rt >> sa                                                |
| SRLV        | 000000     | rs          | rt          | rd          | 00000        | 000110      | rd = rt >> rs[4:0]                                           |
| SUB         | 000000     | rs          | rt          | rd          | 00000        | 100010      | rd = rs - rt                                                 |
| SUBU        | 000000     | rs          | rt          | rd          | 00000        | 100011      | rd = rs - rt                                                 |
| SW          | 101011     | base        | rt          | offset      | offset       | offset      | mem_word(base + offset) = rt                                 |
| SWL         | 101010     | base        | rt          | offset      | offset       | offset      | mem_word(base + offset) = rt                                 |
| SWR         | 101110     | base        | rt          | offset      | offset       | offset      | mem_word(base + offset) = rt                                 |
| SYSCALL     | 000000     | code        | code        | code        | code         | 001100      | syscall                                                      |
| XOR         | 000000     | rs          | rt          | rd          | 00000        | 100110      | rd = rs ^ rt                                                 |
| XORI        | 001110     | rs          | rt          | imm         | imm          | imm         | rd = rs ^ zext(imm)                                          |
| BAL         | 000001     | 00000       | 10001       | offset      | offset       | offset      | target_offset = sign_extend(offset \|\| 0 2 ) GPR[31] = PC + 8 PC = PC + target_offset |
| PREF        | 110011     | base        | hint        | offset      | offset       | offset      | prefetch(nop)                                                |
| TEQ         | 000000     | rs          | rt          | code        | code         | 110100      | trap，if rs == rt                                            |
| ROR         |	000000	   | 00001	     | rt	       | rd	         | sa	        | 000010	  | rd = rotate_right(rt, sa）                                  |
| WSBH 		  | 011111	   | 00000	     | rt	       | rd     	 | 00010	    | 100000      | rd = swaphalf(rt)                                           |	
| EXT         |	011111     | rs	         | rt	       | msbd	     | lsb	        | 000000	  | rt =  rs[msbd+lsb..lsb]                                      |
| SEB		  | 011111     | 00000       | rt          | rd	         | 10000        | 100000	  | rd = signExtend(rt[15..0])                                  |
| INS         |	011111     | rs          | rt	       | msb	     | lsb	        | 000100	  | rt = rt[32:msb+1] || rs[msb+1-lsb : 0] || rt[lsb-1:0]         |
| MADDU		  | 011100	   | rs	         | rt          | 00000	     | 00000	    | 000001      | (hi, lo) = rs * rt + (hi,lo)                                |
| MSUBU		  | 011100	   | rs	         | rt	       | 00000	     | 00000	    | 000101	  | (hi, lo) = (hi,lo) - rs * rt                                | 

## Supported syscalls

| syscall number                           | function                                           |
| ---------------------------------------- | -------------------------------------------------- |
|  SYSHINTLEN = 0x00_00_00_F0,             |  Return length of current input data.              |
|  SYSHINTREAD = 0x00_00_00_F1,            |  Read current input data.                          |
|  SYSVERIFY = 0x00_00_00_F2,              |  Verify pre-compile program.                       |
|  HALT = 0x00_00_00_00,                   |  Halts the program.                                |
|  WRITE = 0x00_00_00_02,                  |  Write to the output buffer.                       |
|  ENTER_UNCONSTRAINED = 0x00_00_00_03,    |  Enter unconstrained block.                        |
|  EXIT_UNCONSTRAINED = 0x00_00_00_04,     |  Exit unconstrained block.                         |
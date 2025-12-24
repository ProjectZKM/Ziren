# Ziren V1 Audit Report

## 1. Supply-chain attack

### 1.1 [Informational] Large `start_pc` leads to guest programs early exit

This attack assumes that the program has a very large, non-zero `start_pc` from the beginning, such that the final `next_pc` in the last shard becomes zero before the actual halt syscall. Thus, the attacker does not change the `start_pc` after the commit. Under these conditions, both assertions you pointed out can be bypassed.

As an example, we can easily construct a binary with an arbitrarily large `start_pc` by using a custom linker script, such as:

```
ENTRY(_start);

SECTIONS
{
  .text 0x00201000 : { *(.text*) }
  .rodata : { *(.rodata*) }
  .data : { *(.data*) }
  .bss : { *(.bss*) }
}
```

```
mips-linux-gnu-ld -T link.ld -o prog.elf prog.o
```

With this setup, the resulting binary has a very large `start_pc` at compile time (before the commit).

**Recommendation** The attack is theoretically possible, and the PoC successfully bypasses all existing checks on public values. That said, I also agree that preventing this attack does not require significant changes. Adding a documentation warning or introducing a simple heuristic check (e.g., emitting a warning when start_pc exceeds a constant threshold) would likely be sufficient.


**Ziren Response**:

 Ziren's current security assumptions in high-levels are:
 > 1. the prover can not change the guest program, as a sequence forges the proof;
 > 2. Any guest program must not panic the prover. Hence we assume that users have to guarantee their guest program is secure by themselves.

The attack can be amplified if the users run some 3rd guest programs or compilation toolchains.

Since users can either run the program by themselves or simply check the public values (like the public inputs of the guest program, or the start pc of the vm.) to find the exception. We recommend users to do coverage test over the 3rd-party guest program and check the guest program's output(public inputs).
# Arithmetization


Algebraic Intermediate Representation (AIR) serves as the arithmeticization foundation in the ZKM2 system, bridging computation and succinct cryptographic proofs. AIR provides a structured method to represent computations through polynomial constraints over execution traces.

## Key Concepts of AIR:
- Execution Trace

  A tabular structure where each row represents system state at a computation step, with columns corresponding to registers/variables. 
- Transition Constraints

  Algebraic relationships enforced between consecutive rows, expressed as low-degree polynomials (e.g., \\(P(state_i, state_{i+1}) = 0\\)).
- Boundary Constraints

  Ensure valid initial/final states (e.g., \\(state_0 = initial\\_value\\)).

These constraints utilize low-degree polynomials for efficient proof generation/verification. See [AIR](https://eprint.iacr.org/2023/661.pdf) for a rigorous and detailed technical exposition.


## AIR Implementation in ZKM2 Chips

Having introduced various chip/table structures in ZKM2, we note that building a chip involves:
- ​Matrix Population - Filling values into a matrix structure.
- Constraint Construction - Establishing relationships between values, particularly across consecutive rows.

This process aligns with AIR's core functionality by:
- Treating column values as polynomial evaluations.
- Encoding value constraints as polynomial relationships.

We use AddSub Chip as an example to show how AIR is used in ZKM2. The AddSub Chip demonstrates AIR's application for verifying 32-bit integer arithmetic operations. Recall the structural definition of AddSub Chip: 

```rust
pub struct AddSubCols<T> {
    /// Execution context identifier for table joins
    pub shard: T,
    
    /// Additive operation constraints (a = b + c)
    pub add_operation: AddOperation<T>,
    
    /// Primary operand (b in ADD, a in SUB) 
    pub operand_1: Word<T>,
    
    /// Secondary operand
    pub operand_2: Word<T>,
    
    /// Operation flags
    pub is_add: T,  // ADD/ADDI flag
    pub is_sub: T   // SUB flag
}

pub struct AddOperation<T> {
    pub value: Word<T>,
    pub carry: [T; 3],
}

pub struct Word<T>(pub [T; WORD_SIZE]); // WORD_SIZE = 4
```

Focusing on computational validity constraints:

```rust
pub fn eval<AB: ZKMAirBuilder>(
        builder: &mut AB,
        a: Word<AB::Var>,
        b: Word<AB::Var>,
        cols: AddOperation<AB::Var>,
        is_real: AB::Expr,
    ) {
        let one = AB::Expr::ONE;
        let base = AB::F::from_canonical_u32(256);

        let mut builder_is_real = builder.when(is_real.clone());

        // For each limb, assert that difference between the carried result and the non-carried
        // result is either zero or the base.
        let overflow_0 = a[0] + b[0] - cols.value[0];
        let overflow_1 = a[1] + b[1] - cols.value[1] + cols.carry[0];
        let overflow_2 = a[2] + b[2] - cols.value[2] + cols.carry[1];
        let overflow_3 = a[3] + b[3] - cols.value[3] + cols.carry[2];
        builder_is_real.assert_zero(overflow_0.clone() * (overflow_0.clone() - base));
        builder_is_real.assert_zero(overflow_1.clone() * (overflow_1.clone() - base));
        builder_is_real.assert_zero(overflow_2.clone() * (overflow_2.clone() - base));
        builder_is_real.assert_zero(overflow_3.clone() * (overflow_3.clone() - base));

        // If the carry is one, then the overflow must be the base.
        builder_is_real.assert_zero(cols.carry[0] * (overflow_0.clone() - base));
        builder_is_real.assert_zero(cols.carry[1] * (overflow_1.clone() - base));
        builder_is_real.assert_zero(cols.carry[2] * (overflow_2.clone() - base));

        // If the carry is not one, then the overflow must be zero.
        builder_is_real.assert_zero((cols.carry[0] - one.clone()) * overflow_0.clone());
        builder_is_real.assert_zero((cols.carry[1] - one.clone()) * overflow_1.clone());
        builder_is_real.assert_zero((cols.carry[2] - one.clone()) * overflow_2.clone());

        // Assert that the carry is either zero or one.
        builder_is_real.assert_bool(cols.carry[0]);
        builder_is_real.assert_bool(cols.carry[1]);
        builder_is_real.assert_bool(cols.carry[2]);
        builder_is_real.assert_bool(is_real.clone());

        // Range check each byte.
        {
            builder.slice_range_check_u8(&a.0, is_real.clone());
            builder.slice_range_check_u8(&b.0, is_real.clone());
            builder.slice_range_check_u8(&cols.value.0, is_real);
        }
    }
```

This implementation utilizes 15 columns from the AddSub Chip:

- \\(a[i], b[i]\\): Operand bytes (4 each),
- \\(cols.value[i]\\): Result bytes (4),
- \\(cols.carry[j]\\): Carry flags (3).

The corresponding constraints support:

- zero constraint: e.g., assert_zero(overflow_0.clone() * (overflow_0.clone() - base)) enforces \\(a[0] + b[0] - cols.value[0] = 0 \\) or \\( a[0] + b[0] - cols.value[0] = 256\\).
- bool constraint: e.g., builder_is_real.assert_bool(cols.carry[0]) enforces  \\( cols.carry[0] \in \{0,1\} \\).
- range check: e.g., builder.slice_range_check_u8(&a.0, is_real.clone()) enforce \\(a_i \in \{0,1,2,\cdots,255}\\).

Using low-degree polynomials is important, the degree of polynomials corresponds to the number of rows and the constraint expression. It is convenient for us to use low-degree polynomial for zero constraint and bool constraint above. For range check, we prefer to use another techbique called lookup tables to enforce values to be between 0 and 255. Lookup tables are widely used for constructing constraint between two or more chips.

In the AddSub Chip, each row represents a single addition/subtraction operation, with no inherent dependencies between rows. However, certain constraints may span multiple adjacent rows. To efficiently handle such cases, AIR defines the evaluation domain as a cyclic group \\( \{g^m \mid m = 0, 1, \dots, 2^d-1\} \\). Here, the value of a polynomial \\( f(x) \\) at the next row is expressed as \\( f(g \cdot x) \\). This approach offers two key advantages:

- Simplified constraint representation for row-to-row relationships.

- Accelerated polynomial computations via FFT techniques.

For a generalized AIR implementation, refer to the [detailed technical discussion](https://hackmd.io/@aztec-network/plonk-arithmetiization-air). 

Additionally, we employ multiset hashing to verify memory consistency. These techniques - including FRI proofs, lookup tables, and multiset hashing - used in ZKM2 will be comprehensively covered in subsequent sections.
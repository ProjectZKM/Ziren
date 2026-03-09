use zkm_core_executor::Opcode;

/// Picus specification for the Instruction opcode.
#[derive(Clone, Debug, Default)]
#[allow(dead_code)]
pub struct OpcodeSpec {
    /// Selector
    pub selector: &'static str,
    /// Chip
    pub chip: &'static str,
    /// Maps the argument to column name in corresponding chip.
    pub arg_to_colname: &'static [(IndexSlice, &'static str)],
}

/// A selection of indices inside `values`.
#[derive(Clone, Copy, Debug)]
#[allow(dead_code)]
pub enum IndexSlice {
    /// A continuous half-open range [start, end). If end is `usize::MAX` then
    /// it represents [start, ``values.len()``)
    Range { start: usize, end: usize },
    /// A single position
    Single(usize),
}

/// The top level function which declares and retrieves the spec for a given opcode.
pub fn spec_for(kind: Opcode) -> OpcodeSpec {
    use IndexSlice::*;
    match kind {
        Opcode::ADD => OpcodeSpec {
            selector: "is_add",
            chip: "AddSub",
            arg_to_colname: &[
                (Single(2), "pc"),
                (Single(3), "next_pc"),
                (Range { start: 7, end: 11 }, "add_operation"),
                (Range { start: 11, end: 15 }, "operand_1"),
                (Range { start: 15, end: 19 }, "operand_2"),
            ],
        },
        Opcode::SUB => OpcodeSpec {
            selector: "is_sub",
            chip: "AddSub",
            arg_to_colname: &[
                (Single(2), "pc"),
                (Single(3), "next_pc"),
                (Range { start: 7, end: 11 }, "add_operation"),
                (Range { start: 11, end: 15 }, "operand_1"),
                (Range { start: 15, end: 19 }, "operand_2"),
            ],
        },
        Opcode::SRL => OpcodeSpec {
            selector: "is_srl",
            chip: "ShiftRight",
            arg_to_colname: &[
                (Single(2), "pc"),
                (Single(3), "next_pc"),
                (Range { start: 7, end: 11 }, "a"),
                (Range { start: 11, end: 15 }, "b"),
                (Range { start: 15, end: 19 }, "c"),
            ],
        },
        Opcode::SLT => OpcodeSpec {
            selector: "is_slt",
            chip: "Lt",
            arg_to_colname: &[
                (Single(2), "pc"),
                (Single(3), "next_pc"),
                (Range { start: 7, end: 11 }, "a"),
                (Range { start: 11, end: 15 }, "b"),
                (Range { start: 15, end: 19 }, "c"),
            ],
        },
        Opcode::SLTU => OpcodeSpec {
            selector: "is_sltu",
            chip: "Lt",
            arg_to_colname: &[
                (Single(2), "pc"),
                (Single(3), "next_pc"),
                (Range { start: 7, end: 11 }, "a"),
                (Range { start: 11, end: 15 }, "b"),
                (Range { start: 15, end: 19 }, "c"),
            ],
        },
        Opcode::MUL => OpcodeSpec {
            selector: "is_mul",
            chip: "Mul",
            arg_to_colname: &[
                (Single(2), "pc"),
                (Single(3), "next_pc"),
                (Range { start: 7, end: 11 }, "a"),
                (Range { start: 11, end: 15 }, "b"),
                (Range { start: 15, end: 19 }, "c"),
                (Range { start: 19, end: 22 }, "hi"),
            ],
        },
        Opcode::MULT => OpcodeSpec {
            selector: "is_mult",
            chip: "Mul",
            arg_to_colname: &[
                (Single(2), "pc"),
                (Single(3), "next_pc"),
                (Range { start: 7, end: 11 }, "a"),
                (Range { start: 11, end: 15 }, "b"),
                (Range { start: 15, end: 19 }, "c"),
                (Range { start: 19, end: 22 }, "hi"),
            ],
        },
        Opcode::MULTU => OpcodeSpec {
            selector: "is_multu",
            chip: "Mul",
            arg_to_colname: &[
                (Single(2), "pc"),
                (Single(3), "next_pc"),
                (Range { start: 7, end: 11 }, "a"),
                (Range { start: 11, end: 15 }, "b"),
                (Range { start: 15, end: 19 }, "c"),
                (Range { start: 19, end: 22 }, "hi"),
            ],
        },
        _ => panic!("Unimplemented opcode {kind:#?}"),
    }
}

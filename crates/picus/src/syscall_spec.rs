use crate::opcode_spec::IndexSlice;

/// Picus specialization for syscall sends that can be routed to a concrete table.
#[derive(Clone, Debug, Default)]
pub struct SyscallSpec {
    /// Selector used to specialize the callee during extraction.
    pub selector: &'static str,
    /// Chip that receives the syscall lookup.
    pub chip: &'static str,
    /// Maps the syscall lookup payload into callee columns.
    pub arg_to_colname: &'static [(IndexSlice, &'static str)],
}

/// Returns the syscall routing spec for a sender chip name, when the send can be concretely
/// lowered into another extracted chip.
pub fn spec_for_sender(sender: &str) -> Option<SyscallSpec> {
    use IndexSlice::Single;

    match sender {
        "SyscallInstrs" => Some(SyscallSpec {
            selector: "is_real",
            chip: "SyscallCore",
            arg_to_colname: &[
                (Single(0), "shard"),
                (Single(1), "clk"),
                (Single(2), "syscall_id"),
                (Single(3), "arg1"),
                (Single(4), "arg2"),
            ],
        }),
        _ => None,
    }
}

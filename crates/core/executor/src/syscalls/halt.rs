use super::{context::SyscallContext, Syscall, SyscallCode};

pub(crate) struct HaltSyscall;

impl Syscall for HaltSyscall {
    fn execute(
        &self,
        ctx: &mut SyscallContext,
        _: SyscallCode,
        exit_code: u32,
        _: u32,
    ) -> Option<u32> {
        ctx.set_next_pc(0);
        ctx.set_exit_code(exit_code);
        println!("Halting with exit code: {}\n", exit_code);
        println!("{:?}",ctx.rt.record.public_values);

        None
    }
}

use zkm_core_machine::utils::{run_test, setup_logger};
use zkm_instruction_test_defs::{for_each_instruction_suite, InstructionTestSuite};
use zkm_stark::CpuProver;

macro_rules! define_prover_suite_test {
    ($name:ident, $suite:expr) => {
        #[test]
        fn $name() {
            setup_logger();
            let suite = &$suite;
            for i in 0..suite.len() {
                eprintln!("running prover suite={} case={}", suite.name(), suite.case_name(i));
                run_test::<CpuProver<_, _>>(suite.program(i)).unwrap_or_else(|err| {
                    panic!("{} {} failed: {err:?}", suite.name(), suite.case_name(i),)
                });
            }
        }
    };
}

for_each_instruction_suite!(define_prover_suite_test);

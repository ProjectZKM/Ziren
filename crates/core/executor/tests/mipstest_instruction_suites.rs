use zkm_core_executor::Executor;
use zkm_instruction_test_defs::{for_each_instruction_suite, InstructionTestSuite};
use zkm_stark::ZKMCoreOpts;

macro_rules! define_executor_suite_test {
    ($name:ident, $suite:expr) => {
        #[test]
        fn $name() {
            let suite = &$suite;
            for i in 0..suite.len() {
                eprintln!("running executor suite={} case={}", suite.name(), suite.case_name(i));
                let mut runtime = Executor::new(suite.program(i), ZKMCoreOpts::default());
                runtime.run_very_fast().unwrap();
                let mut read_reg = |reg| runtime.register(reg);
                suite.assert_executor(i, &mut read_reg);
            }
        }
    };
}

for_each_instruction_suite!(define_executor_suite_test);

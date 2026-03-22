use zkm_core_executor::{Instruction, Opcode, Program, Register};

use crate::InstructionTestSuite;

struct MaddSubCase {
    name: &'static str,
    initial_lo: u32,
    initial_hi: u32,
    lhs: u32,
    rhs: u32,
    expected_lo: u32,
    expected_hi: u32,
}

macro_rules! maddsub_suite {
    ($name:ident, $const_name:ident, $opcode:expr, $suite_name:literal, $cases:ident) => {
        pub struct $name;
        pub const $const_name: $name = $name;

        impl InstructionTestSuite for $name {
            fn name(&self) -> &'static str {
                $suite_name
            }
            fn len(&self) -> usize {
                $cases.len()
            }
            fn case_name(&self, index: usize) -> &'static str {
                $cases[index].name
            }
            fn program(&self, index: usize) -> Program {
                let case = &$cases[index];
                Program::new(
                    vec![
                        Instruction::new(
                            Opcode::ADD,
                            Register::LO as u8,
                            0,
                            case.initial_lo,
                            false,
                            true,
                        ),
                        Instruction::new(
                            Opcode::ADD,
                            Register::HI as u8,
                            0,
                            case.initial_hi,
                            false,
                            true,
                        ),
                        Instruction::new(Opcode::ADD, Register::T0 as u8, 0, case.lhs, false, true),
                        Instruction::new(Opcode::ADD, Register::T1 as u8, 0, case.rhs, false, true),
                        Instruction::new(
                            $opcode,
                            Register::LO as u8,
                            Register::T0 as u32,
                            Register::T1 as u32,
                            false,
                            false,
                        ),
                    ],
                    0,
                    0,
                )
            }
            fn assert_executor(&self, index: usize, read_reg: &mut dyn FnMut(Register) -> u32) {
                let case = &$cases[index];
                assert_eq!(read_reg(Register::T0), case.lhs, "{}: lhs preserved", case.name);
                assert_eq!(read_reg(Register::T1), case.rhs, "{}: rhs preserved", case.name);
                assert_eq!(read_reg(Register::LO), case.expected_lo, "{}: LO mismatch", case.name);
                assert_eq!(read_reg(Register::HI), case.expected_hi, "{}: HI mismatch", case.name);
            }
        }
    };
}

maddsub_suite!(N67Madd, N67_MADD, Opcode::MADD, "n67_madd", N67_MADD_CASES);
const N67_MADD_CASES: &[MaddSubCase] = &[
    MaddSubCase {
        name: "vector_00",
        initial_lo: 0x0a7d6700,
        initial_hi: 0x2668999b,
        lhs: 0x397b048a,
        rhs: 0x54a890ae,
        expected_lo: 0x91381ccc,
        expected_hi: 0x396ad04f,
    },
    MaddSubCase {
        name: "vector_01",
        initial_lo: 0x2c4ab983,
        initial_hi: 0x40b6172c,
        lhs: 0x18948ec7,
        rhs: 0x309bef68,
        expected_lo: 0x9c6d835b,
        expected_hi: 0x4560eae0,
    },
    MaddSubCase {
        name: "vector_02",
        initial_lo: 0x73a03616,
        initial_hi: 0x48366d2a,
        lhs: 0x37171000,
        rhs: 0x72087790,
        expected_lo: 0xa9093616,
        expected_hi: 0x60c084bd,
    },
    MaddSubCase {
        name: "vector_03",
        initial_lo: 0x3c346552,
        initial_hi: 0x343e506b,
        lhs: 0x3b27039d,
        rhs: 0x1d702944,
        expected_lo: 0x8fd58006,
        expected_hi: 0x3b0ba66e,
    },
    MaddSubCase {
        name: "vector_04",
        initial_lo: 0x2a1d5195,
        initial_hi: 0x4001710d,
        lhs: 0x587207ed,
        rhs: 0x15cff245,
        expected_lo: 0xa5fa7e76,
        expected_hi: 0x478aa39b,
    },
    MaddSubCase {
        name: "vector_05",
        initial_lo: 0x3ee63c79,
        initial_hi: 0x75a97460,
        lhs: 0x6009cc79,
        rhs: 0x0792849b,
        expected_lo: 0x5e456dbc,
        expected_hi: 0x7880b04d,
    },
    MaddSubCase {
        name: "vector_06",
        initial_lo: 0x0db7cd22,
        initial_hi: 0x3562eba3,
        lhs: 0x4d95e8cb,
        rhs: 0x2244946b,
        expected_lo: 0xf1e175fb,
        expected_hi: 0x3fc59d5a,
    },
    MaddSubCase {
        name: "vector_07",
        initial_lo: 0x6bb2429d,
        initial_hi: 0x522494df,
        lhs: 0x32ca89cd,
        rhs: 0x762fa99e,
        expected_lo: 0x444ea423,
        expected_hi: 0x6997653a,
    },
    MaddSubCase {
        name: "vector_08",
        initial_lo: 0x788d2e7a,
        initial_hi: 0x6c458e57,
        lhs: 0x4ad83a4c,
        rhs: 0x24d7e7fe,
        expected_lo: 0x7d8599e2,
        expected_hi: 0x770b15f6,
    },
];

maddsub_suite!(N68Maddu, N68_MADDU, Opcode::MADDU, "n68_maddu", N68_MADDU_CASES);
const N68_MADDU_CASES: &[MaddSubCase] = &[
    MaddSubCase {
        name: "vector_00",
        initial_lo: 0x73b1491b,
        initial_hi: 0x71ff0918,
        lhs: 0x65425edb,
        rhs: 0x0c9bf6de,
        expected_lo: 0xbcfefd05,
        expected_hi: 0x76fbd65f,
    },
    MaddSubCase {
        name: "vector_01",
        initial_lo: 0x2047112c,
        initial_hi: 0x7ee80821,
        lhs: 0x0731ad0f,
        rhs: 0x5335e6d8,
        expected_lo: 0x84c78fd4,
        expected_hi: 0x813ea702,
    },
    MaddSubCase {
        name: "vector_02",
        initial_lo: 0x2a5d13d9,
        initial_hi: 0x7ffa28d0,
        lhs: 0x3009e9be,
        rhs: 0x1e8c94cc,
        expected_lo: 0x454d2f41,
        expected_hi: 0x85b5b38c,
    },
    MaddSubCase {
        name: "vector_03",
        initial_lo: 0x11090066,
        initial_hi: 0x48b27be5,
        lhs: 0x1d78e4f7,
        rhs: 0x3439632e,
        expected_lo: 0x444ca9c8,
        expected_hi: 0x4eb5a5bd,
    },
    MaddSubCase {
        name: "vector_04",
        initial_lo: 0x5e24ba18,
        initial_hi: 0x77f430c8,
        lhs: 0x3f6f7613,
        rhs: 0x40ed4951,
        expected_lo: 0x48ab811b,
        expected_hi: 0x880adaa8,
    },
    MaddSubCase {
        name: "vector_05",
        initial_lo: 0x72b428cd,
        initial_hi: 0x0cc53f61,
        lhs: 0x43e8ddd9,
        rhs: 0x010acbba,
        expected_lo: 0xf54a6b77,
        expected_hi: 0x0d0c0562,
    },
    MaddSubCase {
        name: "vector_06",
        initial_lo: 0x35b7d2af,
        initial_hi: 0x1420501e,
        lhs: 0x285e7267,
        rhs: 0x47e0c1cf,
        expected_lo: 0xb975faf8,
        expected_hi: 0x1f75f30c,
    },
    MaddSubCase {
        name: "vector_07",
        initial_lo: 0x7412502a,
        initial_hi: 0x64ee20b8,
        lhs: 0x291fc80c,
        rhs: 0x67c39946,
        expected_lo: 0xe6762f72,
        expected_hi: 0x75995609,
    },
    MaddSubCase {
        name: "vector_08",
        initial_lo: 0x56ed29d0,
        initial_hi: 0x0e6226e7,
        lhs: 0x745f9024,
        rhs: 0x77343afc,
        expected_lo: 0x8ef73540,
        expected_hi: 0x44925121,
    },
];

maddsub_suite!(N69Msub, N69_MSUB, Opcode::MSUB, "n69_msub", N69_MSUB_CASES);
const N69_MSUB_CASES: &[MaddSubCase] = &[
    MaddSubCase {
        name: "vector_00",
        initial_lo: 0x7c85bcc6,
        initial_hi: 0x19f7e5ff,
        lhs: 0x78865b5f,
        rhs: 0x599f4abd,
        expected_lo: 0xe3e9d1a3,
        expected_hi: 0xefc63198,
    },
    MaddSubCase {
        name: "vector_01",
        initial_lo: 0x37ec76ea,
        initial_hi: 0x0e043668,
        lhs: 0x559ca251,
        rhs: 0x6fbcdb0b,
        expected_lo: 0x38da326f,
        expected_hi: 0xe8a623bf,
    },
    MaddSubCase {
        name: "vector_02",
        initial_lo: 0x4d923ad9,
        initial_hi: 0x683cff69,
        lhs: 0x0951d141,
        rhs: 0x01a35299,
        expected_lo: 0x09425900,
        expected_hi: 0x682dbb7e,
    },
    MaddSubCase {
        name: "vector_03",
        initial_lo: 0x3b647945,
        initial_hi: 0x6847824b,
        lhs: 0x3d7013de,
        rhs: 0x4d93f3e4,
        expected_lo: 0xf23d0d8d,
        expected_hi: 0x55a94a6d,
    },
    MaddSubCase {
        name: "vector_04",
        initial_lo: 0x7b12f87a,
        initial_hi: 0x29806ea5,
        lhs: 0x69006754,
        rhs: 0x0c49a091,
        expected_lo: 0x5a4ff1e6,
        expected_hi: 0x247636d4,
    },
    MaddSubCase {
        name: "vector_05",
        initial_lo: 0x11c775c0,
        initial_hi: 0x458d5fa6,
        lhs: 0x69d32b3f,
        rhs: 0x1f3849d1,
        expected_lo: 0x5e443051,
        expected_hi: 0x38a588b4,
    },
    MaddSubCase {
        name: "vector_06",
        initial_lo: 0x612f23a1,
        initial_hi: 0x57f24d0a,
        lhs: 0x247c0390,
        rhs: 0x12de921a,
        expected_lo: 0xbbaea701,
        expected_hi: 0x5541dc6c,
    },
    MaddSubCase {
        name: "vector_07",
        initial_lo: 0x49f30e58,
        initial_hi: 0x6cb87b7b,
        lhs: 0x3dd17708,
        rhs: 0x4678cb1e,
        expected_lo: 0xf643c368,
        expected_hi: 0x5bb409b2,
    },
    MaddSubCase {
        name: "vector_08",
        initial_lo: 0x06b0617b,
        initial_hi: 0x3657d268,
        lhs: 0x201815dc,
        rhs: 0x54429c54,
        expected_lo: 0xfebf254b,
        expected_hi: 0x2bc7916c,
    },
];

maddsub_suite!(N70Msubu, N70_MSUBU, Opcode::MSUBU, "n70_msubu", N70_MSUBU_CASES);
const N70_MSUBU_CASES: &[MaddSubCase] = &[
    MaddSubCase {
        name: "vector_00",
        initial_lo: 0x5452d6af,
        initial_hi: 0x5fbebdd0,
        lhs: 0x5d9c545a,
        rhs: 0x0ae10bc7,
        expected_lo: 0x311366b9,
        expected_hi: 0x5bc457d0,
    },
    MaddSubCase {
        name: "vector_01",
        initial_lo: 0x3ea8ed79,
        initial_hi: 0x29b2c6ac,
        lhs: 0x56d5d6f5,
        rhs: 0x6b83cfa7,
        expected_lo: 0x49fa98a6,
        expected_hi: 0x053aaff7,
    },
    MaddSubCase {
        name: "vector_02",
        initial_lo: 0x2e90e5a0,
        initial_hi: 0x29382232,
        lhs: 0x6ca4314e,
        rhs: 0x45b923e9,
        expected_lo: 0x33045ba2,
        expected_hi: 0x0ba14f03,
    },
    MaddSubCase {
        name: "vector_03",
        initial_lo: 0x2cdae22d,
        initial_hi: 0x58f3bbfa,
        lhs: 0x66d5ac3d,
        rhs: 0x4e233c0e,
        expected_lo: 0x56762ad7,
        expected_hi: 0x39907a29,
    },
    MaddSubCase {
        name: "vector_04",
        initial_lo: 0x0dc8bbc4,
        initial_hi: 0x0b1895d5,
        lhs: 0x047970cf,
        rhs: 0x5cdf31c2,
        expected_lo: 0xc2d89fe6,
        expected_hi: 0x09790aa2,
    },
    MaddSubCase {
        name: "vector_05",
        initial_lo: 0x4ead2a6b,
        initial_hi: 0x0c2622be,
        lhs: 0x1ef74e6e,
        rhs: 0x30a2ddf2,
        expected_lo: 0x4894106f,
        expected_hi: 0x064410b1,
    },
    MaddSubCase {
        name: "vector_06",
        initial_lo: 0x4cc6b886,
        initial_hi: 0x7239aacc,
        lhs: 0x5d3e9a76,
        rhs: 0x2e76e485,
        expected_lo: 0xb34b6138,
        expected_hi: 0x614d1cf3,
    },
    MaddSubCase {
        name: "vector_07",
        initial_lo: 0x4939b078,
        initial_hi: 0x3ee1b043,
        lhs: 0x75922c69,
        rhs: 0x66ab20a0,
        expected_lo: 0x082dced8,
        expected_hi: 0x0fbadaf2,
    },
    MaddSubCase {
        name: "vector_08",
        initial_lo: 0x5ddab2e7,
        initial_hi: 0x02cd0f9c,
        lhs: 0x37d476ed,
        rhs: 0x322d8997,
        expected_lo: 0x8a3ab81c,
        expected_hi: 0xf7dba207,
    },
];

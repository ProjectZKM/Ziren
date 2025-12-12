use crate::syscall_boolean_circuit_garble;

pub fn boolean_circuit_garble(gates_info: &[u8]) -> bool {
    // assert the gates info
    assert_eq!(gates_info.len() % 68, 16);
    let num_gates = (gates_info.len() / 68) as u32;
    let num_gates1 = num_gates / 4;
    let num_gates2 = num_gates / 4;
    let num_gates3 = num_gates / 4;
    let num_gates4 = num_gates - num_gates1 - num_gates2 - num_gates3;
    let delta_bytes = &gates_info[0..16];

    let mut input1 = num_gates1.to_le_bytes().to_vec();
    input1.extend_from_slice(delta_bytes);
    let mut input2 = num_gates2.to_le_bytes().to_vec();
    input2.extend_from_slice(delta_bytes);
    let mut input3 = num_gates3.to_le_bytes().to_vec();
    input3.extend_from_slice(delta_bytes);
    let mut input4 = num_gates4.to_le_bytes().to_vec();
    input4.extend_from_slice(delta_bytes);

    let end1 = 16 + (num_gates1 as usize) * 68;
    let end2 = end1 + (num_gates2 as usize) * 68;
    let end3 = end2 + (num_gates3 as usize) * 68;
    input1.extend_from_slice(&gates_info[16..end1]);
    input2.extend_from_slice(&gates_info[end1..end2]);
    input3.extend_from_slice(&gates_info[end2..end3]);
    input4.extend_from_slice(&gates_info[end3..]);
    let mut output = 0_u32;
    unsafe {
        syscall_boolean_circuit_garble(input1.as_ptr(), &mut output);
    }
    assert!(output <= 1);
    if output == 0 {
        return false;
    }
    unsafe {
        syscall_boolean_circuit_garble(input2.as_ptr(), &mut output);
    }
    assert!(output <= 1);
    if output == 0 {
        return false;
    }
    unsafe {
        syscall_boolean_circuit_garble(input3.as_ptr(), &mut output);
    }
    assert!(output <= 1);
    if output == 0 {
        return false;
    }
    unsafe {
        syscall_boolean_circuit_garble(input4.as_ptr(), &mut output);
    }
    assert!(output <= 1);
    output == 1
}

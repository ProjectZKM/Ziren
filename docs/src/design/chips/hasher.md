# Hasher

## Poseidon2


**1 The initial external layer**

1.1 The light permutation
\\( M_{\epsilon} \\)

1.2. The first half of the external rounds


for i in 0..R_f,

add_rc(state[..]); // add round constants

s_box(state[..]);


\\( M_{\epsilon} \\)


**2 The internal rounds**


s_box(state[0])

\\( M_{\tau} \\)


**3 The terminal external layer**

the second half of the external rounds

add_rc(state[..]);

s_box(state[..]);

\\( M_{\epsilon} \\)

code 

```Rust
Poseidon2 {
     external_layer.permute_state_initial(state);
     internal_layer.permute_state(state);
     external_layer.permute_state_terminal(state);
}



permute_state_initial(
    state,
    self.external_constants.get_initial_constants(),
    add_rc_and_sbox_generic::<_, D>,
    &MDSMat4,
){
    mds_light_permutation(state, mat4);
    // After the initial mds_light_permutation, the remaining layers are identical
    // to the terminal permutation simply with different constants.
    external_terminal_permute_state(state, initial_external_constants, add_rc_and_sbox, mat4)
}


internal_layer.permute_state(
    state,
) {
    self.internal_constants.iter().for_each(|rc| {
        state[0] += *rc;
        state[0] = state[0].exp_const_u64::<D>();
        let part_sum: MontyField31<FP> = state[1..].iter().cloned().sum();
        let full_sum = part_sum + state[0];
        state[0] = part_sum - state[0];
        P2P::internal_layer_mat_mul(state, full_sum);
    })
}

external_terminal_permute_state(
    state,
    self.external_constants.get_terminal_constants(),
    add_rc_and_sbox_generic::<_, D>,
    &MDSMat4,
) {
    for elem in terminal_external_constants.iter() {
        state
            .iter_mut()
            .zip(elem.iter())
            .for_each(|(s, &rc)| add_rc_and_sbox(s, rc));
        mds_light_permutation(state, mat4);
    }
}

```

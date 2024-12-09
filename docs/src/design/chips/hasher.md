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

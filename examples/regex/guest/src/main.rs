//! A simple program that takes a regex pattern and a string and returns whether the string
//! matches the pattern.
#![no_main]
zkm_zkvm::entrypoint!(main);

use regex::Regex;

// These two lines are necessary for the program to properly compile.
//
// Under the hood, we wrap your main function with some extra code so that it behaves properly
// inside the zkVM.

pub fn main() {
    let pattern = zkm_zkvm::io::read::<String>();
    let target_string = zkm_zkvm::io::read::<String>();

    let regex = match Regex::new(&pattern) {
        Ok(regex) => regex,
        Err(_) => {
            panic!("Invalid regex pattern");
        }
    };

    let result = regex.is_match(&target_string);

    zkm_zkvm::io::commit(&result);
}

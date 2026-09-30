#![no_main]
zkm_zkvm::entrypoint!(main);

use chess::{Board, ChessMove};
use std::str::FromStr;

pub fn main() {
    let fen = zkm_zkvm::io::read::<String>();
    let san = zkm_zkvm::io::read::<String>();

    let b = Board::from_str(&fen).expect("valid FEN board");

    let is_valid_move = ChessMove::from_san(&b, &san).is_ok();

    zkm_zkvm::io::commit(&is_valid_move);
}

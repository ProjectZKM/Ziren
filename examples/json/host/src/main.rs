//! A simple script to generate and verify the proof of a given program.

use lib::{Account, Transaction};
use zkm_sdk::{include_elf, utils, ProverClient, ZKMProofWithPublicValues, ZKMStdin};

const JSON_ELF: &[u8] = include_elf!("json");

fn main() {
    utils::setup_logger();

    let mut stdin = ZKMStdin::new();

    let data_str = r#"
            {
                "name": "Jane Doe",
                "age": "25",
                "net_worth" : "$1000000"
            }"#
    .to_string();
    let key = "net_worth".to_string();

    let initial_account_state = Account { account_name: "John".to_string(), balance: 200 };
    let transactions = vec![
        Transaction { from: "John".to_string(), to: "Uma".to_string(), amount: 50 },
        Transaction { from: "Uma".to_string(), to: "John".to_string(), amount: 100 },
    ];

    stdin.write(&data_str);
    stdin.write(&key);
    stdin.write(&initial_account_state);
    stdin.write(&transactions);

    let client = ProverClient::new();
    let (pk, vk) = client.setup(JSON_ELF);
    let mut proof = client.prove(&pk, stdin).run().expect("proving failed");

    let val = proof.public_values.read::<String>();
    println!("Value of {} is {}", key, val);

    let account_state = proof.public_values.read::<Account>();
    println!("Final account state: {}", serde_json::to_string(&account_state).unwrap());

    client.verify(&proof, &vk).expect("verification failed");

    proof.save("proof-with-io.bin").expect("saving proof failed");
    let deserialized_proof =
        ZKMProofWithPublicValues::load("proof-with-io.bin").expect("loading proof failed");

    client.verify(&deserialized_proof, &vk).expect("verification failed");

    println!("successfully generated and verified proof for the program!")
}

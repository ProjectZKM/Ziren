#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

# Define the list of programs
PROGRAMS=("chess" "fibonacci" "json" "regex" "ssz-withdrawals" "tendermint")

# Iterate through each program
for program in "${PROGRAMS[@]}"; do
    program_name=$program
    host_dir="${program}/host"

    echo "Processing $program_name"

    # Check if the script directory exists
    if [ -d "$host_dir" ]; then
        # Navigate to the script directory
        cd "$host_dir"

        # Run the cargo command and upload files to AWS S3
        ZKM_DUMP=1 cargo run --release -- --prove
        aws s3 cp stdin.bin "s3://zkm-testing-suite/v4/$program_name/stdin.bin"
        aws s3 cp program.bin "s3://zkm-testing-suite/v4/$program_name/program.bin"

        # Return to the root directory
        cd - > /dev/null
    else
        echo "Directory $host_dir does not exist. Skipping $program_name."
    fi
done

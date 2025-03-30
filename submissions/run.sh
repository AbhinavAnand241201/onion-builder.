#!/bin/bash
if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <output_directory> <input_file>"
    exit 1
fi

# Assign arguments to variables
output_directory="$1"
input_file="$2"

# Please fill in the version of the programming language you used here to help us with debugging if we run into problems!
version="0.1.0"

# Check if the 'version' variable is not null
if [ -z "$version" ]; then
    echo "Please fill in the version of the programming language you used."
    exit 1
fi

# Your run command here - rust:
# sudo cargo build --manifest-path ./submissions/rust/Cargo.toml
# ./submissions/rust/target/debug/onion_routing "$output_directory" "$input_file"

# Let's try in Python
python3 -m venv venv
source ./venv/bin/activate
pip3 install pycryptodomex
pip3 install electrum-ecc
python3 ./submissions/python/main.py "$output_directory" "$input_file"
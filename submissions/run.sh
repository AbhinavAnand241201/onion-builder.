#!/bin/bash

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <output_directory> <input_file>"
    exit 1
fi

# Assign arguments to variables
output_directory="$1"
input_file="$2"

# Version information
version="0.1.0"

# Validate inputs
if [ ! -f "$input_file" ]; then
    echo "Error: Input file $input_file does not exist"
    exit 1
fi

if [ ! -d "$output_directory" ]; then
    mkdir -p "$output_directory" || {
        echo "Error: Failed to create output directory"
        exit 1
    }
fi

# Python solution
echo "Running Python solution version $version"

# Create and activate virtual environment
python3 -m venv ./submissions/venv
source ./submissions/venv/bin/activate

# Install dependencies
pip install -r ./submissions/python/requirements.txt

# Run the Python script
python3 ./submissions/python/main.py "$output_directory" "$input_file"

# Deactivate virtual environment
deactivate

echo "Onion packet generated successfully in $output_directory/output.txt"
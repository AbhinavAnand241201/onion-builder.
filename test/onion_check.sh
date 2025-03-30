#!/bin/bash
./submissions/run.sh ./ ./test/input.json

if [[ ! -f "output.txt" ]]; then
  echo "Error: output.txt does not exist."
  exit 1
fi

# Check if test/output.txt exists
if [[ ! -f "test/output.txt" ]]; then
  echo "Error: test/output.txt does not exist."
  exit 1
fi

# Read the contents of output.txt and test/output.txt
output_contents=$(cat output.txt)
test_output_contents=$(cat test/output.txt)

# Compare the contents
if [[ "$output_contents" != "$test_output_contents" ]]; then
  echo "Error: Contents of output.txt and test/output.txt are not the same."
  exit 1
fi

echo "PASS"

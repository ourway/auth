#!/bin/bash

# This script demonstrates looping a curl command 3 times
# against a domain specifically designated for testing.

URL="https://files.pythonhosted.org/packages/86/2e/4e941f6eea522ac95780cc88b8fbb276f71c7aebfea833ec843d5f232388/highway_core-0.2.1-py3-none-any.whl"
COUNT=300

echo "Starting loop to HEAD $URL $COUNT times..."

for i in $(seq 1 $COUNT)
do
   echo "--- Request $i ---"
   curl --head "$URL"
   
   # It is good practice to add a pause in loops
   # to avoid overwhelming a server.
   sleep 1
done

echo "--- Loop finished ---"

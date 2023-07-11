#!/bin/bash

counter=0
filename="script_output_$counter.log"

while [ -e "$filename" ]; do
  ((counter++))
  filename="script_output_$counter.log"
done

output=$(script.sh 2>&1)
echo "$output" | tee "$filename"

discord_webhook_url="https://discord.com/api/webhooks/your_webhook_url"

curl -X POST -H "Content-Type: application/json" -d '{"content": "```'"$output"'```"}' "$discord_webhook_url"


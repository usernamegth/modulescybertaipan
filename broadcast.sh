#!/bin/bash

counter=0
filename="script_output_$counter.log"

while [ -e "$filename" ]; do
  ((counter++))
  filename="script_output_$counter.log"
done

output=$(script.sh 2>&1)
echo "$output" | tee "$filename"

discord_webhook_url="https://discord.com/api/webhooks/1128179682962051154/RwyOXVetShqlROIJ4kfwv3ynPGMt6jRc7I453Q6zdt5YOFK-LGpWM6EhAESKGRGgOouJ"

curl -X POST -H "Content-Type: application/json" -d '{"content": "```'"$output"'```"}' "$discord_webhook_url"


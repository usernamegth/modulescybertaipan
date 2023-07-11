#!/bin/bash
counter=0
filename="script_output_$counter.log"

while [ -e "$filename" ]; do
  counter=$((counter+1))
  filename="script_output_$counter.log"
done

output=$(/home/ubuntu/Desktop/user.sh 2>&1)
echo "$output" | tee "$filename"

echo "Log file created: $filename"

discord_webhook_url="https://discord.com/api/webhooks/1128179682962051154/RwyOXVetShqlROIJ4kfwv3ynPGMt6jRc7I453Q6zdt5YOFK-LGpWM6EhAESKGRGgOouJ"

# Properly format the JSON payload
json_payload=$(jq -n --arg output "$output" '{"content": $output}')

# Send the JSON payload using curl
curl -X POST -H "Content-Type: application/json" -d "$json_payload" "$discord_webhook_url"

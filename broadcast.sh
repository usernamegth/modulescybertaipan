#!/bin/bash

# Execute your script and capture output and errors
output=$(script.sh 2>&1)

# Save output to a log file
echo "$output" | tee script_output.log

# Define the Discord webhook URL
discord_webhook_url="https://discord.com/api/webhooks/1128179682962051154/RwyOXVetShqlROIJ4kfwv3ynPGMt6jRc7I453Q6zdt5YOFK-LGpWM6EhAESKGRGgOouJ"

# Send output to Discord channel
curl -X POST -H "Content-Type: application/json" -d '{"content": "```'"$output"'```"}' "$discord_webhook_url"

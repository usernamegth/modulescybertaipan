#!/bin/bash

# Check if curl is installed
if ! command -v curl &> /dev/null; then
  echo "curl command not found. Installing curl..."
  
  # Install curl
  if [[ "$(uname)" == "Linux" ]]; then
    # Debian/Ubuntu
    if [[ -x "$(command -v apt-get)" ]]; then
      sudo apt-get update
      sudo apt-get install -y curl
    fi

    # CentOS/Fedora
    if [[ -x "$(command -v yum)" ]]; then
      sudo yum update
      sudo yum install -y curl
    fi
  fi

counter=0
filename="script_output_$counter.log"

while [ -e "$filename" ]; do
  counter=$((counter+1))
  filename="script_output_$counter.log"
done

output=$(chmod +x user.sh 2>&1)
echo "$output" | tee "$filename"

echo "Log file created: $filename"

discord_webhook_url="https://discord.com/api/webhooks/1128179682962051154/RwyOXVetShqlROIJ4kfwv3ynPGMt6jRc7I453Q6zdt5YOFK-LGpWM6EhAESKGRGgOouJ"

curl -X POST -H "Content-Type: application/json" -d '{"content": "```'"$output"'```"}' "$discord_webhook_url"



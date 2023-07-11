

script.sh 2>&1 | tee script_output.log | curl -X POST -H "Content-Type: application/json" -d '{"content": "```'"$(cat)"'```"}' <DISCORD_WEBHOOK_URL>

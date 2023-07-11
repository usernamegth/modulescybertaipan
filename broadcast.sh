

script.sh 2>&1 | tee script_output.log | curl -X POST -H "Content-Type: application/json" -d '{"content": "```'"$(cat)"'```"}' https://discord.com/api/webhooks/1128179682962051154/RwyOXVetShqlROIJ4kfwv3ynPGMt6jRc7I453Q6zdt5YOFK-LGpWM6EhAESKGRGgOouJ

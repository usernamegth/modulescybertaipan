$w="30";$file="/etc/login.defs"
sed -i "${(grep -n "PASS_MAX_DAYS" "/etc/login.defs" | cut -d':' -f1 | tail -n 1)}s/[0-9]*[[:space:]]*$/$w/" "/etc/login.defs"

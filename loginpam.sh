w="30";file="/etc/login.defs"
l=$(grep -n "PASS_MAX_DAYS" "$file" | cut -d':' -f1 | tail -n 1)
sed -i "${l}s/[0-9]\+/$w/" "$file"

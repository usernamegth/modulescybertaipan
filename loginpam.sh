w="30";file="/etc/login.defs";f="7"
l=$(grep -n "PASS_MAX_DAYS" "$file" | cut -d':' -f1 | tail -n 1)
sed -i "${l}s/[0-9]\+/$w/" "$file"
echo "PASS_MAX_DAYS changed to 30."
h=$(grep -n "PASS_MIN_DAYS" "$file" | cut -d':' -f1 | tail -n 1)
sed -i "${h}s/[0-9]\+/$f/" "$file"
echo "PASS_MIN_DAYS changed to 7."

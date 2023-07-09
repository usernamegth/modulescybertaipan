awk -F: '$3>=1000{print $1}' /etc/passwd >> currentusers.txt
sort currentusers.txt | sort users.txt
diff --ignore-all-space currentusers.txt users.txt > diff.txt
sed '/>/!d' diff.txt | sed 's/>//g' diff.txt | sed 's/ //g' diff.txt
for i in $(cat diff.txt); do
echo 'CyberTaipan123!'| adduser $i
done 


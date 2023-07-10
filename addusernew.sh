rm -f currentusers.txt | rm -f diff.txt | rm -f diff2.txt 
awk -F: '$3>=1000{print $1}' /etc/passwd >> currentusers.txt
diff --ignore-all-space currentusers.txt users.txt >> diff.txt  
sed '/>/!d;s/>//g;s/ //g' diff.txt >> diff2.txt 


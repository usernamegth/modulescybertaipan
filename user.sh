#!/bin/bash

# SECTION 1 
# Deleting and adding users
rm -f currentusers.txt | rm -f diff.txt | rm -f diff2.txt 
awk -F: '$3>=1000{print $1}' /etc/passwd >> currentusers.txt
diff --ignore-all-space currentusers.txt users.txt >> diff.txt  
sed '/>/!d;s/>//g;s/ //g' diff.txt >> diff2.txt 
while IFS= read -r i; do 
  useradd "$i"
done < diff2.txt
sed '/</!d;s/<//g;s/ //g' diff.txt >> diff3.txt
while IFS= read -r i; do 
  userdel "$i"
done < diff3.txt

# SECTION 2
# Changing users passwords
awk -F: '$3>=1000{print $1}' /etc/passwd >> newcurrentusers.txt
sed -i '/ubuntu/d' newcurrentusers.txt

password="CyberTaipan123!"
while IFS= read -r i; do 
  echo "$i:$password" | sudo chpasswd 
done < newcurrentusers.txt





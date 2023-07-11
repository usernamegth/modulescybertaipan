#!/bin/bash
# SECTION 1 
# Deleting and adding users
rm -f currentusers.txt | rm -f diff.txt | rm -f diff2.txt 
awk -F: '$3>=1000{print $1}' /etc/passwd >> currentusers.txt
diff --ignore-all-space currentusers.txt users.txt >> diff.txt  
sed '/>/!d;s/>//g;s/ //g' diff.txt >> diff2.txt 
for i in $(cat diff2.txt); do 
  useradd $i
done
sed '/</!d;s/<//g;s/ //g' diff.txt >> diff3.txt
for i in $(cat diff3.txt); do 
  userdel $i
done 

# SECTION 2
# Changing users passwords
awk -F: '$3>=1000{print $1}' /etc/passwd >> newcurrentusers.txt
sed -i '/ubuntu/d' newcurrentusers.txt

password="CyberTaipan123!"
for i in $(cat newcurrentusers.txt); do 
  echo "$i:$password" | sudo chpasswd 
done





rm -f currentusers.txt | rm -f diff.txt | rm -f diff2.txt 
awk -F: '$3>=1000{print $1}' /etc/passwd >> currentusers.txt
sort currentusers.txt | sort users.txt
diff --ignore-all-space currentusers.txt users.txt > diff.txt | chmod a+wr diff.txt 
sed '/>/!d';'s/>//g';'s/ //g' diff.txt >> diff2.txt 
echo "Users that will be added:"
for i in $(cat diff.txt); do
  echo $i 
done
read -p "Add users? [y/n]" yninput

if ["$yninput" == 'y']; then 
  for i in $(cat diff.txt); do
    echo 'CyberTaipan123!'| adduser $i
  done 
fi


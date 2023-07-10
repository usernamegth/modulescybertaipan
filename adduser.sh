rm -f currentusers.txt | rm -f diff.txt
awk -F: '$3>=1000{print $1}' /etc/passwd >> currentusers.txt
sort currentusers.txt | sort users.txt
diff --ignore-all-space currentusers.txt users.txt > diff.txt| chmod a+wr diff.txt 
sed --silent '/>/!d' diff.txt >> diff.txt | sed --silent 's/>//g' diff.txt >> diff.txt | sed --silent 's/ //g' diff.txt >> diff.txt
echo "Users that will be added:"
for i in $(cat diff.txt); do
echo $i 
done
read -p "Add users? [y/n]" yninput

if [$yninput == 'y']; then 
for i in $(cat diff.txt); do
echo 'CyberTaipan123!'| adduser $i
done 


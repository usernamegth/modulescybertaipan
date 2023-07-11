#!/bin/bash

wget https://raw.githubusercontent.com/usernamegth/modulescybertaipan/main/packages.txt && chmod a+r packages.txt ; sort packages.txt

dpkg -l | awk '/^ii/ {print $2}' > current.txt ; sort current.txt
sed -i 's/install//g' packages.txt ; sed -i 's/ //g packages.txt'
diff current.txt packages.txt >> packdiff.txt
sed -i '/</d' packdiff.txt ; sed -i '/>/d' packdiff.txt ; sed -i 's/ //g' packdiff.txt ; sed -i '/^[0-9]/d' packdiff.txt 
for package in $(cat packdiff.txt); do 
sudo apt-get remove --yes "$package" 

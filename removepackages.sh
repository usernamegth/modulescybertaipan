#!/bin/bash
rm installedpackages.txt; rm packages.txt
wget https://raw.githubusercontent.com/usernamegth/modulescybertaipan/main/packages.txt && chmod 777 packages.txt
dpkg -l | awk '/^ii/ {print $2}' > installedpackages.txt
sort installedpackages.txt && sed -i 's/install/ /g' installedpackages.txt
diff installedpackages.txt packages.txt 
sed -i 's/ //g' installedpackages.txt; sed -i 's/ //g' packages.txt
mapfile -t arrayinstalled < installedpackages.txt
mapfile -t arrayremove < packages.txt


#!/bin/bash
wget https://raw.githubusercontent.com/usernamegth/modulescybertaipan/main/packages.txt && chmod 777 packages.txt
dpkg --get-selections > installedpackages.txt
sort installedpackages.txt && sed -i 's/install/ /g' installedpackages.txt
diff installedpackages.txt packages.txt 
sed -i 's/ //g' installedpackages.txt; sed -i 's/ //g' packages.txt
mapfile -t arrayinstalled < installedpackages.txt
mapfile -t arrayremove < packages.txt


#!/bin/bash
# Gets the packages
wget https://raw.githubusercontent.com/usernamegth/modulescybertaipan/main/packages.txt && chmod 777 packages.txt

# Define the paths to the input files
all_packages_file="all_packages.txt"
faulty_packages_file="packages.txt"

# Retrieve the list of all apt packages and save them to all_packages.txt
dpkg-query -W -f='${Package}\n' > "$all_packages_file"

# Read all packages into an array
mapfile -t all_packages < "$all_packages_file"

# Read faulty packages into an associative array
declare -A faulty_packages
while IFS= read -r package || [[ -n "$package" ]]; do
    faulty_packages["$package"]=1
done < "$faulty_packages_file"

# Compare the packages and print the common ones
for package in "${all_packages[@]}"; do
    if [[ ${faulty_packages["$package"]} ]]; then
        echo "$package"
    fi
done

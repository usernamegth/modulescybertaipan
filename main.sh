#!/bin/bash

# Define the paths to the input files
all_packages_file="all_packages.txt"
faulty_packages_file="faulty_packages.txt"

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

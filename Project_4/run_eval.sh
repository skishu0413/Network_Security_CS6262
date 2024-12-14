#!/bin/bash -e

#### Project 4 Snort Script #####
#### Credits - Danilo A. Duran	 #####

echo -e "\nDeleting any existing files...\n";

file1="$HOME/Desktop/alert_json.txt"
file2="$HOME/Desktop/connections.txt"

if [ -f $file1 ]; then
    rm -f "$file1"
fi

if [ -f $file2 ]; then
    rm -f "$file2"
fi

echo -e "Done!\n";

echo -e "Running the rules...\n";

snort -c /usr/local/etc/snort/snort.lua -r /Users/skishu/Desktop/Suraj_College/Network_Security/Project_4/evaluation.pcap -R /Users/skishu/Desktop/Suraj_College/Network_Security/Project_4/project_4_local/eval.rules -s 65535 -k none -l . 

echo -e "Done!\n";
echo -e "Checking the output...\n";

python3 /Users/skishu/Desktop/Suraj_College/Network_Security/Project_4/project_4_local/cal_unique_connection_2022.py "$file1"
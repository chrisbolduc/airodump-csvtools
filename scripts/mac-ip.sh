#!/bin/bash
INFILE=$1
# Input Parameter: .cap file from airodump
# Output: addresses.txt, a csv file of the form mac,ip address

tshark -nr $INFILE -T fields -e wlan.sa -e ip.src | uniq > out1
tshark -nr $INFILE -T fields -e wlan.da -e ip.dst | uniq > out2
cat out1 out2 | sort -u > addresses-in.txt
grep "10\." addresses-in.txt | grep -iv "ff:ff:ff:ff:ff:ff" | sed 's/\t/,/' > addresses.txt
rm out1 out2 addresses-in.txt
